#Requires -Version 5.1
Set-StrictMode -Version 3.0
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Continue'

# Глобальный обработчик ошибок. Не вызываем Write-AppLog до загрузки lib.
trap {
    $errorMsg = $_.Exception.Message
    try {
        if (Get-Command Write-AppLog -CommandType Function -ErrorAction Ignore) {
            Write-AppLog "Фатальная ошибка: $errorMsg" 'ERROR'
        } elseif ($env:LOCALAPPDATA) {
            $logDir = Join-Path $env:LOCALAPPDATA 'DomainAdminConsole'
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            Add-Content -LiteralPath (Join-Path $logDir 'console.log') -Value (
                "$(Get-Date -Format 'HH:mm:ss') [ERROR] $errorMsg") -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {}
    Write-Host "Domain Admin Console: $errorMsg" -ForegroundColor Red
    exit 1
}

# Информация о программе → lib\config.ps1

# ---------------------------------------------------------------------------
# STA (обязательно для WPF). Приложение поддерживает обе редакции PS,
# но WPF и удалённое администрирование работают только под Windows.
# ---------------------------------------------------------------------------
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Host 'Domain Admin Console требует Windows (WPF недоступен в Linux/macOS).' -ForegroundColor Red
    exit 1
}
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    # STA обязателен для WPF. Раньше скрипт перезапускал самого себя новым
    # интерпретатором (путь к хосту брался из текущего процесса, плюс обход
    # политики исполнения). Этот паттерн — «само-спавн shell с Bypass» —
    # эталонный признак загрузчика, на него и реагирует проактивная защита.
    # Точка входа теперь — DomainAdminConsole.cmd (флаги живут там).
    $launcher = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'DomainAdminConsole.cmd' } else { 'DomainAdminConsole.cmd' }
    if ($env:DAC_STA_RELAUNCH -eq '1') {
        # Аварийный режим (по умолчанию выключен): релонч без -ExecutionPolicy Bypass,
        # политика наследуется от родительского процесса.
        $hostExe = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
        $child = Start-Process -FilePath $hostExe -ArgumentList @('-NoProfile','-STA','-File',('"{0}"' -f $PSCommandPath)) -Wait -PassThru
        exit $child.ExitCode
    }
    throw ("Domain Admin Console требует STA-поток (WPF).`n" +
           "Запустите: `"$launcher`"`n" +
           "или вручную: powershell.exe -NoProfile -STA -File `"$PSCommandPath`"")
}


try {
    $desktopAssemblies = @('PresentationFramework','PresentationCore','WindowsBase','System.Windows.Forms')
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $desktopAssemblies += 'System.Drawing.Common'
    } else {
        $desktopAssemblies += 'System.Drawing'
    }
    Add-Type -AssemblyName $desktopAssemblies -ErrorAction Stop
} catch {
    throw "Не удалось загрузить WPF/WinForms: $($_.Exception.Message). Запустите Windows PowerShell 5.1 или PowerShell 7+ на Windows с установленным .NET Desktop Runtime."
}

# P1-1.3: один экземпляр (общие console.log и JSON-кэши не для конкурентной записи)
$script:InstanceMutex = New-Object System.Threading.Mutex($false, 'Local\DomainAdminConsole_SingleInstance')
if (-not $script:InstanceMutex.WaitOne(0)) {
[void][System.Windows.Forms.MessageBox]::Show(
	'Domain Admin Console уже запущен (второй экземпляр может испортить общие файлы).',
	'Domain Admin Console', 'OK', 'Warning')
exit 0
}

# ---------------------------------------------------------------------------
# C#-типы (DwmHelper, DomainComputer, ComputerGroup) — из предсобранных сборок
# в bin\ (исходники: models\*.cs, сборка: build-models.ps1).
#
# Раньше здесь было 4 × Add-Type -TypeDefinition с исходниками C# в here-строках:
# компиляция на лету + временная сборка в %TEMP%\1<число>\ — это то, за что
# Касперский и выдаёт PDM:Trojan.Win32.Generic на весь Main.ps1.
# ---------------------------------------------------------------------------
# Корень приложения фиксируем один раз: функция вызывается и из обработчиков событий
# WPF, где $PSScriptRoot зависит от цепочки областей.
$script:DacAppRoot = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { $PSScriptRoot }

function Import-DacModelAssembly {
    [CmdletBinding()]
    param()
    if ('DomainComputer' -as [type]) { return }
    $root = if ($script:DacAppRoot) { $script:DacAppRoot } else { $PSScriptRoot }
    $bin = Join-Path $root 'bin'
    $names = @('DomainAdminConsole.Models.desktop.dll')
    if ($PSVersionTable.PSEdition -eq 'Core') {
        # Для PowerShell 7 предпочитаем net8.0-windows-сборку, desktop-версия — как последняя попытка.
        $names = @('DomainAdminConsole.Models.core.dll', 'DomainAdminConsole.Models.desktop.dll')
    }
    $why = New-Object System.Collections.Generic.List[string]
    foreach ($name in $names) {
        $dll = Join-Path $bin $name
        if (-not (Test-Path -LiteralPath $dll)) { $why.Add("нет файла $dll"); continue }
        try { Add-Type -Path $dll -ErrorAction Stop; return }
        catch { $why.Add("$($name): $($_.Exception.Message)") }
    }
    throw ('Не удалось загрузить сборку моделей DomainAdminConsole.Models.' + "`n" +
           ($why.ToArray() -join '; ') + "`nСоберите её один раз: powershell -NoProfile -File `"" + (Join-Path $root 'build-models.ps1') + "`"")
}

# Новое окно консоли для удалённой сессии/ping. Путь к хосту берётся из $PSHOME:
# вычислять «путь к powershell из текущего процесса» — приём, которым пользуются
# вредоносные скрипты, чтобы не светить имя powershell.exe в тексте файла.
function Start-DacConsoleTask {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)
    $hostExe = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
    Start-Process -FilePath $hostExe -ArgumentList @('-NoExit','-Command',$Command)
}

Import-DacModelAssembly


# ==========================================================================
# P1-11 (Split-Script.ps1): библиотеки функций. Порядок загрузки = имя файла.
# ВАЖНО: подключаются ТОЧКОЙ из Main, чтобы $script:-переменные оставались общими.
# ==========================================================================
# --- Статические данные вынесены в lib\config.ps1 ---
$configPath = Join-Path $PSScriptRoot 'lib\config.ps1'
if (Test-Path -LiteralPath $configPath) { . $configPath } else { throw "Не найден файл конфигурации: $configPath" }

# ==========================================================================
# RS-NO-CLOSE (config.ps1:402) — встроенная очистка runspace-пулов.
# Это РЕЗЕРВ: если lib\runspace-pool.ps1 загрузится (авто-циклом ниже),
# он переопределит эти функции своей полной версией. Если файла нет или он
# не загрузился — очистка всё равно работает.
# ==========================================================================
$script:RsPoolModuleVersion = $null   # выставляет lib\runspace-pool.ps1, если загружен
if ($null -eq (Get-Variable -Scope Script -Name 'AppShuttingDown'     -ErrorAction SilentlyContinue)) { $script:AppShuttingDown     = $false }
if ($null -eq (Get-Variable -Scope Script -Name 'RsCleanupDone'       -ErrorAction SilentlyContinue)) { $script:RsCleanupDone       = $false }
if ($null -eq (Get-Variable -Scope Script -Name 'RsCleanupRegistered' -ErrorAction SilentlyContinue)) { $script:RsCleanupRegistered = $false }
if ($null -eq (Get-Variable -Scope Script -Name 'RsPoolLock'          -ErrorAction SilentlyContinue)) { $script:RsPoolLock          = New-Object object }

function Get-DetailRunspacePool {
	[CmdletBinding()]
	param([int]$MinRunspaces = 1, [int]$MaxRunspaces = 8)

	if ($script:AppShuttingDown) { return $null }

	[System.Threading.Monitor]::Enter($script:RsPoolLock)
	try {
		$pool = $script:DetailRunspacePool
		if ($null -ne $pool) {
			$alive = $false
			try { $alive = (-not $pool.IsDisposed -and $pool.RunspacePoolStateInfo.State -eq 'Opened') } catch { $alive = $false }
			if ($alive) { return $pool }
			try { $pool.Dispose() } catch { }
			$script:DetailRunspacePool = $null
		}

		$newPool = $null
		try {
			$newPool = [runspacefactory]::CreateRunspacePool($MinRunspaces, $MaxRunspaces)
			$newPool.ApartmentState  = [System.Threading.ApartmentState]::MTA
			$newPool.CleanupInterval = [timespan]::FromSeconds(30)
			$newPool.Open()
		} catch {
			if ($null -ne $newPool) { try { $newPool.Dispose() } catch { } }
			throw
		}
		$script:DetailRunspacePool = $newPool

		if ($null -eq $script:DetailTokenSource -or $script:DetailTokenSource.IsCancellationRequested) {
			if ($null -ne $script:DetailTokenSource) { try { $script:DetailTokenSource.Dispose() } catch { } }
			$script:DetailTokenSource = New-Object System.Threading.CancellationTokenSource
		}
		return $newPool
	}
	finally { [System.Threading.Monitor]::Exit($script:RsPoolLock) }
}

function Close-DetailRunspacePool {
	[CmdletBinding()]
	param([int]$TimeoutMs = 5000)

	[System.Threading.Monitor]::Enter($script:RsPoolLock)
	try {
		$cts = $script:DetailTokenSource
		if ($null -ne $cts) { try { if (-not $cts.IsCancellationRequested) { $cts.Cancel() } } catch { } }

		$pool = $script:DetailRunspacePool
		if ($null -ne $pool) {
			$closed = $false
			try {
				$ar = $pool.BeginClose($null, $null)
				if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $pool.EndClose($ar); $closed = $true }
			} catch { $closed = $false }
			if (-not $closed) { try { $pool.Close() } catch { } }
			try { $pool.Dispose() } catch { }
		}

		if ($null -ne $cts) { try { $cts.Dispose() } catch { } }
		$script:DetailRunspacePool = $null
		$script:DetailTokenSource  = $null
	}
	finally { [System.Threading.Monitor]::Exit($script:RsPoolLock) }
}

function Invoke-AppShutdownCleanup {
	[CmdletBinding()]
	param([string]$Reason = 'manual')

	if ($script:RsCleanupDone) { return }
	$script:RsCleanupDone   = $true
	$script:AppShuttingDown = $true

	try { Close-DetailRunspacePool } catch { }

	$poolType = 'System.Management.Automation.Runspaces.RunspacePool' -as [type]
	foreach ($name in @('UiPool', 'BgPool', 'ScanRunspacePool', 'ScanRunspace')) {
		$v = Get-Variable -Scope Script -Name $name -ErrorAction SilentlyContinue
		if ($null -eq $v -or $null -eq $v.Value) { continue }
		$o = $v.Value
		if ($null -ne $poolType -and $poolType.IsInstanceOfType($o)) {
			$closed = $false
			try {
				$ar = $o.BeginClose($null, $null)
				if ($ar.AsyncWaitHandle.WaitOne(5000)) { $o.EndClose($ar); $closed = $true }
			} catch { $closed = $false }
			if (-not $closed) { try { $o.Close() } catch { } }
		} else {
			try { $o.Close() } catch { }
		}
		try { $o.Dispose() } catch { }
		try { Set-Variable -Scope Script -Name $name -Value $null -ErrorAction Stop } catch { }
	}

	$dt = 'System.Windows.Threading.DispatcherTimer' -as [type]
	if ($null -ne $dt) {
		foreach ($name in @('UiDrainTimer','BgTimer','DrainTimer','EventMonitorTimer','EventMonitorCheckTimer',
		                    'OneCMonitoringTimer','CacheCleanupTimer','SearchTimer','Timer','CountersTimer',
		                    'EventsLoadTimer','MonitorBootTimer')) {
			$v = Get-Variable -Scope Script -Name $name -ErrorAction SilentlyContinue
			if ($null -eq $v -or $null -eq $v.Value) { continue }
			$t = $v.Value
			if ($dt.IsInstanceOfType($t)) { try { $t.IsEnabled = $false } catch { }; try { $t.Stop() } catch { } }
		}
	}
}

function Register-RsPoolCleanup {
	[CmdletBinding()]
	param([object]$Window)

	if ($script:RsCleanupRegistered) { return }
	$script:RsCleanupRegistered = $true

	$winType = 'System.Windows.Window' -as [type]
	if ($null -ne $Window -and $null -ne $winType -and $winType.IsInstanceOfType($Window)) {
		try { $null = $Window.add_Closed({ Invoke-AppShutdownCleanup -Reason 'Window.Closed' }) } catch { }
	}
	if ('System.Windows.Threading.Dispatcher' -as [type]) {
		try {
			$null = [System.Windows.Threading.Dispatcher]::CurrentDispatcher.add_ShutdownStarted({
				Invoke-AppShutdownCleanup -Reason 'Dispatcher.ShutdownStarted'
			})
		} catch { }
	}
	try {
		$null = [System.AppDomain]::CurrentDomain.add_ProcessExit({ Invoke-AppShutdownCleanup -Reason 'ProcessExit' })
	} catch { }
}
# ================= конец встроенного блока RS-NO-CLOSE =================

$dacLibDir = Join-Path $PSScriptRoot 'lib'
if (-not (Test-Path -LiteralPath $dacLibDir)) { throw "Не найден каталог lib: $dacLibDir" }
foreach ($dacLibFile in (Get-ChildItem -LiteralPath $dacLibDir -Filter '*.ps1' | Where-Object { $_.Name -ne 'config.ps1' } | Sort-Object Name)) {
. $dacLibFile.FullName
}

# RS-NO-CLOSE: проверяем, что модуль очистки пулов реально загрузился.
# lib\runspace-pool.ps1 подхватывается авто-циклом выше; если его нет
# (или имя/расширение не .ps1, или файл не читается) — подгружаем явно,
# а иначе работаем на встроенном резерве и пишем об этом в лог.
try {
	if ($null -eq $script:RsPoolModuleVersion) {
		$rsPoolLib = Join-Path $dacLibDir 'runspace-pool.ps1'
		if (Test-Path -LiteralPath $rsPoolLib) {
			try {
				. $rsPoolLib
				Write-AppLog "lib\runspace-pool.ps1 загружен явно из Main (авто-цикл его пропустил)" 'WARN'
			} catch {
				Write-AppLog "Ошибка загрузки lib\runspace-pool.ps1: $($_.Exception.Message) — используется встроенный резерв" 'ERROR'
			}
		} else {
			Write-AppLog "lib\runspace-pool.ps1 не найден в $dacLibDir — используется встроенный резерв очистки пулов" 'WARN'
		}
	} else {
		Write-AppLog "lib\runspace-pool.ps1 загружен (v$script:RsPoolModuleVersion)" 'INFO'
	}
} catch { }

# Авторизация до создания главного окна и запуска фоновых задач.
if (-not (Start-DacAuthentication)) {
    # config.ps1 уже успел поднять пул runspace'ов — закрываем его перед выходом
    try { if (Get-Command Invoke-AppShutdownCleanup -CommandType Function -ErrorAction Ignore) { Invoke-AppShutdownCleanup -Reason 'AuthFailed' } } catch {}
    exit 0
}

# ---------------------------------------------------------------------------
# Модель строки таблицы и модель группы (DomainComputer / ComputerGroup) —
# типы из сборки моделей, она загружена выше (см. Import-DacModelAssembly).
# ---------------------------------------------------------------------------
Import-DacModelAssembly

# Инициализация коллекций, зависящих от типа ComputerGroup (если config загружен до Add-Type)
if (-not $script:ComputerGroups -and ('ComputerGroup' -as [type])) {
$script:ComputerGroups = New-Object System.Collections.ObjectModel.ObservableCollection[ComputerGroup]
}
if (-not $script:AllComputers -and ('DomainComputer' -as [type])) {
$script:AllComputers = New-Object System.Collections.ObjectModel.ObservableCollection[DomainComputer]
}

$script:Settings = Get-AppSettings
$script:MacCache = Get-MacCache
$script:ComputerCache = Get-ComputerCache
$script:TabDataCache = Get-TabDataCache
#$script:AllComputers = New-Object System.Collections.ObjectModel.ObservableCollection[DomainComputer]
$script:View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:AllComputers)
$script:ScanToken = 0
$script:Scanning = $false
$script:AdReady = $false
$script:DomainName = $env:USERDNSDOMAIN
$script:HasAdModule = $false
$script:Ui = @{ Window = $null }
$script:LogLines = New-Object System.Collections.ObjectModel.ObservableCollection[string]
$script:FilterQuery = ''
$script:FilterMode = 'all'
# $script:SearchPlaceholder → lib\config.ps1
$script:ResultQueue = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
$script:ScanMeta = [hashtable]::Synchronized(@{ Total = 0; Done = 0; Online = 0; Finished = $false })
$script:ScanRunspace = $null
$script:ScanPipe = $null
$script:DrainTimer = $null

# Инициализация кэша
$script:TaskCache = Get-TaskCache

#---------------------------------------------------------------------------
# Фоновые задачи для UI / вкладок (ДВИЖОК)
#---------------------------------------------------------------------------
$script:UiPool = $null
$script:UiJobs = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]@())
$script:UiDrainTimer = $null
$script:DetailToken = 0

# ---------------------------------------------------------------------------
# Универсальный пул runspace'ов для фоновых задач (без Start-Job)
# ---------------------------------------------------------------------------
$script:BgPool = $null
# $script:BgPoolMaxSize → lib\config.ps1 ( = 32)
$script:BgTasks = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]@())
$script:BgTimer = $null

# Проверка доступности ThreadJob + универсальный запуск
$script:HasThreadJob = $null

# Вызывать при запуске:
Write-AppLog (Show-CurrentLogLevel) 'INFO'
Write-AppLog "Запуск. Пользователь: $env:USERDOMAIN\$env:USERNAME  Домен: $script:DomainName" 'INFO'
$runtimeInfo = Get-DacRuntimeInfo
Write-AppLog "Среда запуска: $($runtimeInfo.Label); .NET: $($runtimeInfo.Framework); PID: $PID; кэш ПК: $($script:ComputerCache.Keys.Count) ($script:ComputerCachePath)" 'INFO'

# ---------------------------------------------------------------------------
# Параллельный опрос статуса
# ---------------------------------------------------------------------------
# (перенесено в lib\)

$script:ProbeScript = {
param($Name, $Dns, $IpHint, $PingMs, $WmiSec, $FastOnly)
Set-StrictMode -Version 3.0

$result = [ordered]@{
    Name = $Name; Online = $false; IP = $IpHint; User = ''; OS = ''; OSVersion = ''
    Uptime = ''; UptimeSeconds = 0L; MAC = ''; Manufacturer = ''; Model = ''; Memory = ''; DiskInfo = ''
    Domain = ''; Error = ''; Boot = $null; DiskFreePct = -1
}
$target = if ([string]::IsNullOrWhiteSpace($Dns)) { $Name } else { $Dns }

$ping = $null
try {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($target, [int]$PingMs)
    if ($reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success -and $IpHint) {
        $reply = $ping.Send($IpHint, [int]$PingMs)
        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $target = $IpHint }
    }
    if ($reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) { return [pscustomobject]$result }
    $result.Online = $true
    if ($reply.Address) { $result.IP = $reply.Address.ToString() }
} catch {
    $result.Error = $_.Exception.Message
    return [pscustomobject]$result
} finally {
    if ($ping) { $ping.Dispose() }
}
if ($FastOnly) { return [pscustomobject]$result }

# Одна DCOM-сессия на четыре CIM-запроса. WinRM на целевом ПК не требуется.
$session = $null
try {
    $timeout = [Math]::Max(1, [int]$WmiSec)
    $options = New-CimSessionOption -Protocol Dcom -ErrorAction Stop
    $session = New-CimSession -ComputerName $target -SessionOption $options -OperationTimeoutSec $timeout -ErrorAction Stop
    $query = @{ CimSession = $session; Namespace = 'root\cimv2'; OperationTimeoutSec = $timeout; ErrorAction = 'Stop' }

    $cs = Get-CimInstance @query -ClassName Win32_ComputerSystem `
        -Property UserName,Manufacturer,Model,TotalPhysicalMemory,Domain | Select-Object -First 1
    if ($cs) {
        $result.User = [string]$cs.UserName
        $result.Manufacturer = [string]$cs.Manufacturer
        $result.Model = [string]$cs.Model
        $result.Domain = [string]$cs.Domain
        if ($cs.TotalPhysicalMemory) { $result.Memory = ('{0:N1} ГБ' -f ([double]$cs.TotalPhysicalMemory / 1GB)) }
    }

    $os = Get-CimInstance @query -ClassName Win32_OperatingSystem `
        -Property Caption,Version,LastBootUpTime | Select-Object -First 1
    if ($os) {
        $result.OS = [string]$os.Caption
        $result.OSVersion = [string]$os.Version
        if ($os.LastBootUpTime) {
            $boot = if ($os.LastBootUpTime -is [datetime]) { $os.LastBootUpTime } else { $null }
            if ($boot) {
                $result.Boot = $boot
                $ts = [datetime]::Now - $boot
                $result.UptimeSeconds = [long]$ts.TotalSeconds
                if ($ts.TotalDays -ge 1) { $result.Uptime = ('{0}д {1}ч {2}м' -f [int]$ts.TotalDays, $ts.Hours, $ts.Minutes) }
                elseif ($ts.TotalHours -ge 1) { $result.Uptime = ('{0}ч {1}м' -f [int]$ts.TotalHours, $ts.Minutes) }
                else { $result.Uptime = ('{0}м' -f [int]$ts.TotalMinutes) }
            }
        }
    }

    $nics = Get-CimInstance @query -ClassName Win32_NetworkAdapterConfiguration `
        -Filter 'IPEnabled = TRUE' -Property MACAddress,IPEnabled
    foreach ($nic in $nics) {
        $mac = [string]$nic.MACAddress
        if ($mac -and $mac -notmatch '^00:00:00') { $result.MAC = $mac; break }
    }

    $disk = Get-CimInstance @query -ClassName Win32_LogicalDisk `
        -Filter "DriveType = 3 AND DeviceID = 'C:'" -Property DeviceID,Size,FreeSpace | Select-Object -First 1
    if ($disk -and $disk.Size) {
        $freeGb = [double]$disk.FreeSpace / 1GB
        $sizeGb = [double]$disk.Size / 1GB
        $pct = if ($sizeGb -gt 0) { [int](($freeGb / $sizeGb) * 100) } else { 0 }
        $result.DiskFreePct = $pct
        $result.DiskInfo = ('C: {0:N0}/{1:N0} ГБ свободно ({2}%)' -f $freeGb, $sizeGb, $pct)
    }
} catch {
    $result.Error = $_.Exception.Message
} finally {
    if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
}
return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
# Throttled Update-Counters: реальная работа не чаще 1 раза в секунду
# ---------------------------------------------------------------------------
$script:CountersDirty = $false
$script:CountersTimer = $null

# ---------------------------------------------------------------------------
# Загрузка окна
# ---------------------------------------------------------------------------
try {
$window = Load-Xaml -Name 'MainWindow'
if (-not $window) {
	throw "Load-Xaml вернул null для MainWindow"
}
} catch {
$errorMsg = $_.Exception.Message
Write-AppLog "ОШИБКА ЗАГРУЗКИ ИНТЕРФЕЙСА: $errorMsg" 'ERROR'

# Показываем сообщение об ошибке
[System.Windows.MessageBox]::Show(
	"Ошибка разбора интерфейса:`n`n$errorMsg`n`n" +
	"Возможные причины:`n" +
	"• Некорректный XAML (незакрытые теги, ошибки в свойствах)`n" +
	"• Отсутствующие ресурсы или стили`n" +
	"• Проблемы с кодировкой файла`n`n" +
	"Проверьте файл d3_debug.ps1 на наличие ошибок в XAML разметке.",
	$script:AppTitle,
	'OK',
	'Error'
) | Out-Null

# Создаем минимальное окно для отображения ошибки
$errorWindow = New-Object System.Windows.Window
$errorWindow.Title = "$script:AppTitle - Ошибка запуска"
$errorWindow.Width = 700
$errorWindow.Height = 400
$errorWindow.WindowStartupLocation = 'CenterScreen'
$errorWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#0f1419')
$errorWindow.Foreground = [System.Windows.Media.Brushes]::White

$errorGrid = New-Object System.Windows.Controls.Grid
$errorGrid.Margin = '20'
$errorGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = 'Auto' }))
$errorGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = '*' }))
$errorGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property @{ Height = 'Auto' }))

# Заголовок
$titleBlock = New-Object System.Windows.Controls.TextBlock
$titleBlock.Text = "❌ Ошибка загрузки интерфейса"
$titleBlock.FontSize = 18
$titleBlock.FontWeight = 'Bold'
$titleBlock.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#ef4444')
$titleBlock.Margin = '0,0,0,15'
[void]$errorGrid.Children.Add($titleBlock)
[System.Windows.Controls.Grid]::SetRow($titleBlock, 0)

# Текст ошибки
$errorText = New-Object System.Windows.Controls.TextBox
$errorText.IsReadOnly = $true
$errorText.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#1a2332')
$errorText.Foreground = [System.Windows.Media.Brushes]::White
$errorText.FontFamily = [System.Windows.Media.FontFamily]::new('Consolas')
$errorText.FontSize = 12
$errorText.TextWrapping = 'Wrap'
$errorText.VerticalScrollBarVisibility = 'Auto'
$errorText.Padding = '10'
$errorText.Text = @"
Ошибка: $errorMsg

Возможные причины:
1. Некорректный XAML - проверьте закрывающие теги и кавычки
2. Отсутствующие ресурсы (стили, кисти)
3. Проблемы с кодировкой (UTF-8 с BOM)
4. Неправильные имена элементов управления

Для исправления:
• Проверьте XAML разметку в файле
• Убедитесь, что все теги корректно закрыты
• Проверьте соответствие имен элементов в XAML и коде
"@
[void]$errorGrid.Children.Add($errorText)
[System.Windows.Controls.Grid]::SetRow($errorText, 1)

# Кнопка закрытия
$btnClose = New-Object System.Windows.Controls.Button
$btnClose.Content = "✕ Закрыть"
$btnClose.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#2563eb')
$btnClose.Foreground = [System.Windows.Media.Brushes]::White
$btnClose.FontWeight = 'SemiBold'
$btnClose.Padding = '20,10'
$btnClose.HorizontalAlignment = 'Right'
$btnClose.Margin = '0,15,0,0'
$btnClose.Cursor = 'Hand'
$btnClose.Add_Click({ $errorWindow.Close() })
[void]$errorGrid.Children.Add($btnClose)
[System.Windows.Controls.Grid]::SetRow($btnClose, 2)

$errorWindow.Content = $errorGrid
$errorWindow.ShowDialog()
throw
}

$script:Ui.Window = $window
$window.Add_SourceInitialized({
Set-AppDarkTitleBar -Window $window
Set-AppIcon -Window $window
})

# Получаем все элементы управления
# Имена контролов хранятся в config.ps1: ключи есть и для необязательных
# элементов, чтобы проверка $script:Ui.<имя> не падала при StrictMode 3.0.
foreach ($n in $script:UiElementNames) {
$script:Ui[$n] = $window.FindName($n)
}

# ПРОВЕРКА: Убеждаемся, что все элементы найдены
$missingElements = @()
foreach ($key in $script:Ui.Keys) {
if ($null -eq $script:Ui[$key]) {
	$missingElements += $key
}
}
if ($missingElements.Count -gt 0) {
Write-AppLog "Не найдены элементы UI: $($missingElements -join ', ')" 'WARN'
}

# Проверка наличия кнопки "Отчет по всем ПК"
if ($script:Ui.ContainsKey('BtnSecurityScanAll') -and $script:Ui.BtnSecurityScanAll) {
Write-AppLog "✅ Кнопка 'Отчет по всем ПК' найдена" 'INFO'
}

# Принудительно показываем кнопку Debug
#if ($script:Ui.ContainsKey('BtnDebugLog') -and $script:Ui.BtnDebugLog) {
#$script:Ui.BtnDebugLog.Visibility = 'Visible'
#Write-AppLog "✅ Кнопка Debug найдена и видима" 'INFO'
#}

if ($script:Ui.TxtLogLevel) {
$level = Get-AppSetting 'LogLevel' 'INFO'
$script:Ui.TxtLogLevel.Text = "📋 $level"
}

if ($script:Ui.BtnAbout) {
$script:Ui.BtnAbout.Add_Click({
	Show-Info (Show-AppInfo -Full) "О программе"
})
}

# --- Плагины: окно управления ---
if ($script:Ui.BtnPlugins) {
    $script:Ui.BtnPlugins.Add_Click({
        try {
            Write-AppLog "Открытие окна управления плагинами" 'INFO'
            Show-PluginManagerWindow
        } catch {
            $err = $_.Exception.Message
            Write-AppLog "Ошибка открытия окна плагинов: $err" 'ERROR'
            Show-Err "Не удалось открыть окно управления плагинами:`n$err"
        }
    })
} else {
    Write-AppLog "Кнопка 'BtnPlugins' не найдена в XAML" 'WARN'
}

# Обработчик кнопки Debug - открывает окно отладки
#if ($script:Ui.BtnDebugLog) {
#$script:Ui.BtnDebugLog.Add_Click({
#	try {
#		Write-AppLog "Открытие окна отладки..." 'INFO'
#		Show-DebugWindow
#	} catch {
#		$err = $_.Exception.Message
#		Write-AppLog "Ошибка открытия окна отладки: $err" 'ERROR'
#		Show-Err "Не удалось открыть окно отладки:`n$err"
#	}
#})
#}

# Инициализация основных элементов (без Write-AppLog, т.к. функция ещё не определена)
if ($script:Ui.GridComputers) {
$script:Ui.GridComputers.ItemsSource = $script:View
}

if ($script:Ui.ListLog) {
$script:Ui.ListLog.ItemsSource = $script:LogLines
}

# Подпись текущего пользователя, меню учётной записи и права интерфейса.
Initialize-DacAuthorizationUi -Window $window -Controls $script:Ui

# Версия самого запущенного PowerShell и кэш ПК видны независимо от XAML-дополнений.
Update-RuntimeHeader

# Placeholder для поиска
if ($script:Ui.TxtSearch) {
# $script:SearchPlaceholder → lib\config.ps1 (уже задан)
$script:Ui.TxtSearch.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#64748b')
$script:Ui.TxtSearch.Height = 36
$script:Ui.TxtSearch.MinHeight = 36
$script:Ui.TxtSearch.MaxHeight = 36
$script:Ui.TxtSearch.VerticalAlignment = 'Center'
$script:Ui.TxtSearch.Text = $script:SearchPlaceholder
}

# Только реальная смена вкладки: SelectionChanged от вложенных списков всплывает
# через Tabs и не должен повторно запускать загрузку/логирование.
if ($script:Ui.Tabs) {
$script:Ui.Tabs.Add_SelectionChanged({
    param($sender, $e)
    if ($e -and $e.OriginalSource -ne $script:Ui.Tabs) { return }
    try { Sync-DetailTabs }
    catch { Write-AppLog "Не удалось обновить вкладку: $($_.Exception.Message)" 'WARN' }
})
}
#########
# ЗАГРУЖАЕМ ГРУППЫ В ПАМЯТЬ ДО ПЕРВОГО ИМПОРТА AD
Load-ComputerGroupsIntoMemory
Update-CacheStatus
# --- Плагины: загрузка сразу (реестр), монтаж — после готовности окна ---
Initialize-PluginsState            # читает plugins-state.json + plugins-trust.json
Import-DacPluginsFiltered          # грузит только разрешённые, без заблокированных
# Бейдж кнопки «Плагины» раньше не обновлялся вообще:
try { Update-PluginsButtonBadge } catch { Write-AppLog "Плагины: бейдж — $($_.Exception.Message)" 'WARN' }

# ---------------------------------------------------------------------------
# Обзор выбранного ПК
# ---------------------------------------------------------------------------

$script:Ui.GridComputers.Add_SelectionChanged({
try {
	Update-Overview
	if ($script:Ui.Tabs -and $script:Ui.Tabs.SelectedIndex -ne 0) {
		$script:Ui.Tabs.SelectedIndex = 0
	}
	$script:LoadedTabKey = ''
	Sync-DetailTabs
}
catch { Write-AppLog $_.Exception.Message 'WARN' }
})
$script:Ui.GridComputers.Add_MouseDoubleClick({
$pc = Get-SelectedComputer
if ($pc) { Start-RdpSession -Computer $pc }
})

# ---------------------------------------------------------------------------
# Поиск / фильтр
# ---------------------------------------------------------------------------
$script:Ui.TxtSearch.Add_GotFocus({
if ($script:Ui.TxtSearch.Text -eq $script:SearchPlaceholder) {
	$script:Ui.TxtSearch.Text = ''
	$script:Ui.TxtSearch.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#e2e8f0')
}
})
$script:Ui.TxtSearch.Add_LostFocus({
if ([string]::IsNullOrWhiteSpace($script:Ui.TxtSearch.Text)) {
	$script:Ui.TxtSearch.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#64748b')
	$script:Ui.TxtSearch.Text = $script:SearchPlaceholder
}
})
$script:SearchTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:SearchTimer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:SearchTimer.Add_Tick({
$script:SearchTimer.Stop()
Update-FilterView
})

$script:Ui.TxtSearch.Add_TextChanged({
if ($script:Ui.TxtSearch.Text -eq $script:SearchPlaceholder) { return }
$script:SearchTimer.Stop()
$script:SearchTimer.Start()
})
$script:Ui.CmbFilter.Add_SelectionChanged({ Update-FilterView })

# ---------------------------------------------------------------------------
# Кнопки панели
# ---------------------------------------------------------------------------
$script:Ui.BtnLoadAd.Add_Click({
try { Import-DomainComputerList } catch { Show-Err $_.Exception.Message; Write-AppLog $_.Exception.Message 'ERROR' }
})
$script:Ui.BtnRefresh.Add_Click({ Start-StatusScan })
$script:Ui.BtnRefreshSel.Add_Click({
    try {
        Write-AppLog "=== BtnRefreshSel click ===" 'INFO'
        Start-StatusScan -SelectedOnly
        Write-AppLog "=== BtnRefreshSel OK ===" 'INFO'
    } catch {
        Write-AppLog "BtnRefreshSel FAIL: $($_.Exception.Message)" 'ERROR'
        Write-AppLog "STACK: $($_.ScriptStackTrace)" 'ERROR'
        Write-AppLog "TARGET: $($_.InvocationInfo.PositionMessage)" 'ERROR'
        Show-Err "Ошибка опроса: $($_.Exception.Message)`n`nСтрока: $($_.InvocationInfo.ScriptLineNumber)"
    }
})

$script:Ui.BtnExport.Add_Click({
$dlg = New-Object Microsoft.Win32.SaveFileDialog
$dlg.Filter = 'CSV (*.csv)|*.csv'
$dlg.FileName = "domain-computers-$(Get-Date -Format yyyyMMdd-HHmm).csv"
if ($dlg.ShowDialog()) {
	$script:AllComputers | Select-Object Name, Status, CurrentUser, IPAddress, Role, OS, OSVersion, Uptime, DiskInfo, MAC, LastLogon, OU, Description, Enabled |
		Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
	Write-AppLog "Экспорт: $($dlg.FileName)" 'OK'
	Show-Info "Сохранено: $($dlg.FileName)"
}
})

$script:Ui.BtnFindUser.Add_Click({
$q = Show-InputDialog -Title 'Найти пользователя' -Prompt 'Имя пользователя (часть логина или DOMAIN\user):'
if (-not $q) { return }
$hits = @($script:AllComputers | Where-Object { $_.CurrentUser -and $_.CurrentUser -like "*$q*" })
if ($hits.Count -eq 0) {
	Show-Info "В текущем снимке пользователь '*$q*' не найден.`nОпросите статус и повторите поиск."
	return
}
$script:Ui.TxtSearch.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#e2e8f0')
$script:Ui.TxtSearch.Text = $q
Update-FilterView
$script:Ui.GridComputers.SelectedItem = $hits[0]
$script:Ui.GridComputers.ScrollIntoView($hits[0])
Show-Info (("Найдено: {0}`n`n" -f $hits.Count) + (($hits | ForEach-Object { '{0}  —  {1}' -f $_.Name, $_.CurrentUser }) -join "`n"))
})

# ============================================================================
# ФИЛЬТР ПО ГРУППАМ В ГЛАВНОМ ОКНЕ
# ============================================================================

$script:Ui.BtnSettings.Add_Click({ try { Show-SettingsWindow } catch { Show-Err $_.Exception.Message } })
if ($script:Ui.BtnLoadPrn) {
$script:Ui.BtnLoadPrn.Add_Click({
	$pc = Get-SelectedComputer
	if (-not $pc) {
		Show-Warn 'Выберите компьютер.'
		return
	}

	# Проверяем статус ПК
	if ($pc.StatusCode -ne 'Online') {
		Show-Warn "$($pc.Name) офлайн. Принтеры недоступны."
		if ($script:Ui.TxtPrnInfo) {
			$script:Ui.TxtPrnInfo.Text = "❌ $($pc.Name) офлайн"
			$script:Ui.TxtPrnInfo.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#ef4444')
		}
		$script:Ui.GridPrinters.ItemsSource = $null
		return
	}

	# Очищаем кэш для этого ПК перед принудительной загрузкой
	$cacheKey = "Printers_$($pc.Name)"
	if ($script:ComputerCache.ContainsKey($cacheKey)) {
		$script:ComputerCache.Remove($cacheKey)
	}

	# Очищаем список
	$script:Ui.GridPrinters.ItemsSource = $null

	# Загружаем
	Load-PrintersForSelected
})
}
if ($script:Ui.BtnPrintUi) {
$script:Ui.BtnPrintUi.Add_Click({
	$pc = Get-SelectedComputer; if (-not $pc) { return }
	$prn = $null
	if ($script:Ui.GridPrinters) { $prn = $script:Ui.GridPrinters.SelectedItem }
	if ($prn -and $prn.Name) {
		Start-Process explorer.exe "\\$($pc.Target)\$($prn.Name)"
	} else {
		Show-Info "Выберите принтер в таблице или откройте \\\$($pc.Target) в проводнике."
	}
})
}
if ($script:Ui.BtnPrintMgmt) {
$script:Ui.BtnPrintMgmt.Add_Click({
	$pc = Get-SelectedComputer; if (-not $pc) { return }
	try { Start-Process printmanagement.msc } catch {
		Start-Process explorer.exe "\$($pc.Target)"
	}
})
}

# ---------------------------------------------------------------------------
# Управление режимом отладки
# ---------------------------------------------------------------------------

$script:Ui.BtnWol.Add_Click({ $c = Require-Selection; if ($c) { Send-WakeOnLan -Computers $c } })
$script:Ui.BtnOff.Add_Click({ $c = Require-Selection; if ($c) { Invoke-RemoteShutdown -Computers $c -Action PowerOff -Force } })
$script:Ui.BtnReboot.Add_Click({ $c = Require-Selection; if ($c) { Invoke-RemoteShutdown -Computers $c -Action Restart -Force } })
$script:Ui.BtnLogoff.Add_Click({ $c = Require-Selection; if ($c) { Invoke-RemoteShutdown -Computers $c -Action Logoff -Force } })
#$script:Ui.BtnRdp.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-RdpSession $pc } else { Show-Warn 'Выберите компьютер.' } })
#$script:Ui.BtnRdpAdmin.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-RdpSession $pc -Admin } else { Show-Warn 'Выберите компьютер.' } })
$script:Ui.BtnEvents.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
$script:Ui.Tabs.SelectedIndex = 1
Queue-EventsForSelected -ComputerName $pc.Name
})
$script:Ui.BtnEventvwr.Add_Click({
$pc = Get-SelectedComputer; if (-not $pc) { return }
Start-Process eventvwr.exe -ArgumentList $pc.Target
})
$script:Ui.BtnCompmgmt.Add_Click({
$pc = Get-SelectedComputer; if (-not $pc) { return }
Start-Process mmc.exe -ArgumentList @('compmgmt.msc', "/computer:$($pc.Target)")
})
$script:Ui.BtnMsg.Add_Click({
$list = Require-Selection; if (-not $list) { return }
$text = Show-InputDialog -Title 'Сообщение' -Prompt 'Текст сообщения пользователю:'
if (-not $text) { return }
foreach ($pc in $list) {
	try {
		Send-RemoteMessage -Computer $pc.Target -Text $text
		Write-AppLog "$($pc.Name): сообщение отправлено" 'OK'
	} catch {
		Write-AppLog "$($pc.Name): $($_.Exception.Message)" 'ERROR'
		Show-Err "$($pc.Name): $($_.Exception.Message)"
	}
}
})

$script:Ui.BtnPs.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
if ($pc.StatusCode -ne 'Online') { Show-Warn "$($pc.Name) сейчас офлайн. PowerShell-сессия невозможна."; return }
$ok = $false
try {
	$null = Test-WSMan -ComputerName $pc.Target -ErrorAction Stop
	$ok = $true
} catch { $ok = $false }
if (-not $ok) {
	Show-Warn ("WinRM на $($pc.Name) недоступен.`n`nEnter-PSSession требует службу WinRM (порт 5985).`nВключите её кнопкой «Включить WinRM» на вкладке «Команда / ПО / сеть» или выполните на целевом ПК:`n  Enable-PSRemoting -Force")
	return
}
$cmd = "Enter-PSSession -ComputerName '$($pc.Target)'"
Start-DacConsoleTask -Command $cmd
Write-AppLog "PowerShell → $($pc.Target)" 'OK'
})
$script:Ui.BtnPing.Add_Click({
$pc = Get-SelectedComputer; if (-not $pc) { return }
Start-DacConsoleTask -Command "& ping.exe -t '$($pc.Target)'"
})
$script:Ui.BtnSetMac.Add_Click({
$pc = Get-SelectedComputer; if (-not $pc) { return }
Set-ComputerMacManual -Computer $pc
})

# Контекстное меню
$script:Ui.CtxRdp.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-RdpSession $pc } })
$script:Ui.CtxRefresh.Add_Click({ Start-StatusScan -SelectedOnly })
$script:Ui.CtxWol.Add_Click({ $c = Require-Selection; if ($c) { Send-WakeOnLan $c } })
$script:Ui.CtxOff.Add_Click({ $c = Require-Selection; if ($c) { Invoke-RemoteShutdown -Computers $c -Action PowerOff -Force } })
$script:Ui.CtxReboot.Add_Click({ $c = Require-Selection; if ($c) { Invoke-RemoteShutdown -Computers $c -Action Restart -Force } })
$script:Ui.CtxC.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-Process explorer.exe "\\$($pc.Target)\C$" } })
$script:Ui.CtxMgmt.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-Process mmc.exe @('compmgmt.msc', "/computer:$($pc.Target)") } })
$script:Ui.CtxEv.Add_Click({ $pc = Get-SelectedComputer; if ($pc) { Start-Process eventvwr.exe $pc.Target } })
$script:Ui.CtxCopy.Add_Click({
$names = ((Get-SelectedComputers) | ForEach-Object { $_.Name }) -join [Environment]::NewLine
if ($names) { [System.Windows.Clipboard]::SetText($names) }
})

# --- 23. Проверка наличия Get-ValidSelectedComputer ---
if (-not (Get-Command Get-ValidSelectedComputer -CommandType Function -ErrorAction Ignore)) {
function Get-ValidSelectedComputer {
	param([bool]$ShowWarning = $true)
	$pc = Get-SelectedComputer
	if (-not $pc) {
		if ($ShowWarning) { Show-Warn 'Выберите компьютер.' }
		return $null
	}
	if ([string]::IsNullOrWhiteSpace($pc.Target)) {
		if ($ShowWarning) { Show-Warn "Имя ПК не указано для $($pc.Name)" }
		return $null
	}
	if ($pc.StatusCode -ne 'Online') {
		if ($ShowWarning) { Show-Warn "$($pc.Name) офлайн." }
		return $null
	}
	return $pc
}
}

# ---------------------------------------------------------------------------
# Вкладки деталей - улучшенный статус
# ---------------------------------------------------------------------------
$script:LoadedTabKey = ''
$script:SvcCache = @()
$script:ProcCache = @()
$script:CurrentSessionComputer = $null
$script:SessionIds = @()

# RDP Shadow
$script:Ui.BtnRdpShadow.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }

# Проверяем статус ПК
if ($pc.StatusCode -ne 'Online') {
	Show-Warn "$($pc.Name) офлайн. RDP Shadow недоступен."
	return
}

# Показываем диалог выбора сессии
$sessionIds = @($script:SessionIds | Where-Object { $_.Id -gt 0 })
if ($sessionIds.Count -eq 0) {
	Show-Warn "Нет активных сессий для RDP Shadow.`nОбновите сессии и убедитесь, что пользователь вошел в систему."
	return
}

# Диалог выбора сессии
$inputWin = New-Object System.Windows.Window
$inputWin.Title = "RDP Shadow - выбор сессии"
$inputWin.Width = 450
$inputWin.Height = 250
$inputWin.WindowStartupLocation = 'CenterOwner'
$inputWin.Owner = $script:Ui.Window
$inputWin.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#0f1419')
$inputWin.Foreground = [System.Windows.Media.Brushes]::White

$grid = New-Object System.Windows.Controls.Grid
$grid.Margin = '10'
$row1 = New-Object System.Windows.Controls.RowDefinition
$row1.Height = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
$grid.RowDefinitions.Add($row1)

$row2 = New-Object System.Windows.Controls.RowDefinition
$row2.Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
$grid.RowDefinitions.Add($row2)

$row3 = New-Object System.Windows.Controls.RowDefinition
$row3.Height = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
$grid.RowDefinitions.Add($row3)

# Заголовок
$titleBlock = New-Object System.Windows.Controls.TextBlock
$titleBlock.Text = "Выберите сессию для подключения на $($pc.Name)"
$titleBlock.FontWeight = 'Bold'
$titleBlock.FontSize = 14
$titleBlock.Margin = '0,0,0,10'
[void]$grid.Children.Add($titleBlock)
$titleBlock.SetValue([System.Windows.Controls.Grid]::RowProperty, 0)

# Список сессий
$listBox = New-Object System.Windows.Controls.ListBox
$listBox.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#1a2332')
$listBox.Foreground = [System.Windows.Media.Brushes]::White
$listBox.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#334155')
$listBox.Margin = '0,0,0,10'

foreach ($sess in $sessionIds | Sort-Object Id) {
	$item = New-Object System.Windows.Controls.ListBoxItem
	$item.Content = "ID $($sess.Id) - $($sess.Username)"
	$item.Tag = $sess.Id
	[void]$listBox.Items.Add($item)
}
$listBox.SelectedIndex = 0
[void]$grid.Children.Add($listBox)
$listBox.SetValue([System.Windows.Controls.Grid]::RowProperty, 1)

# Кнопки
$buttonPanel = New-Object System.Windows.Controls.StackPanel
$buttonPanel.Orientation = 'Horizontal'
$buttonPanel.HorizontalAlignment = 'Right'
$buttonPanel.Margin = '0,10,0,0'

$btnCancel = New-Object System.Windows.Controls.Button
$btnCancel.Content = "Отмена"
$btnCancel.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#243044')
$btnCancel.Foreground = [System.Windows.Media.Brushes]::White
$btnCancel.Padding = '20,8'
$btnCancel.Margin = '0,0,10,0'
[void]$buttonPanel.Children.Add($btnCancel)

$btnConnect = New-Object System.Windows.Controls.Button
$btnConnect.Content = "✅ Подключиться"
$btnConnect.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#2563eb')
$btnConnect.Foreground = [System.Windows.Media.Brushes]::White
$btnConnect.FontWeight = 'SemiBold'
$btnConnect.Padding = '20,8'
[void]$buttonPanel.Children.Add($btnConnect)

[void]$grid.Children.Add($buttonPanel)
$buttonPanel.SetValue([System.Windows.Controls.Grid]::RowProperty, 2)

$inputWin.Content = $grid

$btnCancel.Add_Click({ $inputWin.DialogResult = $false; $inputWin.Close() })
$btnConnect.Add_Click({
	if ($listBox.SelectedItem) {
		$sessionId = [int]$listBox.SelectedItem.Tag
		Start-RdpShadow -Computer $pc -SessionId $sessionId
		$inputWin.DialogResult = $true
		$inputWin.Close()
	} else {
		Show-Warn "Выберите сессию."
	}
})

[void]$inputWin.ShowDialog()
})

# RDP из сессии
$script:Ui.BtnRdpSession.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
Start-RdpSession -Computer $pc
})

$script:Ui.BtnRdpSessionAdmin.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
Start-RdpSession -Computer $pc -Admin
})

$script:Ui.BtnCShareSession.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
Start-Process explorer.exe -ArgumentList "\\$($pc.Target)\C$"
Write-AppLog "Explorer \\$($pc.Target)\C$" 'OK'
})

$script:Ui.BtnCompmgmtSession.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) { Show-Warn 'Выберите компьютер.'; return }
Start-Process mmc.exe -ArgumentList @('compmgmt.msc', "/computer:$($pc.Target)")
})

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)
if ($script:Ui.BtnLoadEvents) {
$script:Ui.BtnLoadEvents.Add_Click({ Load-EventsForSelected })
}

if ($script:Ui.BtnLoadWarn) {
$script:Ui.BtnLoadWarn.Add_Click({ Load-EventsForSelected -IncludeWarn })
}
$script:Ui.BtnExportEvents.Add_Click({
$rows = @($script:Ui.GridEvents.ItemsSource)
if (-not $rows -or $rows.Count -eq 0) { Show-Warn 'Нет данных журнала.'; return }
$dlg = New-Object Microsoft.Win32.SaveFileDialog
$dlg.Filter = 'CSV (*.csv)|*.csv'
$dlg.FileName = "events-$(Get-Date -Format yyyyMMdd-HHmm).csv"
if ($dlg.ShowDialog()) {
	$rows | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
	Show-Info "Сохранено: $($dlg.FileName)"
}
})

$script:Ui.BtnLoadDisks.Add_Click({
$pc = Get-SelectedComputer
if (-not $pc) {
	Show-Warn 'Выберите компьютер.'
	return
}

if ($pc.StatusCode -ne 'Online') {
	Show-Warn "$($pc.Name) офлайн. Диски недоступны."
	Set-StatusInfo 'TxtDisksInfo' "$($pc.Name) офлайн" 'error'
	$script:Ui.GridDisks.ItemsSource = $null
	return
}

# Принудительно сбрасываем блокировку
$key = "$($pc.Name)|2"
if ($script:TabLoading.ContainsKey($key)) {
	$script:TabLoading[$key] = $false
}

# Удаляем кэш дисков для этого ПК
$cacheKey = "Disks_$($pc.Name)"
if ($script:ComputerCache.ContainsKey($cacheKey)) {
	$script:ComputerCache.Remove($cacheKey)
	Save-ComputerCache
	Write-AppLog "Кэш дисков для $($pc.Name) удален" 'INFO'
}

# Очищаем грид
$script:Ui.GridDisks.ItemsSource = $null

Write-AppLog "Принудительное обновление дисков для $($pc.Name)" 'INFO'
Load-DisksForSelected
})

$script:Ui.BtnLoadSvc.Add_Click({ Load-ServicesForSelected })

# (перенесено в lib\)
$script:Ui.TxtSvcFilter.Add_TextChanged({ Apply-SvcFilter })

# (перенесено в lib\)
$script:Ui.BtnSvcStart.Add_Click({ Invoke-SelectedService 'StartService' })
$script:Ui.BtnSvcStop.Add_Click({ Invoke-SelectedService 'StopService' })
$script:Ui.BtnSvcRestart.Add_Click({
Invoke-SelectedService 'StopService'
Start-Sleep -Seconds 2
Invoke-SelectedService 'StartService'
})

$script:Ui.BtnLoadProc.Add_Click({ Load-ProcessesForSelected })
# (перенесено в lib\)
$script:Ui.TxtProcFilter.Add_TextChanged({ Apply-ProcFilter })
$script:Ui.BtnKillProc.Add_Click({
$pc = Get-SelectedComputer
$pr = $script:Ui.GridProc.SelectedItem
if (-not $pc -or -not $pr) { Show-Warn 'Выберите процесс.'; return }
if (-not (Confirm-Ask "Завершить $($pr.Name) (PID $($pr.ProcessId)) на $($pc.Name)?")) { return }
try {
	$obj = Get-DacWmiObject -ComputerName $pc.Target -Class Win32_Process -Filter "ProcessId=$($pr.ProcessId)" -ErrorAction Stop
	$r = $obj | ForEach-Object { Invoke-DacCimInstanceMethod -InputObject $_ -ComputerName $pc.Target -MethodName Terminate }
	Write-AppLog "$($pc.Name): terminate $($pr.Name) → $($r.ReturnValue)" 'OK'
	$script:Ui.BtnLoadProc.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
} catch { Show-Err $_.Exception.Message }
})

$script:Ui.BtnLoadSess.Add_Click({ Load-SessionsForSelected })
$script:Ui.BtnLogoffSess.Add_Click({
$pc = Get-SelectedComputer; if (-not $pc) { return }
$id = Show-InputDialog -Title 'Logoff' -Prompt "ID сессии для logoff на $($pc.Name):"
if (-not $id) { return }
try {
	$null = & logoff.exe $id /server:$($pc.Target) 2>&1
	Write-AppLog "$($pc.Name): logoff session $id" 'OK'
	$script:Ui.BtnLoadSess.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
} catch { Show-Err $_.Exception.Message }
})

# ---------------------------------------------------------------------------
# Горячие клавиши
# ---------------------------------------------------------------------------
$window.Add_KeyDown({
param($s, $e)
if ($e.Key -eq 'F5') { Start-StatusScan; $e.Handled = $true }
elseif ($e.Key -eq 'F' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
	$script:Ui.TxtSearch.Focus(); $e.Handled = $true
}
})

# ---------------------------------------------------------------------------
# Автоопрос
# ---------------------------------------------------------------------------
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
# (перенесено в lib\)
$script:Timer.Add_Tick({
if (-not $script:Scanning -and $script:AdReady -and $script:AllComputers.Count -gt 0) {
	Start-StatusScan
}
})

$window.Add_Closing({
param($s, $e)

$ask = Confirm-Ask ("Закрыть {0}?`n`nВсе выполняющиеся операции будут отменены." -f $script:AppTitle) $script:AppTitle

if (-not $ask) {
	$e.Cancel = $true
	return
}

if ($script:DetailTokenSource) { $script:DetailTokenSource.Cancel() }
Stop-BgTasks
Stop-AllTasks
try { Stop-EventMonitor } catch {}
try { Clear-CimSessionPool } catch {}
try {
	if ($script:GlobalNotifyIcon) { $script:GlobalNotifyIcon.Visible = $false; $script:GlobalNotifyIcon.Dispose() }
} catch {}

# RS-NO-CLOSE (config.ps1:402). Раньше здесь было
#     if ($script:DetailRunspacePool) { $script:DetailRunspacePool.Dispose() }
# Dispose() без Close() не останавливает выполняющиеся операции, поэтому пул
# (до 8 runspace'ов со своим session state) доживал до конца процесса, а сам
# процесс мог не завершиться из-за живых потоков пула.
# Теперь закрываем ПОСЛЕ остановки задач; функция идемпотентна.
try {
	if (Get-Command Invoke-AppShutdownCleanup -CommandType Function -ErrorAction Ignore) {
		Invoke-AppShutdownCleanup -Reason 'Window.Closing'
	} else {
		# крайний случай: нет ни модуля, ни резерва — закрываем пул вручную
		if ($script:DetailTokenSource)  { try { $script:DetailTokenSource.Cancel() } catch {} }
		if ($script:DetailRunspacePool) { try { $script:DetailRunspacePool.Close() } catch {}; try { $script:DetailRunspacePool.Dispose() } catch {}; $script:DetailRunspacePool = $null }
	}
} catch {
	Write-AppLog "Invoke-AppShutdownCleanup: $($_.Exception.Message)" 'WARN'
}
})

# ---------------------------------------------------------------------------
# Очистка лога (кнопки)
# ---------------------------------------------------------------------------
$script:Ui.BtnClearLog.Add_Click({
$script:LogLines.Clear()
})

$script:Ui.BtnClearLogFile.Add_Click({
if (Confirm-Ask "Очистить файл лога? Это действие необратимо.") {
	try {
		Set-Content -LiteralPath $script:LogPath -Value '' -Encoding UTF8 -ErrorAction Stop
		Write-AppLog "Файл лога очищен." 'OK'
	} catch {
		Show-Err "Не удалось очистить файл лога: $($_.Exception.Message)"
	}
}
})

# 2. Оптимизированный параллельный опрос с использованием пула потоков
# (перенесено в lib\)

if (-not (Get-Command Reset-StuckLocks -CommandType Function -ErrorAction Ignore)) {
function Reset-StuckLocks {
	param([string]$ComputerName = $null)

	$keysToRemove = @()
	foreach ($k in $script:TabLoading.Keys) {
		if ($ComputerName -and $k -match "^$([regex]::Escape($ComputerName))\|") {
			$keysToRemove += $k
		} elseif (-not $ComputerName) {
			$keysToRemove += $k
		}
	}

	foreach ($k in $keysToRemove) {
		$script:TabLoading[$k] = $false
		Write-DebugLog "Сброшена блокировка: $k" 'INFO'
	}

	if ($keysToRemove.Count -gt 0) {
		Write-AppLog "Сброшено $($keysToRemove.Count) блокировок" 'OK'
	}
	return $keysToRemove.Count
}
}

# Добавляем вызов в Reset-StuckJobs
if (-not (Get-Command Reset-StuckJobs -CommandType Function -ErrorAction Ignore)) {
function Reset-StuckJobs {
	Write-AppLog "Сброс зависших задач..." 'INFO'

	# Сбрасываем блокировки вкладок
	Reset-StuckLocks
	# Очищаем кэш WSMan (так как состояние могло измениться)
	Clear-WSManCache
	# Очищаем кэш WMI
	Clear-WmiCache
	# Останавливаем все таймеры
	foreach ($id in @($script:JobTimers.Keys)) {
		try {
			$script:JobTimers[$id].Stop()
		} catch {}
		$script:JobTimers.Remove($id)
	}

	# Завершаем все задачи
	foreach ($j in @($script:UiJobs)) {
		try {
			Write-AppLog "Завершение задачи $($j.JobId)" 'WARN'
			$j.PS.Stop()
			$j.PS.Dispose()
		} catch {}
	}
	$script:UiJobs.Clear()
	$script:TabLoading = @{}

	Write-AppLog "Сброс завершен" 'OK'
}
}
# ============================================================================
# УПРАВЛЕНИЕ ГРУППАМИ КОМПЬЮТЕРОВ - ИСПРАВЛЕННАЯ ВЕРСИЯ
# ============================================================================

# (перенесено в lib\)

# ============================================================================
# ЗАГРУЗКА ГРУПП В ПАМЯТЬ (вызывать при старте приложения)
# ============================================================================
# (перенесено в lib\)

# Загружаем группы в память
Load-ComputerGroupsIntoMemory

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# ============================================================================
# ФУНКЦИЯ ОБНОВЛЕНИЯ UI ПОСЛЕ ИЗМЕНЕНИЯ ГРУПП
# ============================================================================

# (перенесено в lib\)

# ============================================================================
# ФИЛЬТР ПО ГРУППАМ В ГЛАВНОМ ОКНЕ
# ============================================================================

# (перенесено в lib\)

# ============================================================================
# КНОПКА "ГРУППЫ" В ПАНЕЛИ ИНСТРУМЕНТОВ
# ============================================================================

# Удаляем старую кнопку, если она существует
$existingBtn = $script:Ui['BtnGroups']
if ($existingBtn) {
$panel = $window.FindName('PanelActions')
if ($panel) { $panel.Children.Remove($existingBtn) }
}

# Создаем кнопку "Группы"
$btnGroups = New-Object System.Windows.Controls.Button
$btnGroups.Content = "📊 Группы"
$btnGroups.Style = $window.FindResource('Btn')
$btnGroups.Height = 36
$btnGroups.MinHeight = 36
$btnGroups.MaxHeight = 36
$btnGroups.VerticalAlignment = 'Center'
$btnGroups.ToolTip = "Управление группами компьютеров"
$btnGroups.Margin = "0,0,6,0"

$btnGroups.Add_Click({ Show-GroupsWindow })
$script:Ui['BtnGroups'] = $btnGroups

# Добавляем в панель (рядом с BtnSettings)
$panel = $window.FindName('PanelActions')
if ($panel) {
$index = -1
for ($i = 0; $i -lt $panel.Children.Count; $i++) {
	if ($panel.Children[$i] -eq $script:Ui.BtnSettings) {
		$index = $i
		break
	}
}
if ($index -ge 0) {
	$panel.Children.Insert($index, $btnGroups)
} else {
	$panel.Children.Add($btnGroups)
}
}

# ============================================================================
# ДИАЛОГ ВЫБОРА ГРУППЫ (для контекстного меню)
# ============================================================================

# (перенесено в lib\)

# ============================================================================
# КОНТЕКСТНОЕ МЕНЮ - ПРОСТАЯ РАБОЧАЯ ВЕРСИЯ (ЧЕРЕЗ ДИАЛОГ)
# ============================================================================

# Удаляем все старые пункты меню с тегами AddToGroup и RemoveFromGroup
$ctxMenu = $script:Ui.GridComputers.ContextMenu
if ($ctxMenu) {
$itemsToRemove = @()
foreach ($item in $ctxMenu.Items) {
	if ($item.Tag -eq "AddToGroup" -or $item.Tag -eq "RemoveFromGroup") {
		$itemsToRemove += $item
	}
}
foreach ($item in $itemsToRemove) {
	$ctxMenu.Items.Remove($item)
}
}

# ============================================================================
# ПУНКТ "ДОБАВИТЬ В ГРУППУ" - ПРОСТОЙ ВАРИАНТ (ОТКРЫВАЕТ ДИАЛОГ)
# ============================================================================

$ctxAddToGroup = New-Object System.Windows.Controls.MenuItem
$ctxAddToGroup.Header = "📊 Добавить в группу"
$ctxAddToGroup.Tag = "AddToGroup"

$ctxAddToGroup.Add_Click({
try {
	Write-AppLog "Нажата кнопка 'Добавить в группу'" 'INFO'

	# Получаем выбранные компьютеры
	$computers = Get-SelectedComputers
	if ($computers.Count -eq 0) {
		Show-Warn "Выберите компьютеры в таблице."
		return
	}

	Write-AppLog "Выбрано компьютеров: $($computers.Count)" 'INFO'

	# Проверяем, есть ли онлайн ПК
	$online = @($computers | Where-Object { $_.StatusCode -eq 'Online' })
	if ($online.Count -eq 0) {
		Show-Warn "Нет онлайн ПК для добавления."
		return
	}

	Write-AppLog "Онлайн ПК: $($online.Count)" 'INFO'

	# Проверяем, есть ли группы
	if ($script:ComputerGroups.Count -eq 0) {
		Show-Warn "Нет созданных групп. Сначала создайте группу через кнопку 'Группы' в панели инструментов."
		return
	}

	# Показываем диалог выбора группы
	$groupId = Show-SelectGroupDialog -Title "Добавить в группу" -Prompt "Выберите группу для $($online.Count) компьютеров:"
	Write-AppLog "Выбрана группа ID: $groupId" 'INFO'

	if (-not $groupId) {
		Write-AppLog "Группа не выбрана" 'INFO'
		return
	}

	# Находим группу
	$group = $null
	foreach ($g in $script:ComputerGroups) {
		if ($g.Id -eq $groupId) {
			$group = $g
			break
		}
	}
	if (-not $group) {
		Show-Warn "Группа не найдена."
		return
	}

	Write-AppLog "Группа: $($group.Name)" 'INFO'

	# Фильтруем только те, которых нет в группе
	$toAdd = @($online | Where-Object { -not ($group.Computers -contains $_.Name) })

	if ($toAdd.Count -eq 0) {
		Show-Warn "Все выбранные компьютеры уже в группе '$($group.Name)'"
		return
	}

	Write-AppLog "Добавляется компьютеров: $($toAdd.Count)" 'INFO'

	if (-not (Confirm-Ask "Добавить $($toAdd.Count) компьютеров в группу '$($group.Name)'?")) {
		return
	}

	$added = 0
	$failed = 0
	foreach ($c in $toAdd) {
		if (Add-ComputerToGroup -ComputerName $c.Name -GroupId $groupId) {
			$added++
			Write-AppLog "$($c.Name) добавлен в группу $($group.Name)" 'INFO'
		} else {
			$failed++
			Write-AppLog "Ошибка добавления $($c.Name) в группу $($group.Name)" 'WARN'
		}
	}

	Show-Info "✅ $added компьютеров добавлены в группу '$($group.Name)'"
	if ($failed -gt 0) {
		Show-Warn "⚠️ $failed компьютеров не удалось добавить."
	}

	Update-ViewAfterGroupChange

} catch {
	Write-AppLog "Ошибка добавления в группу: $($_.Exception.Message)" 'ERROR'
	Write-AppLog "Stack: $($_.ScriptStackTrace)" 'ERROR'
	Show-Err "Ошибка: $($_.Exception.Message)"
}
})

# ============================================================================
# ПУНКТ "УДАЛИТЬ ИЗ ГРУППЫ" - ПРОСТОЙ ВАРИАНТ (ОТКРЫВАЕТ ДИАЛОГ)
# ============================================================================

$ctxRemoveFromGroup = New-Object System.Windows.Controls.MenuItem
$ctxRemoveFromGroup.Header = "❌ Удалить из группы"
$ctxRemoveFromGroup.Tag = "RemoveFromGroup"

$ctxRemoveFromGroup.Add_Click({
try {
	Write-AppLog "Нажата кнопка 'Удалить из группы'" 'INFO'

	# Получаем выбранные компьютеры
	$computers = Get-SelectedComputers
	if ($computers.Count -eq 0) {
		Show-Warn "Выберите компьютеры в таблице."
		return
	}

	Write-AppLog "Выбрано компьютеров: $($computers.Count)" 'INFO'

	# Собираем группы, в которых есть выбранные компьютеры
	$groupsWithSelected = @{}
	foreach ($c in $computers) {
		if ($c.GroupId) {
			foreach ($g in $script:ComputerGroups) {
				if ($g.Id -eq $c.GroupId -and $g.Computers -contains $c.Name) {
					if (-not $groupsWithSelected.ContainsKey($g.Id)) {
						$groupsWithSelected[$g.Id] = @{
							Group = $g
							Computers = @()
						}
					}
					$groupsWithSelected[$g.Id].Computers += $c.Name
				}
			}
		}
	}

	if ($groupsWithSelected.Count -eq 0) {
		Show-Warn "Выбранные компьютеры не в группах."
		return
	}

	Write-AppLog "Найдено групп с выбранными ПК: $($groupsWithSelected.Count)" 'INFO'

	# Если компьютеры в нескольких группах - показываем список для выбора
	$selectedGroupId = $null
	if ($groupsWithSelected.Count -eq 1) {
		$selectedGroupId = ($groupsWithSelected.Keys | Select-Object -First 1)
		Write-AppLog "Одна группа: $selectedGroupId" 'INFO'
	} else {
		# Несколько групп - показываем диалог выбора
		$groupNames = @()
		$groupIds = @()
		foreach ($gId in $groupsWithSelected.Keys) {
			$g = $groupsWithSelected[$gId].Group
			$count = $groupsWithSelected[$gId].Computers.Count
			$groupNames += "$($g.Icon) $($g.Name) ($count ПК)"
			$groupIds += $gId
		}

		$selectedGroupId = Show-SelectGroupDialog -Title "Выберите группу" -Prompt "Выберите группу для удаления:"
		if (-not $selectedGroupId) {
			Write-AppLog "Группа не выбрана" 'INFO'
			return
		}
		Write-AppLog "Выбрана группа ID: $selectedGroupId" 'INFO'
	}

	if (-not $selectedGroupId) { return }

	$group = $null
	foreach ($g in $script:ComputerGroups) {
		if ($g.Id -eq $selectedGroupId) {
			$group = $g
			break
		}
	}
	if (-not $group) {
		Show-Warn "Группа не найдена."
		return
	}

	Write-AppLog "Группа: $($group.Name)" 'INFO'

	$inGroup = @($computers | Where-Object { $group.Computers -contains $_.Name })
	if ($inGroup.Count -eq 0) {
		Show-Warn "Выбранные компьютеры не в группе '$($group.Name)'"
		return
	}

	Write-AppLog "Удаляется компьютеров: $($inGroup.Count)" 'INFO'

	if (-not (Confirm-Ask "Удалить $($inGroup.Count) компьютеров из группы '$($group.Name)'?")) {
		return
	}

	$removed = 0
	foreach ($c in $inGroup) {
		if (Remove-ComputerFromGroup -ComputerName $c.Name -GroupId $selectedGroupId) {
			$removed++
			Write-AppLog "$($c.Name) удален из группы $($group.Name)" 'INFO'
		}
	}

	Show-Info "✅ $removed компьютеров удалены из группы '$($group.Name)'"
	Update-ViewAfterGroupChange

} catch {
	Write-AppLog "Ошибка удаления из группы: $($_.Exception.Message)" 'ERROR'
	Show-Err "Ошибка: $($_.Exception.Message)"
}
})

# ============================================================================
# ДОБАВЛЯЕМ ПУНКТЫ В КОНТЕКСТНОЕ МЕНЮ
# ============================================================================

if ($ctxMenu) {
# Находим позицию для вставки (после первого разделителя)
$insertIndex = 0
for ($i = 0; $i -lt $ctxMenu.Items.Count; $i++) {
	if ($ctxMenu.Items[$i] -is [System.Windows.Controls.Separator]) {
		$insertIndex = $i + 1
		break
	}
}

# Вставляем пункты
$ctxMenu.Items.Insert($insertIndex, $ctxAddToGroup)
$ctxMenu.Items.Insert($insertIndex + 1, $ctxRemoveFromGroup)

# Добавляем разделитель после пунктов групп, если его нет
$hasSeparatorAfter = $false
for ($i = $insertIndex + 2; $i -lt $ctxMenu.Items.Count; $i++) {
	if ($ctxMenu.Items[$i] -is [System.Windows.Controls.Separator]) {
		$hasSeparatorAfter = $true
		break
	}
}
if (-not $hasSeparatorAfter) {
	$sep = New-Object System.Windows.Controls.Separator
	$ctxMenu.Items.Insert($insertIndex + 2, $sep)
}
}

Write-AppLog "Контекстное меню групп инициализировано (исправленная версия)" 'OK'

# После загрузки групп, синхронизируем с компьютерами
if ($script:ComputerGroups.Count -gt 0 -and $script:AllComputers.Count -gt 0) {
Sync-GroupsWithComputers
}

# (перенесено в lib\)

# ---------------------------------------------------------------------------
# Экспериментальные функции
# ---------------------------------------------------------------------------

# Функция для получения всех экспериментальных вкладок
# (перенесено в lib\)

# Принудительно применяем состояние экспериментальных функций при загрузке
$experimentalEnabled = Get-AppSetting 'EnableExperimentalFeatures' $false
if ($experimentalEnabled) {
Write-AppLog "При загрузке: экспериментальные функции ВКЛЮЧЕНЫ" 'INFO'
} else {
Write-AppLog "При загрузке: экспериментальные функции ОТКЛЮЧЕНЫ" 'INFO'
}

# ============================================================================
# УПРАВЛЕНИЕ ЭКСПЕРИМЕНТАЛЬНЫМИ ФУНКЦИЯМИ (С ПРИМЕНЕНИЕМ НА ЛЕТУ)
# ============================================================================

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# Функция для поиска Border внутри TabItem
# (перенесено в lib\)

# ============================================================================
# УПРАВЛЕНИЕ ПАМЯТЬЮ
# ============================================================================

# Добавляем периодическую очистку кэша
# (перенесено в lib\)

# Запускаем очистку каждые 5 минут
if (-not $script:CacheCleanupTimer) {
$script:CacheCleanupTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:CacheCleanupTimer.Interval = [TimeSpan]::FromMinutes(5)
$script:CacheCleanupTimer.Add_Tick({ Clear-ExpiredCache })
$script:CacheCleanupTimer.Start()
}

# CriticalEventConfig → lib\config.ps1
# Инициализация файла для хранения уведомлений

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# Вызов:
# Force-TestNotification

# Оригинальное WPF-уведомление (переименовано)
# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# (перенесено в lib\)

# ============================================================================
# НОВОЕ ОКНО УПРАВЛЕНИЯ МОНИТОРИНГОМ (С ВЫБОРОМ ПК)
# ============================================================================

# (перенесено в lib\)

# ============================================================================
# ОКНО СПИСКА СОБЫТИЙ
# ============================================================================

# (перенесено в lib\)

# (перенесено в lib\)

# ============================================================================
# ДОБАВЛЕНИЕ UI ЭЛЕМЕНТОВ МОНИТОРИНГА В ГЛАВНОЕ ОКНО
# ============================================================================

# (перенесено в lib\)

# (перенесено в lib\)

# ============================================================================
# ИНИЦИАЛИЗАЦИЯ МОНИТОРИНГА
# ============================================================================

# Добавляем UI элементы после загрузки окна
$window.Add_ContentRendered({
try {

	# Автоматический запуск мониторинга, если есть онлайн ПК
	if ($script:AllComputers.Count -gt 0) {
		$online = @($script:AllComputers | Where-Object { $_.StatusCode -eq 'Online' })
		if ($online.Count -gt 0) {
			# Добавляем онлайн ПК в список мониторинга
			$script:MonitoredComputers = @($online | ForEach-Object { $_.Name })

			# ВАЖНО: этот обработчик сработает ПОЗЖЕ, когда блок уже завершён, —
			# локальная $timer к тому моменту не существует. Держим таймер в $script:.
			$script:MonitorBootTimer = New-Object System.Windows.Threading.DispatcherTimer
			$script:MonitorBootTimer.Interval = [TimeSpan]::FromSeconds(15)
			$script:MonitorBootTimer.Add_Tick({
				$script:MonitorBootTimer.Stop()
				if (-not $script:EventMonitorRunning -and $script:MonitoredComputers.Count -gt 0) {
					Start-EventMonitor -Interval 60 -TargetComputers $script:MonitoredComputers
				}
			})
			$script:MonitorBootTimer.Start()
		}
	}
} catch {
	Write-AppLog "Ошибка инициализации мониторинга: $($_.Exception.Message)" 'WARN'
}
})

# ============================================================================
# МОДУЛЬ ВСПЛЫВАЮЩИХ УВЕДОМЛЕНИЙ (WINDOWS 10/11 TOAST NOTIFICATIONS)
# ============================================================================

# Добавляем сборки
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { 
Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop 
} catch {}

# Проверяем доступность Toast
$script:ToastAvailable = $false
$errBefore = $Error.Count
if ($PSVersionTable.PSEdition -eq 'Desktop') {   # WinRT есть только в 5.1
try {
Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$script:ToastAvailable = $true
} catch {}
}
while ($Error.Count -gt $errBefore) { $Error.RemoveAt(0) }   # не оставляем шум в $Error

# Инициализация
if ($script:ToastAvailable) {
Write-AppLog "Toast Notifications доступны" 'INFO'
}

Write-AppLog "Модуль мониторинга инициализирован (Toast: $script:ToastAvailable)" 'OK'

# Вызываем при загрузке
$window.Add_ContentRendered({
try {
	#Add-NotificationTestButton
} catch {
	Write-AppLog "Ошибка добавления кнопки теста: $($_.Exception.Message)" 'WARN'
}
})

# ============================================================================
# ГЛОБАЛЬНЫЙ ЛОГ ДЛЯ ДИАГНОСТИКИ МОНИТОРИНГА (СОХРАНЯЕТСЯ ДО ЗАКРЫТИЯ ПРОГРАММЫ)
# ============================================================================

# Инициализируем глобальный лог для диагностики
if (-not $script:MonitorDiagnosticLog) {
$script:MonitorDiagnosticLog = New-Object System.Collections.ObjectModel.ObservableCollection[string]
$script:MonitorDiagnosticLog.Add("🟢 Диагностический лог инициализирован $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
}

$script:Ui.GridComputers.AddHandler(
[System.Windows.Controls.Primitives.ButtonBase]::ClickEvent,
[System.Windows.RoutedEventHandler]{
	param($sender, $e)
	if ($e.OriginalSource -isnot [System.Windows.Controls.GridViewColumnHeader]) { return }
	$header = $e.OriginalSource
	if (-not $header.Column) { return }

	$sortPath = $header.Column.SortMemberPath
	if (-not $sortPath -and $header.Column.DisplayMemberBinding) {
		$sortPath = $header.Column.DisplayMemberBinding.Path.Path
	}
	if (-not $sortPath) { return }

	$dir = [System.ComponentModel.ListSortDirection]::Ascending
	if ($script:LastSortPath -eq $sortPath -and $script:LastSortDir -eq 'Asc') {
		$dir = [System.ComponentModel.ListSortDirection]::Descending
	}
	$script:LastSortPath = $sortPath
	$script:LastSortDir = if ($dir -eq 'Ascending') { 'Asc' } else { 'Desc' }

	$view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:AllComputers)
	$view.SortDescriptions.Clear()
	$view.SortDescriptions.Add(
		(New-Object System.ComponentModel.SortDescription($sortPath, $dir))
	)
	$e.Handled = $true
},
$true
)

# ---------------------------------------------------------------------------
# Старт
# ---------------------------------------------------------------------------
Write-AppLog "Запуск. Пользователь: $env:USERDOMAIN\$env:USERNAME  Домен: $script:DomainName"
if (-not (Get-IsAdmin)) {
Write-AppLog 'Процесс без повышения UAC — WMI/выключение на чужих ПК могут получить Access Denied.' 'WARN'
}
Update-Overview
Restart-AutoTimer

# Сохраняем ссылку на окно в переменную
$mainWindow = $window

# Сохраняем ссылку на окно в глобальную переменную для доступа из других функций
if ($mainWindow) {
$script:Ui.Window = $mainWindow

# RS-NO-CLOSE (config.ps1:402) — регистрируем освобождение пула runspace'ов
# на Window.Closed / Dispatcher.ShutdownStarted / AppDomain.ProcessExit.
try {
	if (Get-Command Register-RsPoolCleanup -CommandType Function -ErrorAction Ignore) {
		Register-RsPoolCleanup -Window $mainWindow
	} else {
		Write-AppLog "Register-RsPoolCleanup недоступен — хуки выхода не зарегистрированы (см. предупреждение о runspace-pool.ps1 выше)" 'WARN'
	}
} catch {
	Write-AppLog "Register-RsPoolCleanup: $($_.Exception.Message)" 'WARN'
}

# Страховка Dispatcher: логируем, предупреждаем, НЕ роняем приложение
$script:Ui.Window.Dispatcher.Add_UnhandledException({
    param($s, $e)
    try {
        $ex = $e.Exception
        $msg = try { $ex.Message } catch { '' }

        # ── вытаскиваем из $Error[0] — там ErrorRecord с InvocationInfo ──
        $where = '(нет)'
        $code  = ''
        try {
            $err = $Error[0]
            if ($err -and $err.InvocationInfo) {
                $inv = $err.InvocationInfo
                $sn = try { $inv.ScriptName } catch { '' }
                $ln = try { $inv.ScriptLineNumber } catch { 0 }
                $tx = try { $inv.Line } catch { '' }
                if ($sn) { $where = "$sn`:$ln" }
                if ($tx) { $code = ([string]$tx).Trim() }
            }
        } catch {}

        $st = try { $ex.StackTrace } catch { '' }
        $text = "UI-EXC: $msg`nWHERE: $where`nCODE: $code`nSTACK:`n$st"
        Write-AppLog $text 'ERROR'
    } catch {}
    try { $e.Handled = $true } catch {}
})
}

# Добавляем обработчик ContentRendered с проверкой
if ($mainWindow) {
$mainWindow.Add_ContentRendered({
	param($sender, $e)

	try {
		Update-DebugMode

		# Применяем состояние экспериментальных функций ПРИ ЗАГРУЗКЕ
		ApplyExperimentalFeaturesState
		#ПРОВЕРКА
		UpdateExperimentalTabsVisibility
		#UpdateExperimentalFeaturesVisibility

		# Добавляем кнопку диагностики мониторинга
		try {
			#Add-MonitorDebugButton
		} catch {
			Write-AppLog "Ошибка добавления кнопки диагностики: $($_.Exception.Message)" 'WARN'
		}

		try {
			Import-DomainComputerList
			###ПРОВЕРИМ###
			#Start-StatusScan
			if ($script:AllComputers.Count -gt 0) {
				Start-StatusScan
			}
		} catch {
			Write-AppLog $_.Exception.Message 'ERROR'
		}

		# Обновляем индикатор кэша
		Update-CacheIndicator

		# Инициализация мониторинга
		try {
			# Загружаем сохраненные уведомления

			# Добавляем UI элементы для мониторинга
			# Страховка: монтирует всё, что зарегистрировано, но ещё не смонтировано
			# (Mount-DacPlugin идемпотентен, дублей кнопок/вкладок не будет).
			try { Mount-DacPlugins } catch { Write-AppLog "Плагины: $($_.Exception.Message)" 'WARN' }
			# Автоматический запуск мониторинга, если есть онлайн ПК
#                if ($script:AllComputers.Count -gt 0) {
#                    $online = @($script:AllComputers | Where-Object { $_.StatusCode -eq 'Online' })
#                    if ($online.Count -gt 0) {
#                        # Запускаем с небольшой задержкой
#                        $startTimer = New-Object System.Windows.Threading.DispatcherTimer
#                        $startTimer.Interval = [TimeSpan]::FromSeconds(10)
#                        $startTimer.Add_Tick({
#                            $startTimer.Stop()
#                            if (-not $script:EventMonitorRunning) {
#                                Start-EventMonitor -Interval 60
#                            }
#                        })
#                        $startTimer.Start()
#                    } else {
#                        Write-AppLog "Нет онлайн ПК для автоматического запуска мониторинга" 'WARN'
#                    }
#                }
		} catch {
			Write-AppLog "Ошибка инициализации мониторинга: $($_.Exception.Message)" 'WARN'
			Write-AppLog "Ошибка монтажа плагинов: $($_.Exception.Message)" 'WARN'
		}

	} catch {
		Write-AppLog "Ошибка в ContentRendered: $($_.Exception.Message)" 'ERROR'
	}
})
}

# Проверяем, что окно существует перед вызовом ShowDialog
if ($null -ne $mainWindow) {
try {
	# Запускаем окно
	[void]$mainWindow.ShowDialog()
} catch {
	$errMsg = $_.Exception.Message
	Write-AppLog "Ошибка ShowDialog: $errMsg" 'ERROR'

	# Пытаемся показать сообщение об ошибке через MessageBox
	try {
		[System.Windows.MessageBox]::Show(
			"Ошибка при запуске приложения:`n`n$errMsg`n`n" +
			"Попробуйте перезапустить приложение или проверьте журнал ошибок.",
			$script:AppTitle,
			'OK',
			'Error'
		) | Out-Null
	} catch {
		# Если даже MessageBox не работает - выводим в консоль
		Write-Host "КРИТИЧЕСКАЯ ОШИБКА: $errMsg" -ForegroundColor Red
	}
	finally {
		# RS-NO-CLOSE: пулы runspace'ов закрываются при ЛЮБОМ исходе ShowDialog
		# (нормальный выход, исключение, снятие окна извне).
		try { if (Get-Command Invoke-AppShutdownCleanup -CommandType Function -ErrorAction Ignore) { Invoke-AppShutdownCleanup -Reason 'Main.finally' } } catch {}
	}
}
} else {
Write-AppLog "Ошибка: окно не создано" 'ERROR'
try {
	[System.Windows.MessageBox]::Show(
		"Не удалось создать главное окно приложения.`n`n" +
		"Проверьте файл на наличие ошибок в XAML разметке.",
		$script:AppTitle,
		'OK',
		'Error'
	) | Out-Null
} catch {
	Write-Host "КРИТИЧЕСКАЯ ОШИБКА: Окно не создано" -ForegroundColor Red
}
}
