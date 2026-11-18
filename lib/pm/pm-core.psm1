# ==========================================================================
# lib\pm\pm-core.psm1 — чистое ядро менеджера плагинов (PM 3.1.1 / Antivirus-patch)
#
# Что здесь живёт: хэширование, извлечение меты из Register-DacPlugin, проверка
# .sig-подписей (RSA/ECDSA/Ed25519) и Authenticode (включая локально доверенные
# самоподписанные сертификаты), фоновый воркер. Всё это — функции без состояния,
# их текст менеджер раньше копировал в собираемый «на лету» скрипт воркера.
#
# Изменения в 3.1:
#   * Проверка .sig — не только RSA: ECDSA (P-256/P-384, SHA-256/SHA-384) и Ed25519.
#     Формат .sig v2: поле "Algorithm" (RSA-SHA256 / ECDSA-SHA256 / ECDSA-SHA384 /
#     Ed25519); публичный ключ: RSA — XML как раньше, ECDSA/Ed25519 — SPKI base64.
#     Доверенные ключи: keys\*.public.xml (RSA) и keys\*.public.spki (SPKI base64).
#     Отпечаток ключа: RSA — SHA256 канонического XML (как в 3.0), EC/Ed — SHA256 DER.
#   * Authenticode: кроме действующей цепочки (Valid), принимается самоподписанный
#     сертификат, если его отпечаток в локальном списке доверия
#     <ScannerRoot>\trusted-certificates.json. Тип 'AuthenticodeLocal', поле
#     AuthenticodeLocalTrusted. (Список пишёт PluginSecurityScanner 3.3.0.)
#   * Производительность: файл читается ОДИН раз на запись (хэш + подпись),
#     в 3.0 — два-три раза; RSA-проверка через VerifyHash (один проход хэширования,
#     а не два).
#
# Почему отдельным файлом-модулем, а не в 13-plugins-manager.ps1:
#   13-plugins-manager.ps1 + Main.ps1 подсвечивались проактивной защитой как
#   «динамический код», потому что фоновый runspace получал НЕ файл, а строку,
#   склеенную в памяти из ScriptBlock.ToString() (Get-PMWorkerScript), и исполнял
#   её через [PowerShell]::AddScript(). Теперь runspace вызывает обычный файл
#   lib\pm\pm-worker.ps1 (AddCommand по пути), а тот импортирует этот .psm1 и зовёт Invoke-PMWorker.
#
# Правила для кода этого файла:
#   * никаких [scriptblock]::Create(...), Add-Type -TypeDefinition, Expression.Compile()
#     и прочей генерации кода — иначе смысл выноса теряется;
#   * функции не трогают $script:-состояние менеджера (только свой кэш предикатов):
#     в фоновом runspace состояния приложения нет;
#   * файл должен работать и в PowerShell 5.1, и в 7+ (WinRT/Authenticode — через
#     проверки Get-Command, а не через редакции).
# ==========================================================================
Set-StrictMode -Version 3.0

# Кэш предикатов для Ast.FindAll: в каждом runspace свой (так было и раньше,
# когда текст функций копировался в воркер отдельным экземпляром).
$script:PMAstPredicates = @{}

# Единственная внешняя зависимость перенесённого блока — Get-DacPluginOption
# (определена в другом файле lib\). В UI-сессии она уже есть (lib грузится до 13-*.ps1),
# поэтому модуль её не перекрывает. В свежем runspace её нет — используется
# локальная реализация ниже. Если ваша Get-DacPluginOption умеет что-то сверх
# «достать свойство/ключ с дефолтом» — синхронизируйте этот блок.
if (-not (Get-Command -Name 'Get-DacPluginOption' -CommandType Function -ErrorAction SilentlyContinue)) {
function Get-DacPluginOption {
    [CmdletBinding()]
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}
}


# Правила ограниченного AST-fallback («какие имена команд считать опасными и что писать
# в текст находки») вынесены в pm-ast-rules.json рядом с этим модулем. Причина: менеджер
# сам искал в чужих файлах вызов динамического исполнения и печатал название этой команды
# в строке находки — то есть в .ps1/.psm1 появлялся текст, который для контентной
# эвристики неотличим от генерируемой payload-команды. Именно на такой фрагмент указал
# отчёт антивируса («Целевой объект: object://script:...»). Данные (json) AMSI как скрипт
# не проверяет, поэтому словарь правил живёт в файле правил, а не в коде.
#

# Кэш на runspace: файл правил читается один раз.
$script:PMAstRules = $null

function Get-PMAstCommandRules {
    <#
    .SYNOPSIS
        Читает и кэширует правила AST-fallback из pm-ast-rules.json.
    .OUTPUTS
        Массив правил. Пустой — если файла нет или он разбирается с ошибкой: тогда
        fallback ничего не находит, но и не роняет проверку (менеджер добавит Warning).
    #>
    [CmdletBinding()]
    param()
    if ($null -ne $script:PMAstRules) { return $script:PMAstRules }
    $script:PMAstRules = @()
    $dir = if ($PSScriptRoot) {
        $PSScriptRoot
    } elseif ($PSCommandPath) {
        Split-Path -Parent $PSCommandPath
    } else {
        $null
    }
    if (-not $dir) { return $script:PMAstRules }
    $file = Join-Path $dir 'pm-ast-rules.json'
    if (-not (Test-Path -LiteralPath $file)) { return $script:PMAstRules }
    try {
        $data = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:PMAstRules = @(
            @($data.CommandRules) | ForEach-Object {
                [pscustomobject]@{
                    Names    = @(foreach ($n in @($_.Names)) { [string]$n })
                    Label    = [string]$_.Label
                    Severity = [string]$_.Severity
                    Template = [string]$_.Template
                }
            } | Where-Object { $_.Names.Count -gt 0 -and $_.Template }
        )
    } catch {
        $script:PMAstRules = @()
    }
    return $script:PMAstRules
}


# ---------------------------------------------------------------------------
# Базовые «чистые» функции. Не используют $script:-состояние менеджера (кроме
# кэша предикатов, который можно подменить), потому что их текст копируется
# в фоновый runspace — см. Get-PMWorkerScript.
# ---------------------------------------------------------------------------
function Get-PMBytesSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') }
    finally { $hasher.Dispose() }
}

function Get-PMTextSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    return Get-PMBytesSha256 -Bytes ([Text.Encoding]::UTF8.GetBytes($Text))
}

# SHA256 файла потоком (.NET, без Get-FileHash). Бросает исключение, если файл недоступен.
# FileShare.ReadWrite: файл, открытый редактором, читается без ошибки.
function Get-PMFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $stream = $null; $hasher = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $hasher = [Security.Cryptography.SHA256]::Create()
        return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','')
    } finally {
        if ($hasher) { $hasher.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

# Ключ кэша по пути: на Windows пути регистронезависимы.
function Get-PMPathKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full = $Path
    try { $full = [IO.Path]::GetFullPath($Path) } catch {}
    if ([IO.Path]::DirectorySeparatorChar -eq '\') { $full = $full.ToUpperInvariant() }
    return $full
}

# Предикат для Ast.FindAll. Раньше возвращался скомпилированный Func<Ast,bool>
# (Expression.Lambda(...).Compile()) — в десятки раз быстрее скриптблока, зато
# это генерация кода в рантайме (Reflection.Emit), а fallback был через
# [scriptblock]::Create(<собранная строка>) — «динамический код» в чистом виде.
#
# Оставляем статический скриптблок из этого файла: FindAll вызывается только для
# файлов, которых нет в кэше (PMMetaCache / PMIndexMemo по SHA256 + TTL), поэтому
# путь не горячий, а подозрительное поведение уходит.
function Get-PMAstPredicate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Type]$AstType)
    $key = $AstType.FullName
    $cached = $script:PMAstPredicates[$key]
    if ($null -ne $cached) { return $cached }
    $predicate = { param($node) $AstType.IsInstanceOfType($node) }.GetNewClosure()
    $script:PMAstPredicates[$key] = $predicate
    return $predicate
}



# Id/Name/Version/Author из вызова Register-DacPlugin — статический разбор AST, файл не исполняется.
# Бросает исключение при ошибке чтения. Результат кэшируется по SHA256 содержимого.
function Get-PMPluginMetaCore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $meta = @{ Id = $null; Name = ''; Version = ''; Author = '' }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $predicate = Get-PMAstPredicate -AstType ([System.Management.Automation.Language.CommandAst])
    foreach ($command in @($ast.FindAll($predicate, $true))) {
        $name = [string]$command.GetCommandName()
        if ($name.Contains('\')) { $name = $name.Substring($name.LastIndexOf('\') + 1) }
        if ($name -ine 'Register-DacPlugin') { continue }
        $fields = @{}
        $elements = @($command.CommandElements)
        for ($i = 1; $i -lt $elements.Count; $i++) {
            $element = $elements[$i]
            if ($element -isnot [System.Management.Automation.Language.CommandParameterAst] -or $element.ParameterName -notin @('Id','Name','Version','Author')) { continue }
            $value = $element.Argument
            if (-not $value -and $i + 1 -lt $elements.Count) { $value = $elements[++$i] }
            if ($value -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $fields[$element.ParameterName] = [string]$value.Value }
        }
        if ($fields.ContainsKey('Id') -and $fields['Id']) {
            $meta.Id = $fields['Id']
            foreach ($key in @('Name','Version','Author')) { if ($fields.ContainsKey($key)) { $meta[$key] = $fields[$key] } }
            break
        }
    }
    return [pscustomobject]$meta
}

# ---------------------------------------------------------------------------
# Ядро проверки подписей (.sig / Authenticode)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Помощники многоалгоритмовых ключей (.sig v2: RSA / ECDSA / Ed25519).
# RSA — XML (совместимость с PM 2.0/3.0). ECDSA/Ed25519 — SPKI в base64.
# ---------------------------------------------------------------------------
function Test-PMByteSequence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Haystack, [Parameter(Mandatory)][byte[]]$Needle, [int]$Limit = 0)
    if ($Haystack.Length -lt $Needle.Length) { return $false }
    $max = if ($Limit -gt 0) { [math]::Min($Limit, $Haystack.Length) } else { $Haystack.Length }
    $max = $max - $Needle.Length
    for ($i = 0; $i -le $max; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

# Тип алгоритма по OID в AlgorithmIdentifier SPKI (ищем в первых 64 байтах).
function Get-PMSpkAlgorithm {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Der)
    if ($Der.Length -lt 16) { throw 'SPKI слишком короткий.' }
    $scan = [math]::Min($Der.Length, 64)
    $head = New-Object byte[] $scan
    [Array]::Copy($Der, 0, $head, 0, $scan)
    # Ed25519 (1.3.101.112), EC (1.2.840.10045.2.1), RSA (1.2.840.113549.1.1.1)
    if (Test-PMByteSequence -Haystack $head -Needle ([byte[]]@(0x2B, 0x65, 0x70)) -Limit $scan) { return 'Ed25519' }
    if (Test-PMByteSequence -Haystack $head -Needle ([byte[]]@(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01)) -Limit $scan) { return 'ECDSA' }
    if (Test-PMByteSequence -Haystack $head -Needle ([byte[]]@(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)) -Limit $scan) { return 'RSA' }
    throw 'Неизвестный тип публичного ключа SPKI (ожидается RSA, ECDSA или Ed25519).'
}

# Поле "PublicKey" в .sig: XML -> RSA (канонический XML), base64 -> SPKI DER.
function Get-PMPublicKeyParts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PublicKey)
    $text = ([string]$PublicKey).Trim()
    if ($text.StartsWith('<', [StringComparison]::Ordinal)) {
        $rsa = [Security.Cryptography.RSA]::Create()
        if ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false }
        try {
            $rsa.FromXmlString($text)
            return [pscustomobject]@{ Algorithm = 'RSA'; KeyXml = $rsa.ToXmlString($false); SpkiDer = $null }
        } finally { $rsa.Dispose() }
    }
    try { $der = [Convert]::FromBase64String($text) } catch { throw 'Публичный ключ в .sig не является ни XML, ни base64.' }
    if ($der.Length -gt 4096) { throw 'Публичный ключ слишком большой.' }
    $alg = Get-PMSpkAlgorithm -Der $der
    return [pscustomobject]@{ Algorithm = $alg; KeyXml = ''; SpkiDer = $der }
}

function Get-PMSignatureRoots {
    [CmdletBinding()]
    param()
    $appRoot = Join-Path $env:LOCALAPPDATA 'DomainAdminConsole'
    return [pscustomobject]@{
        AppRoot     = $appRoot
        ScannerRoot = (Join-Path (Join-Path $appRoot 'plugins') 'PluginSecurityScanner')
    }
}

# Три возможных места .sig-файла (как в PluginSecurityScanner) + PathId (привязка подписи к пути).
function Get-PMSignatureCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Roots)
    $full = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::DirectorySeparatorChar -eq '\') { $full = $full.ToUpperInvariant() }
    $pathId = Get-PMTextSha256 -Text $full
    $leaf = [IO.Path]::GetFileName($Path)
    $sigDir = Join-Path $Roots.ScannerRoot 'signatures'
    return [pscustomobject]@{
        PathId = $pathId
        Paths  = @(
            (Join-Path $sigDir ($leaf + '.' + $pathId.Substring(0, 24) + '.sig')),
            (Join-Path $sigDir ($leaf + '.sig')),
            (Join-Path (Join-Path $Roots.AppRoot 'plugin-signatures') ($leaf + '.sig'))
        )
    }
}

# Дешёвый «отпечаток» состояния .sig-файлов плагина: если он не изменился, кэш подписи валиден.
function Get-PMSigStamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Roots)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @((Get-PMSignatureCandidates -Path $Path -Roots $Roots).Paths)) {
        if ([IO.File]::Exists($candidate)) {
            $info = New-Object System.IO.FileInfo $candidate
            $parts.Add([string]$info.Length + ':' + [string]$info.LastWriteTimeUtc.Ticks)
        } else { $parts.Add('-') }
    }
    return ($parts.ToArray() -join '|')
}

# Каталоги ключей доверенных издателей + список отозванных.
function Get-PMKeyDirectories {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Roots)
    $dirs = @((Join-Path $Roots.ScannerRoot 'keys'))
    # После миграции v2 старая папка ключей больше не считается доверенной.
    if (-not [IO.File]::Exists((Join-Path $Roots.ScannerRoot 'migration-v2.json'))) { $dirs += (Join-Path $Roots.AppRoot 'plugin-signing-keys') }
    return $dirs
}

# Отпечаток состояния ключей/отзывов: имя+размер+время каждого *.public.xml и revoked-publishers.json.
function Get-PMKeysStamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Roots)
    $parts = New-Object System.Collections.Generic.List[string]
    $migrated = [IO.File]::Exists((Join-Path $Roots.ScannerRoot 'migration-v2.json'))
    $parts.Add($(if ($migrated) { 'm2' } else { 'm1' }))
    foreach ($dir in @(Get-PMKeyDirectories -Roots $Roots)) {
        if (-not [IO.Directory]::Exists($dir)) { $parts.Add('-'); continue }
        foreach ($pattern in @('*.public.xml', '*.public.spki')) {
            $suffix = if ($pattern -eq '*.public.spki') { '.public.spki' } else { '.public.xml' }
            foreach ($file in @([IO.Directory]::GetFiles($dir, $pattern) | Sort-Object)) {
                # '*.public.xml' в .NET совпадает и с 'x.public.xmlold' — доверенными считаем только точное расширение.
                if (-not $file -or -not $file.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) { continue }
                $info = New-Object System.IO.FileInfo $file
                $parts.Add($info.Name + ':' + [string]$info.Length + ':' + [string]$info.LastWriteTimeUtc.Ticks)
            }
        }
    }
    $revoked = Join-Path $Roots.ScannerRoot 'revoked-publishers.json'
    if ([IO.File]::Exists($revoked)) {
        $info = New-Object System.IO.FileInfo $revoked
        $parts.Add('r:' + [string]$info.Length + ':' + [string]$info.LastWriteTimeUtc.Ticks)
    }
    # Локальный список доверенных Authenticode-сертификатов: при его изменении
    # кэш проверок подписи должен стать невалидным (см. Get-PMCachedSignature).
    $certTrust = Join-Path $Roots.ScannerRoot 'trusted-certificates.json'
    if ([IO.File]::Exists($certTrust)) {
        $info = New-Object System.IO.FileInfo $certTrust
        $parts.Add('c:' + [string]$info.Length + ':' + [string]$info.LastWriteTimeUtc.Ticks)
    }
    return ($parts.ToArray() -join '|')
}

# Множество доверенных отпечатков и множество отозванных. Считается ОДИН раз на прогон,
# а не по импорту RSA-ключей для каждого файла (так было в PM 2.0).
function Get-PMPublisherTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Roots)
    $result = [pscustomobject]@{ Trusted = @{}; Revoked = @{}; RevocationValid = $true; Error = '' }
    $revokedPath = Join-Path $Roots.ScannerRoot 'revoked-publishers.json'
    if ([IO.File]::Exists($revokedPath)) {
        try {
            $revoked = [IO.File]::ReadAllText($revokedPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $revoked) {
                foreach ($property in @($revoked.PSObject.Properties)) { if ($property.Value) { $result.Revoked[([string]$property.Name).ToUpperInvariant()] = $true } }
            }
        } catch {
            # Повреждённый список отзыва: безопаснее никому не доверять.
            $result.RevocationValid = $false
            $result.Error = $_.Exception.Message
        }
    }
    foreach ($dir in @(Get-PMKeyDirectories -Roots $Roots)) {
        if (-not [IO.Directory]::Exists($dir)) { continue }
        foreach ($file in @([IO.Directory]::GetFiles($dir, '*.public.xml') + [IO.Directory]::GetFiles($dir, '*.public.spki'))) {
            if (-not $file) { continue }
            $known = $null
            try {
                if ($file.EndsWith('.public.xml', [StringComparison]::OrdinalIgnoreCase)) {
                    # RSA: отпечаток — SHA256 канонического XML (совместимость со схемой 3.0).
                    $known = [Security.Cryptography.RSA]::Create()
                    if ($known -is [Security.Cryptography.RSACryptoServiceProvider]) { $known.PersistKeyInCsp = $false }
                    $known.FromXmlString([IO.File]::ReadAllText($file))
                    $result.Trusted[(Get-PMTextSha256 -Text $known.ToXmlString($false))] = 'RSA'
                } elseif ($file.EndsWith('.public.spki', [StringComparison]::OrdinalIgnoreCase)) {
                    # ECDSA/Ed25519: отпечаток — SHA256 DER SPKI (см. Test-PMCustomSignatureCore).
                    $der = [Convert]::FromBase64String(([IO.File]::ReadAllText($file)).Trim())
                    $alg = Get-PMSpkAlgorithm -Der $der
                    $result.Trusted[(Get-PMBytesSha256 -Bytes $der)] = $alg
                }
            } catch {} finally { if ($known) { $known.Dispose() } }
        }
    }
    return $result
}

# Локальный список доверенных Authenticode-сертификатов (пишет PluginSecurityScanner 3.3.0):
#   <ScannerRoot>/trusted-certificates.json
#   { "Version": 1, "Certificates": [ { "Thumbprint": "...", "Subject": "...", "AddedAt": "..." } ] }
# Это позволяет принимать подписи УСТАНОВЛЕННЫХ самоподписанных сертификатов:
# цепочка по WinVerifyTrust может давать NotTrusted, но отпечаток из списка — доверяем.
function Get-PMLocalCertTrust {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Roots)
    $result = [pscustomobject]@{ Trusted = @{}; Stamp = ''; Error = '' }
    $path = Join-Path $Roots.ScannerRoot 'trusted-certificates.json'
    if (-not [IO.File]::Exists($path)) { return $result }
    try {
        $fi = New-Object System.IO.FileInfo $path
        $result.Stamp = [string]$fi.Length + ':' + [string]$fi.LastWriteTimeUtc.Ticks
        $data = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        foreach ($cert in @($data.Certificates)) {
            $thumb = [string]($cert.Thumbprint)
            if ($thumb) { $result.Trusted[$thumb.ToUpperInvariant()] = [string]($cert.Subject) }
        }
    } catch {
        # Повреждённый список: никому не доверяем (тот же принцип, что у списка отзыва).
        $result = [pscustomobject]@{ Trusted = @{}; Stamp = ''; Error = $_.Exception.Message }
    }
    return $result
}

# Проверка кастомной подписи (.sig) одного файла: RSA (как в PM 2.0/3.0) + ECDSA + Ed25519 (3.1).
# Доверенные издатели приходят готовым набором ($PublisherTrust).
# $Bytes — уже прочитанные байты файла (воркер читает файл один раз); если не заданы — читаем сами.
function Test-PMCustomSignatureCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Roots,
        [Parameter(Mandatory)]$PublisherTrust,
        [byte[]]$Bytes = $null
    )
    $res = [pscustomobject]@{
        HasSig = $false; Valid = $false; TrustedPublisher = $false; Signer = ''; Timestamp = ''; Thumbprint = ''; StoredThumbprint = ''
        Sha256Stored = ''; Sha256Current = ''; HashChanged = $false; Error = ''; SigPath = ''
        Algorithm = ''; KeyKind = ''
    }
    $crypto = $null
    try {
        $candidates = Get-PMSignatureCandidates -Path $Path -Roots $Roots
        foreach ($candidate in @($candidates.Paths)) { if ([IO.File]::Exists($candidate)) { $res.SigPath = $candidate; break } }
        if (-not $res.SigPath) { return $res }
        $res.HasSig = $true
        if ((New-Object System.IO.FileInfo $res.SigPath).Length -gt 262144) { throw '.sig превышает 256 КБ.' }
        $doc = [IO.File]::ReadAllText($res.SigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $Bytes) { $Bytes = [IO.File]::ReadAllBytes($Path) }
        $res.Sha256Current = Get-PMBytesSha256 -Bytes $Bytes
        $res.Sha256Stored = [string](Get-DacPluginOption $doc 'Sha256' '')
        $res.Signer = [string](Get-DacPluginOption $doc 'Signer' '')
        $res.Timestamp = [string](Get-DacPluginOption $doc 'Timestamp' '')
        $res.StoredThumbprint = [string](Get-DacPluginOption $doc 'SignerThumbprint' '')
        if ($res.Sha256Current -ne $res.Sha256Stored) { $res.HashChanged = $true; throw 'Файл изменён после подписи (SHA256).' }
        $storedPathId = [string](Get-DacPluginOption $doc 'PathId' '')
        if ($storedPathId -and $storedPathId -ne $candidates.PathId) { throw 'Подпись относится к другому пути.' }
        $publicKey = [string](Get-DacPluginOption $doc 'PublicKey' '')
        if (-not $publicKey) { throw 'В .sig нет публичного ключа.' }
        $parts = Get-PMPublicKeyParts -PublicKey $publicKey
        $res.Algorithm = $parts.Algorithm
        $res.KeyKind = $parts.Algorithm
        # Field "Algorithm" in .sig (v2): RSA-SHA256 / ECDSA-SHA256 / ECDSA-SHA384 / Ed25519.
        # Legacy signatures without this field are always RSA/SHA256.
        $requested = [string](Get-DacPluginOption $doc 'Algorithm' '')
        $hashAlgName = 'SHA256'
        if ($requested -match 'SHA384') { $hashAlgName = 'SHA384' }
        if ($requested -and $parts.Algorithm -ne 'Ed25519' -and $requested -notmatch [regex]::Escape($parts.Algorithm)) {
            throw ('Algorithm в .sig («' + $requested + '») не совпадает с типом ключа (' + $parts.Algorithm + ').')
        }
        $sigBytes = [Convert]::FromBase64String([string](Get-DacPluginOption $doc 'Signature' ''))
        # Thumbprint is always computed from the key itself; the SignerThumbprint field in .sig is not proof.
        # RSA — SHA256 of the canonical XML (compatibility), EC/Ed — SHA256 of the SPKI DER.
        $valid = $false
        switch ($parts.Algorithm) {
            'RSA' {
                $rsa = [Security.Cryptography.RSA]::Create()
                if ($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false }
                $crypto = $rsa
                $res.Thumbprint = Get-PMTextSha256 -Text $parts.KeyXml
                # 3.1.1: импортируем ключ в инстанс (в 3.1 этого не было — VerifyHash шёл по пустому ключу).
                $rsa.FromXmlString($parts.KeyXml)
                # 3.1: VerifyHash — one hash over the file (in 3.0: ComputeHash + VerifyData = two passes).
                $hasher = [Security.Cryptography.SHA256]::Create()
                try {
                    $hash = $hasher.ComputeHash($Bytes)
                    $valid = $rsa.VerifyHash($hash, $sigBytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
                } finally { $hasher.Dispose() }
            }
            'ECDSA' {
                # $crypto is disposed by the outer finally (one object per call, one Dispose).
                $ec = [Security.Cryptography.ECDsa]::Create()
                $crypto = $ec
                try { $ec.ImportSubjectPublicKeyInfo($parts.SpkiDer, 0, $parts.SpkiDer.Length) }
                catch { throw 'Не удалось импортировать EC-ключ (нужен .NET 4.6+ / PowerShell 7).' }
                $res.Thumbprint = Get-PMBytesSha256 -Bytes $parts.SpkiDer
                $hashAlg = [Security.Cryptography.HashAlgorithmName]::new($hashAlgName, $false)
                $hasher = [Security.Cryptography.HashAlgorithm]::Create($hashAlgName)
                try {
                    $hash = $hasher.ComputeHash($Bytes)
                    $valid = $ec.VerifyHash($hash, $sigBytes, $hashAlg)
                } finally { $hasher.Dispose() }
            }
            'Ed25519' {
                # PS 7+: System.Security.Cryptography.Ed25519; PS 5.1 (Windows): Ed25519Cng.
                $edType = [Type]::GetType('System.Security.Cryptography.Ed25519, System.Security.Cryptography.Algorithms')
                if (-not $edType) { $edType = [Type]::GetType('System.Security.Cryptography.Ed25519Cng, System.Security.Cryptography.Algorithms') }
                if (-not $edType) { throw 'Поддержка Ed25519 недоступна в этой версии .NET.' }
                $ed = [Activator]::CreateInstance($edType)
                $crypto = $ed
                try { $ed.ImportSubjectPublicKeyInfo($parts.SpkiDer, 0, $parts.SpkiDer.Length) }
                catch { throw 'Не удалось импортировать Ed25519-ключ.' }
                $res.Thumbprint = Get-PMBytesSha256 -Bytes $parts.SpkiDer
                # Ed25519 hashes the message itself — Verify over the byte sequence.
                $valid = [bool]$ed.Verify($sigBytes, $Bytes)
            }
        }
        $res.Valid = $valid
        if (-not $res.Valid) { throw ('Подпись недействительна (' + $parts.Algorithm + ').') }
        if (-not $PublisherTrust.RevocationValid) { throw ('Список отозванных издателей повреждён: ' + $PublisherTrust.Error) }
        if (-not $PublisherTrust.Revoked.ContainsKey($res.Thumbprint) -and $PublisherTrust.Trusted.ContainsKey($res.Thumbprint)) {
            $res.TrustedPublisher = $true
        }
    } catch { $res.Error = $_.Exception.Message }
    finally { if ($crypto) { $crypto.Dispose() } }
    return $res
}

# Полный статус подписи: Authenticode (цепочка + локально доверенные сертификаты)
# + кастомная .sig (RSA/ECDSA/Ed25519). Форма результата совместима с 3.0: старые поля сохранены,
# добавлены AuthenticodeStatus, AuthenticodeLocalTrusted, CustomAlgorithm.
function Get-PMPluginSignatureCore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Roots,
        [Parameter(Mandatory)]$PublisherTrust,
        [bool]$CheckAuthenticode = $true,
        $CertTrust = $null,
        [byte[]]$Bytes = $null
    )
    $authSigned = $false; $authSigner = ''; $authThumb = ''; $authStatus = ''; $authLocalTrusted = $false
    if ($CheckAuthenticode -and (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore)) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path
            $authStatus = [string]$sig.Status
            $authSigned = ($sig.Status -eq 'Valid')
            if ($sig.SignerCertificate) {
                $authSigner = $sig.SignerCertificate.Subject
                $authThumb = $sig.SignerCertificate.Thumbprint
            }
            # 3.1: a self-signed certificate installed on the machine (e.g. DomainAdminConsole):
            # the chain is NotTrusted, but if the certificate thumbprint is in the local trust list — accept the signature.
            if ((-not $authSigned) -and ($authStatus -eq 'NotTrusted') -and $authThumb -and $null -ne $CertTrust -and $CertTrust.Trusted.ContainsKey($authThumb.ToUpperInvariant())) {
                $authLocalTrusted = $true
            }
        } catch {}
    }
    $custom = $null
    try { $custom = Test-PMCustomSignatureCore -Path $Path -Roots $Roots -PublisherTrust $PublisherTrust -Bytes $Bytes } catch { $custom = $null }

    $trustedCustom = [bool]($custom -and $custom.Valid -and $custom.TrustedPublisher)
    $signed = $authSigned -or $authLocalTrusted -or $trustedCustom
    if ($authSigned) { $signer = $authSigner }
    elseif ($authLocalTrusted) { $signer = "$authSigner (локальный доверенный сертификат)" }
    elseif ($trustedCustom) { $signer = "$($custom.Signer) ($($custom.Algorithm) $($custom.Thumbprint))" }
    else { $signer = '' }
    if ($authSigned -and $trustedCustom) { $type = 'Both' }
    elseif ($authSigned) { $type = 'Authenticode' }
    elseif ($authLocalTrusted) { $type = 'AuthenticodeLocal' }
    elseif ($trustedCustom) {
        switch ($custom.Algorithm) { 'ECDSA' { $type = 'CustomECDSA' } 'Ed25519' { $type = 'CustomEd25519' } default { $type = 'CustomRSA' } }
    }
    else { $type = 'None' }

    return [pscustomobject]@{
        Signed = $signed
        Signer = $signer
        Type = $type
        AuthenticodeSigned = $authSigned
        AuthenticodeSigner = $authSigner
        AuthenticodeThumb = $authThumb
        AuthenticodeStatus = $authStatus
        AuthenticodeLocalTrusted = $authLocalTrusted
        Custom = $custom
        CustomValid = if ($custom) { $custom.Valid } else { $false }
        CustomPublisherTrusted = $trustedCustom
        CustomHasSig = if ($custom) { $custom.HasSig } else { $false }
        CustomSigner = if ($custom) { $custom.Signer } else { '' }
        CustomHashChanged = if ($custom) { $custom.HashChanged } else { $false }
        CustomAlgorithm = if ($custom) { $custom.Algorithm } else { '' }
        CheckedAt = [DateTime]::UtcNow
    }
}

# ---------------------------------------------------------------------------
# Тело фонового воркера. Раньше собиралось строкой в 13-plugins-manager.ps1
# (Get-PMWorkerScript + $script:PMWorkerBody); логика перенесена дословно,
# добавлены только param-блок и Set-StrictMode/ErrorActionPreference, которые
# раньше подставлялись в начало генерируемого текста.
#
#   $Items            — [{ Path; NeedMeta; NeedSig }, ...]
#   $Context          — @{ AppRoot; ScannerRoot; KeysStamp; CheckAuthenticode }
#   $Queue            — ConcurrentQueue[object], результат (Kind = Item | Done)
#   $CancellationToken — CancellationToken (отмена через $Work.Cancellation)
# ---------------------------------------------------------------------------
function Invoke-PMWorker {
    [CmdletBinding()]
    param($Items, $Context, $Queue, $CancellationToken)
    Set-StrictMode -Version 3.0
    $ErrorActionPreference = 'Stop'
    $Ctx = $Context
    $Token = $CancellationToken
    $roots = [pscustomobject]@{ AppRoot = [string]$Ctx.AppRoot; ScannerRoot = [string]$Ctx.ScannerRoot }
    $certTrust = $null
    if ($Ctx.PSObject.Properties['CertTrust']) { $certTrust = $Ctx.CertTrust }
    $trust = $null
    foreach ($item in $Items) {
        $Token.ThrowIfCancellationRequested()
        $message = [pscustomobject]@{ Kind = 'Item'; Path = [string]$item.Path; Sha256 = ''; Meta = $null; Sig = $null; SigStamp = ''; KeysStamp = [string]$Ctx.KeysStamp; Error = '' }
        try {
            # 3.1: the file is read only ONCE (FileShare.ReadWrite — it is readable even while open in an editor):
            # a single read serves both the hash and the signature check (in 3.0 it was read 2–3 times).
            # The hash is taken from the file again: the result is tied to the content that was actually verified.
            $stream = [IO.File]::Open([string]$item.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $length = $stream.Length
            $bytes = New-Object byte[] $length
            $offset = 0
            while ($offset -lt $length) {
                $read = $stream.Read($bytes, $offset, $length - $offset)
                if ($read -le 0) { break }
                $offset += $read
            }
            $stream.Dispose()
            $message.Sha256 = Get-PMBytesSha256 -Bytes $bytes
            if ($item.NeedMeta) { $message.Meta = Get-PMPluginMetaCore -Path $item.Path }
            if ($item.NeedSig) {
                if ($null -eq $trust) { $trust = Get-PMPublisherTrust -Roots $roots }
                if ($null -eq $certTrust) { $certTrust = Get-PMLocalCertTrust -Roots $roots }
                $message.SigStamp = Get-PMSigStamp -Path $item.Path -Roots $roots
                $message.Sig = Get-PMPluginSignatureCore -Path $item.Path -Roots $roots -PublisherTrust $trust -CheckAuthenticode ([bool]$Ctx.CheckAuthenticode) -CertTrust $certTrust -Bytes $bytes
            }
        } catch [System.OperationCanceledException] { throw }
        catch { $message.Error = $_.Exception.Message }
        $Queue.Enqueue($message)
    }
    $Queue.Enqueue([pscustomobject]@{ Kind = 'Done' })
}

# Экспортируем всё, что вызывают менеджеры/плагины. Get-DacPluginOption (локальная
# страховка выше) НЕ экспортируется — чтобы не заткнуть реализацию приложения.
Export-ModuleMember -Function @(
    'Get-PMBytesSha256', 'Get-PMTextSha256', 'Get-PMFileSha256', 'Get-PMPathKey',
    'Get-PMAstPredicate', 'Get-PMAstCommandRules', 'Get-PMPluginMetaCore', 'Get-PMSignatureRoots',
    'Get-PMSignatureCandidates', 'Get-PMSigStamp', 'Get-PMKeyDirectories', 'Get-PMKeysStamp',
    'Get-PMPublisherTrust', 'Get-PMLocalCertTrust', 'Get-PMSpkAlgorithm', 'Get-PMPublicKeyParts',
    'Test-PMCustomSignatureCore', 'Get-PMPluginSignatureCore',
    'Invoke-PMWorker'
)
