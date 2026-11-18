# ==========================================================================
# lib\pm\pm-worker.ps1 — точка входа фонового воркера менеджера плагинов.
#
# Файл нужен, чтобы runspace получал НЕ «собранный в памяти текст скрипта»
# (как делал Get-PMWorkerScript + [PowerShell]::AddScript), а обычный статический
# скрипт с диска: его можно прочитать, проверить подписью и не за что зацепиться
# проактивной защите. Логика — в pm-core.psm1, здесь только связка.
#
# Вызывается из Start-PMInspect:
#   [void]$ps.AddCommand($script:PMWorkerEntryPoint)   # путь к этому файлу
#   [void]$ps.AddParameter('Items', $items) ...
# ==========================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory)]$Items,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$Queue,
    [Parameter(Mandatory)]$CancellationToken
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$corePath = Join-Path $PSScriptRoot 'pm-core.psm1'
if (-not (Test-Path -LiteralPath $corePath)) { throw "Не найден pm-core.psm1: $corePath" }
Import-Module -Name $corePath -Force -Global

Invoke-PMWorker -Items $Items -Context $Context -Queue $Queue -CancellationToken $CancellationToken
