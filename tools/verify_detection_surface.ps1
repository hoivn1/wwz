param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\build\Release\wwz_external.exe'),
    [string]$Document = (Join-Path $PSScriptRoot '..\include\wwz\Sandbox\DetectionSurface.md')
)

$ErrorActionPreference = 'Stop'
$exports = @(
    'NtReadVirtualMemory',
    'NtWriteVirtualMemory',
    'NtOpenProcess',
    'NtProtectVirtualMemory'
)
$headings = @(
    'handle',
    'access mask',
    'call stack',
    'ETW',
    'ObRegisterCallbacks',
    'ETW-TI',
    'handle stripping',
    'process protection light'
)

if (-not (Test-Path -LiteralPath $Executable)) {
    throw "Report executable not found: $Executable"
}
if (-not (Test-Path -LiteralPath $Document)) {
    throw "Detection document not found: $Document"
}

$report = (& $Executable 2>&1 | Out-String)
foreach ($export in $exports) {
    if ($report -notmatch [regex]::Escape($export)) {
        throw "Report is missing export name: $export"
    }
}

$content = Get-Content -Raw -LiteralPath $Document
foreach ($heading in $headings) {
    if ($content -notmatch [regex]::Escape($heading)) {
        throw "Detection document is missing required heading/text: $heading"
    }
}

Write-Output 'Detection surface verification passed.'
