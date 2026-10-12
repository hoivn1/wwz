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
    'Handle',
    'Access mask',
    'Call stack',
    'ETW',
    'ObRegisterCallbacks',
    'ETW-TI',
    'Handle stripping',
    'Process protection light'
)

if (-not (Test-Path -LiteralPath $Executable)) {
    throw "Report executable not found: $Executable"
}
if (-not (Test-Path -LiteralPath $Document)) {
    throw "Detection document not found: $Document"
}

$report = (& $Executable 2>&1 | Out-String)
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    throw "Report executable failed with exit code $exitCode`n$report"
}
foreach ($export in $exports) {
    $linePattern = '(?im)^' + [regex]::Escape($export) + '\s+address=(?!0x?0+$)(?:0x)?[0-9a-f]+\s+syscall_number=\d+\s*$'
    if ($report -notmatch $linePattern) {
        throw "Report is missing a valid line for $export (name, non-null address, numeric syscall_number)"
    }
}

$content = Get-Content -Raw -LiteralPath $Document
foreach ($heading in $headings) {
    $headingPattern = '(?im)^###\s+' + [regex]::Escape($heading) + '\s*$'
    if ($content -notmatch $headingPattern) {
        throw "Detection document is missing required heading: $heading"
    }
}

Write-Output 'Detection surface verification passed.'
