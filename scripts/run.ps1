# Downloads the latest letsSS release and runs the desktop app or the command-line tool.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repository = '1jmdev/letsss'

Write-Host ''
Write-Host '  letsSS - Minecraft screenshare tool' -ForegroundColor Cyan
Write-Host ''
Write-Host '  1) Desktop app'
Write-Host '  2) Command-line tool'
Write-Host '  3) Exit'
Write-Host ''
do {
    $Choice = Read-Host 'Select 1, 2 or 3'
} until ($Choice -in '1', '2', '3')

switch ($Choice) {
    '1' { $Asset = 'letsSS-desktop-windows-x86_64.exe'; $Arguments = @() }
    '2' { $Asset = 'letsss-windows-x86_64.exe'; $Arguments = @('--no-elevate') }
    '3' { return }
}

$Destination = Join-Path $env:TEMP $Asset
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Downloading $Asset..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest/download/$Asset" -OutFile $Destination -UseBasicParsing
Unblock-File -Path $Destination

Write-Host 'Starting letsSS (accept the administrator prompt)...' -ForegroundColor Cyan
if ($Arguments.Count -gt 0) {
    Start-Process -FilePath $Destination -ArgumentList $Arguments -Verb RunAs
} else {
    Start-Process -FilePath $Destination -Verb RunAs
}
