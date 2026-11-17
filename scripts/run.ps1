# Downloads the latest letsSS command-line release and runs it as administrator.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repository = '1jmdev/letsss'
$Asset = 'letsss-windows-x86_64.exe'
$Destination = Join-Path $env:TEMP $Asset

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host 'Downloading letsSS...' -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest/download/$Asset" -OutFile $Destination -UseBasicParsing
Unblock-File -Path $Destination

Write-Host 'Starting letsSS (accept the administrator prompt)...' -ForegroundColor Cyan
Start-Process -FilePath $Destination -ArgumentList '--no-elevate' -Verb RunAs -Wait
