$URI = "https://raw.githubusercontent.com/azdeivids/PowerShell/main/examples/choco-install/ent_packages.config"
$CONFIG = ".\packages.config"
#Requires -RunAsAdministrator
$run_local=$args[0]

# install chocolatey if not installed
if (!(Test-Path -Path "$env:ProgramData\Chocolatey")) {
  Invoke-Expression((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

if ($run_local -eq "local") {
# for each package in the list run install
  Get-Content $CONFIG | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}
else
{
# for each package in the list run install
Write-Host "File not found!!!"  
(Invoke-webrequest -URI $URI).Content | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}