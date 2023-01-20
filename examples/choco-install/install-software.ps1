$URI = "github_url"
$FILE = ".\win11.ent.choco.yml"
#Requires -RunAsAdministrator
$run_local=$args[0]

# install chocolatey if not installed
if (!(Test-Path -Path "$env:ProgramData\Chocolatey")) {
  Invoke-Expression((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

if ($run_local -eq "local") {
# for each package in the list run install
  Get-Content "C:\Users\degle\Dev\PowerShell\examples\choco-install\win11.ent.choco.yml" | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}
else
{
# for each package in the list run install
Write-Host "File not found!!!"  
#(Invoke-webrequest -URI $URI).Content | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}