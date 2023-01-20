$URI = "https://raw.githubusercontent.com/azdeivids/PowerShell/main/examples/choco-install/ent_packages.config"
$CONFIG = "C:\Users\degle\Dev\PowerShell\examples\choco-install\ent_packages.config"
#Requires -RunAsAdministrator
$run_local=$args[0]

# install chocolatey if not installed
if (!(Test-Path -Path "$env:ProgramData\Chocolatey")) {
  Invoke-Expression((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

if ($run_local -eq "local") {
# for each package in the list run install
  Get-Content "C:\Users\degle\Dev\PowerShell\examples\choco-install\ent_packages.config" | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}
else
{
# for each package in the list run install
Write-Host "File not found!!!"  
(Invoke-webrequest -URI $URI).Content | ForEach-Object{($_ -split "\r\n")[0]} | ForEach-Object{choco install -y $_}
}

Start-Sleep -Seconds 360

$UnifiSearchToolUrl = "https://github.com/Crypto-Spartan/unifi-search-tool/releases/download/2.0.1/unifi-search-tool_v2.0.1.exe"
$UnifiSeachToolOutpath = "C:\temp\unifi-search-tool_v2.0.1.exe"
  
  Invoke-WebRequest -Uri $UnifiSearchToolUrl -OutFile $UnifiSeachToolOutpath

  C:\temp\unifi-search-tool_v2.0.1.exe

Install-Module -Name Terminal-Icons -Repository PSGallery
Install-Module posh-git