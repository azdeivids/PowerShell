<#  

.SYNOPSIS
 This will only work with powershell 7
.DESCRIPTION
During the script execution you will be asked to provide the taget service to test the connection to. You can use FQDN or IP address.
This will be set in the $target variable.
.EXAMPLE
./Test-Connection.ps1 | Tee-Object -FilePath output.txt

This will dump the results in the specified FilePath as well as show them in the console.

#>

$target = Read-Host "Enter the target service"
Write-Host "Testing connection to: $target"

Test-Connection $target -Repeat | select @{name="Time";expr={Get-Date}},Status,Latency