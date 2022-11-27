<#
.SYNOPSIS
Get physical network adapters.
.DESCRIPTION
Display all physical network adapters from Win32_NetworkAdapter class.
.PARAMETER computername
Name of computer to be queried
.EXAMPLE
~\Get-PhysicalNetworkAdapter -host dc2k22
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,HelpMessage="Enter a computer name to be queried")]
    [Alias('hostname')]
    [string]$computername
)
Write-Verbose "Getting physical network adapter from $computername"
Get-CimInstance Win32_NetworkAdapter -ComputerName $computername |
Where-Object { $_.PhysicalAdapter } |
Select-Object MACAddress,AdapterType,DeviceID,Name,Speed
Write-Verbose "Script has completed."