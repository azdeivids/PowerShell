<#
.SYNOPSIS
Get-DiskInvetory retrieves logical disk information from one or more computers
.DESCRIPTION
Get-DiskInvetory uses CIM to retrieve the Win32_LogicalDisk instances from one or
more computers. It displays each disk's drive letter, free space, total size, and
percentage of free space.
.PARAMETER computername
The computer, or names, to query. Default: dc2k22
.EXAMPLE
Get-DiskInventory -ComputerName sql2k16 -DriveType 3
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,HelpMessage="Enter a computer name to query")]
    [Alias('hostname')]
    [string]$ComputerName,
    [ValidateSet(2,3)]
    [int]$DriveType = 3
)
Write-Verbose "Connecting to $computername"
Write-Verbose "Looking for drive type $drivetype" 
Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $computername -Filter "drivetype=$drivetype" |
Sort-Object -Property DeviceID |
Select-Object -Property DeviceID,
    @{name='FreeSpace(MB)';e={$_.FreeSpace / 1MB -as [int]}},
    @{name='Size(GB)';e={$_.Size / 1GB -as [int]}},
    @{name='%Free';e={$_.FreeSpace / $_.Size * 100 -as [int]}}
Write-Verbose "Finished running the script"