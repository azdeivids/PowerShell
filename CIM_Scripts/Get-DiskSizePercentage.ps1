<#
.SYNOPSIS
Get drives based on percentage free space.
.DESCRIPTION
This script will get all drives that have less percentage free space than the speciefied value in the
variable.
.PARAMETER computername
The name of the computer/s to run the query against.
.PARAMETER drivetype 
The type of drive to retrieve.
.PARAMETER freespacepercentage
Minimum treshold. The default value is 10; you should enter any value between 1 and 100
.EXAMPLE
Get-DiskSizePercentage -minimum 20
Find all disk with less than 20 percent free space
Get-DiskSizePersentage -ComputerName sql2k16 -Minimum 30
Find all disk with less than 30 percent free space on sql2k16 device.
#>
param (
    $computername = 'dc2k22',
    $drivetype = 3,
    $freespacepercentage = 10
)
$minpercent = $freespacepercentage / 100
Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $computername -Filter "drivetype=$drivetype" |
Where-Object { ($_.FreeSpace / $_.Size) -lt $minpercent } | Select-Object -Property DeviceID,FreeSpace,Size