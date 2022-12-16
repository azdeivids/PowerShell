# find specific computer in AD
Get-AdComputer -Identity deivids-laptop -properties *
# find computers in specific OU
Get-AdComputer -Filter * -SearchBase "OU=Laptops,OU=Staff,OU=Workstations,OU=msdeivids,OU=msdeivids,OU=local" | ft
# find win 10 computers
Get-AdComputer -Filter "OperatingSystem -eq 'Windows 10*' -or OperatingSystem 'Windows 11*'" | ft
# find all inactive computers 
$date = (Get-Date) - (New-TimeSpan -Days 90)
Get-AdComputer -Filter 'lastLogonTime -lt $date' -properties canonicalName, lastLogonDate | select name,canonicalName,lastlogondate | Ft -AutoSize