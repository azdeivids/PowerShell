$date = Get-Date;
Get-ADComputer -filter * -Properties LastLogonDate,Name,Description,Created|
Where-Object {$_.LastLogonDate -lt $date.AddDays(-30)}|
Where-Object {$_.Created -lt $date.AddDays(-30)}| 
Select Name,DistinguishedName,Created,LastLogonDate,Description,DNSHostName,Enabled|
export-csv staleComputers.csv