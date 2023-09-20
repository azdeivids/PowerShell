# Import the Active Directory module
Import-Module ActiveDirectory

# Calculate the date six months ago from the current date
$LastLogonTime = (Get-Date).AddMonths(-6)

# Get all computer objects from Active Directory that haven't logged in since six months ago
$InactiveComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $LastLogonTime} -Properties LastLogonTimeStamp

# Display the results
$InactiveComputers | Select-Object Name, LastLogonTimeStamp | Sort-Object LastLogonTimeStamp
$InactiveComputers | Select-Object Name, LastLogonTimeStamp | Sort-Object LastLogonTimeStamp | Export-Csv -Path "C:\InactiveComputers.csv" -NoTypeInformation