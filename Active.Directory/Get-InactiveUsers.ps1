# Import the Active Directory module
Import-Module ActiveDirectory

# Get all user objects from Active Directory that haven't logged in since 12 months ago
$LastLogonTime = (Get-Date).AddMonths(-12)
$InactiveUsers = Get-ADUser -Filter {LastLogonDate -lt $LastLogonTime} -Properties SamAccountName, LastLogonDate

# Create a new CSV file with the list of inactive users
$CSVFilePath = "C:\InactiveUsers.csv"
$InactiveUsers | Select-Object SamAccountName, LastLogonDate | Export-Csv -Path $CSVFilePath -NoTypeInformation