# Import the Active Directory module
Import-Module ActiveDirectory

# Calculate the date six months ago from the current date
$LastLogonTime = (Get-Date).AddMonths(-6)

# Get all computer objects from Active Directory that haven't logged in since six months ago
$InactiveComputers = Get-ADComputer -Filter {LastLogonTimeStamp -lt $LastLogonTime} -Properties LastLogonTimeStamp

# Loop through each inactive computer and delete it
foreach ($computer in $InactiveComputers) {
    # Display the name of the computer being deleted
    Write-Host "Deleting computer: $($computer.Name)"

    # Uncomment the following line to actually delete the computer
    Remove-ADComputer -Identity $computer -Confirm:$false
}