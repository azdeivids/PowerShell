# Import the Active Directory module
Import-Module ActiveDirectory

# Path to the CSV file containing the list of inactive user accounts (update the path accordingly)
$CSVFilePath = "C:\InactiveUsers.csv"

# Read the CSV file and get the list of user accounts to be removed
$UsersToRemove = Import-Csv -Path $CSVFilePath

# Loop through each user in the CSV and remove them from Active Directory
foreach ($user in $UsersToRemove) {
    $SamAccountName = $user.SamAccountName

    # Check if the user account exists in Active Directory
    $existingUser = Get-ADUser -Filter {SamAccountName -eq $SamAccountName}

    if ($existingUser) {
        # Display the name of the user being removed
        Write-Host "Removing user: $SamAccountName"

        # Uncomment the following line to actually remove the user account
        Remove-ADUser -Identity $SamAccountName -Confirm:$false
    } else {
        Write-Host "User $SamAccountName not found in Active Directory."
    }
}