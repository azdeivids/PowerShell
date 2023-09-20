# Import the Active Directory module
Import-Module ActiveDirectory

# Path to the CSV file containing user names (update the path accordingly)
$csvFilePath = "C:\temp\user_list.csv"

# Specify the new password that you want to set for all users
$newPassword = "n3w_pa55w0rd!"

# Check if the CSV file exists
if (Test-Path $csvFilePath) {
    # Import the CSV file
    $userNames = Import-Csv $csvFilePath

    # Loop through each user in the CSV and reset their password
    foreach ($user in $userNames) {
        $userName = $user.Name
        
        # Check if the user exists in Active Directory
        if (Get-AdUser -Filter {SamAccountName -eq $userName}) {
            # Reset the user's password
            Set-AdAccountPassword -Identity $userName -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) -Reset

            # Enable the user account (in case it's disabled)
            Enable-AdAccount -Identity $userName

            Write-Host "Password reset for user: $userName"
        }
        else {
            Write-Host "User not found in Active Directory: $userName"
        }
    }
}
else {
    Write-Host "CSV file not found: $csvFilePath"
}