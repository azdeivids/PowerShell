# Define the target OU distinguished name
$ouDistinguishedName = " provide the path here " 
# Get a list of all users in the specified OU
$users = Get-ADUser -Filter * -SearchBase $ouDistinguishedName

# Loop through each user and reset their password to "Wexam123!"
foreach ($user in $users) {
    # Set the new password
    $newPassword = ConvertTo-SecureString "n3w_pa55w0rd!" -AsPlainText -Force

    # Reset the user's password
    Set-ADAccountPassword -Identity $user -NewPassword $newPassword -Reset

    # Enable the user account (in case it's disabled)
    Enable-ADAccount -Identity $user

    # Output the user's name and the fact that their password has been reset
    Write-Host "Reset password for $($user.Name)."
}
