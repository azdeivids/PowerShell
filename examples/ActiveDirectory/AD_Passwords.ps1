#  Reset user password in specific OU 
Get-ADUser -Filter * -SearchScope Subtree -SearchBase "OU=Managers,OU=Staff,OU=Users,DC=msdeivids,DC=local" | `
Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "P@55worD!" -Force)

# change user password properties
Get-ADUser -Filter * -SearchBase "OU=USERS_TEST,DC=lab,DC=intra" | Set-ADUser -PasswordNeverExpires $True
Get-ADUser -Filter * -SearchBase "OU=USERS_TEST,DC=lab,DC=intra" | Set-ADUser -CannotChangePassword $False
Get-ADUser -Filter * -SearchBase "OU=USERS_TEST,DC=lab,DC=intra" | Set-ADUser -ChangePasswordAtLogon $True