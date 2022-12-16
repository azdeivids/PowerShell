# get ad user and view propeties
Get-AdUser -Filter "givenName -eq 'deivids'" -Properties *
# get ad user from an OU
Get-AdUser -Filter * -SearchBase 'OU=Staff,OU=Users,OU=msdeivids,DC=domian,DC=local' -SearchScope 1
# uset the like operator
Get-ADUser -Filter "name -like '*dei*'"
# find users based on bad login accounts 
Get-AdUser -Filter "badpwcount -ge 3"
# find users with no email address field
Get-AdUser -Filter "Email -notlike '*'" | Format-Table
# FOR REVIEW * Get-ADUser -Filter "email -notlike '*'" | Set-AdUser -Email '@deividsegle.com'"

# get user and reset password 
$pass = ConvertTo-SecureString "password1" -AsPlainText -Force 
Set-AdAccountPassword -Identity deivids -NewPassword $pass -Reset
Set-AdUser -Identity deivids -ChangePasswordAtLogon $true

# get users that haven't login the past 90 days
$date = (Get-Date) - (New-TimeSpan -Days 90)
Get-ADUser -Filter 'lastLogon -lt $date' | Format-Table