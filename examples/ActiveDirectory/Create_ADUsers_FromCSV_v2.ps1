$ADUsers = Import-Csv -Path C:\scripts\users.csv

$ADUsers | ForEach-Object {
    New-AdUser `
    -Name $($_.FirstName + " " + $_.LastName) `
    -GivenName $_.FirstName `
    -Surname $_.LastName `
    -Department $_.Department `
    -DisplayName $($_.Fitstname + " " + $_.LastName) `
    -UserPrincipalName $_.UserPrincipalName `
    -SamAccountName $_.SamAccountName `
    -AccountPassword $(ConvertTo-SecureString $_.Password -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true 
}