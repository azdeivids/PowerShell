$ADUsers = Import-Csv C:\scripts\users.txt

foreach ($user in $ADUsers)
{
    # csv file columns
    $Username = $user.username
    $Password = $user.password
    $Firstname = $user.firstname
    $Lastname = $user.lastname
    $Department = $user.department
    $OU = $user.ou

    if (Get-ADUser -F {samAccountName -eq $Username})
    {
        Write-Warning "User account $username already exisits in AD."
    }
    else {
        New-ADUser `
        -SamAccountName $Username `
        -UserPrincipalName "$username@deividsegle.com" `
        -Mail "$username@deividsegle.com"
        -Name "$firstname $lastname" `
        -GivenName $Firstname `
        -Surname $Lastname `
        -Enabled $true `
        -ChangePasswordAtLogon $true `
        -DisplayName "$lastname, $firstname" `
        -Department $Department `
        -Path $OU `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force)

        Write-Host "User account $username is created." -ForegroundColor Magenta
    }
}

Read-Host -Prompt "Press enter to exit"
