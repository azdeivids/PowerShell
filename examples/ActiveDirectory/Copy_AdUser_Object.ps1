$template_acc = Get-AdUser -Identity deivids -Properties *
$template_acc.UserPrincipalName = $null

New-AdUser -Instance $template_acc `
-Name 'New User' `
-SamAccountName "nuser@deividsegle.com" `
-AccountPassword (Read-Host -AsSecureString "Input user password") `
-Mail "nuser@deividsegle.com" `
-Enabled $true `
-ChangePasswordAtLogon $true