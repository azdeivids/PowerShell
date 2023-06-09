$domainName = Read-Host "Provide custom domain name."
$TargetGroup = Read-Host "Provide group of users to replace the UPN sufix with custom domain name."
$users = Get-ADGroupMember -Identity $TargetGroup -Recursive | Where-Object {$_.objectClass -eq 'user'}

foreach ($user in $users) {
    $user = Get-ADUser -Identity $User.SamAccountName
    $userName = $user.UserPrincipalName.Split('@')[0] 
    $upn = $userName + "@" + $domainName 
    $user | Set-ADUser -UserPrincipalName $upn
}