$usergroups = Get-AdUser -Identity deivids -Properties memberof | Select-Object -ExpandProperty memberof
$usergroups | Add-AzADGroupMember -Members newuser -Verbose
Get-AdUser -Identity newuser -Properties memberof | Select-Object -ExpandProperty memberof

# create log file when adding users to groups

$logfile = "C:\log\newuser.log"
$userSource = "deivids"
$userTarget = "newuser"
$time = Get-Date
Add-Content $logfile -Value $time -Encoding utf8
Add-Content $logfile -Value "_____________"
Add-Content $logfile -Value "Copy groups from $userSource to $userTarget" -Encoding utf8
$sourceGroups = (Get-ADPrincipalGroupMembership -Identity $userSource).samAccountName
foreach ($group in $sourceGroups) {
    Add-Content $logfile -Value "Adding $userTarget to $group" -Encoding utf8
    try {
        $log = Add-ADPrincipalGroupMembership -Identity $userTarget -MemberOf $group Add-Content $logfile -value $log -Encoding utf8
    }
    catch {
        Add-Content $logfile $($Error[0].Exception.Message) -Encoding utf8
        Continue
    }
}
Add-Content $logfile -Value "_____________"