# get AD group
Get-AdGroup -Identity Managers
Get-AdGroup -Identity Managers -Properties *
Get-AdGroup -Filter "Name -like 'Sec_*'" | ft
# get AD group members
Get-AdGroupMember -Identity "Sec_Managers" | ft
# add user to group
Add-ADGroupMember -Identity "Sec_Managers" -Members deivids,deivids,deivids