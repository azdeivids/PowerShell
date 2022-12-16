# generate random minustes
$random = Get-Random -Minimum 1 -Maximum 5
# invoke gpupdate /force on target OU
Get-AdComputer -SearchBase "OU=Staff,OU=Desktops,OU-Workstations,DC=msdeivids,DC=local" -Filter * | ForEach-Object -Proces {
    Invoke-GPUpdate -Computer $_.Name -RandomDelayInMinutes $random -Force
}