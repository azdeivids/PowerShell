<#  This script will check if the syncro services are running and if not act accordingly to either kill or start the service.   #>

$SyncroServices = Get-Service -Name "Syncro*"

if ($SyncroServices.StartType -eq "Automatic") {
    Write-Host -ForegroundColor Cyan "Syncro Services are running!"
    $SyncroServices | ForEach-Object {
        Stop-Service -InputObject $_
        Set-Service -InputObject $_ -StartupType Disabled
        Write-Host -ForegroundColor DarkMagenta "Syncro Services Killed!"
    }
} else {
    Write-Host -ForegroundColor Cyan "Syncro Services are dead!"
    $SyncroServices | ForEach-Object {
        Set-Service -InputObject $_ -StartupType Automatic
        Start-Service -InputObject $_
        Write-Host -ForegroundColor DarkGreen "Syncro Services Started!"
    }
}