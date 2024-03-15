Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module Microsoft.Graph -Scope CurrentUser -Confirm:$false
Install-Script -Name Get-WindowsAutopilotInfo -Confirm:$false
Get-WindowsAutopilotInfo -Online -TenantId "4fb1974c-7293-4ad4-9cc9-5bc656e75408" -AppId "56a83133-c833-4859-9b23-039a0d98b3aa" -AppSecret "6vw8Q~xccM1GN4kJoEgtk.typOCAORszG3nh0agj" -AddToGroup "intune_autopilot_device_enrollment_Security"