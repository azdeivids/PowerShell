#######################################################################################################
#
# 		Privacy Tweaks
#
#######################################################################################################



# Disable Telemetry
# Note: This tweak also disables the possibility to join Windows Insider Program and breaks Microsoft Intune enrollment/deployment, as these feaures require Telemetry data.
# Windows Update control panel may show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again.
# See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57 and https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/92
Function DisableTelemetry {
	Write-Output "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	# Office 2016 / 2019
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name Enablelogging -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name EnableUpload -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name Enablelogging -Type DWord -Value 0 -Force
	New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name EnableUpload -Type DWord -Value 0 -Force
}

# Enable Telemetry
Function EnableTelemetry {
	Write-Output "Enabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	# Office 2016 / 2019
	Enable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name Enablelogging -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\osm" -Name EnableUpload -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name Enablelogging -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\osm" -Name EnableUpload -ErrorAction SilentlyContinue
}

# Disable Cortana
Function DisableCortana {
	Write-Output "Disabling Cortana..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
	Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage
}

# Enable Cortana
Function EnableCortana {
	Write-Output "Enabling Cortana..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
}

# Enable Wi-Fi Sense
Function EnableWiFiSense {
	Write-Output "Enabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Enable Web Search in Start Menu
Function EnableWebSearch {
	Write-Output "Enabling Bing Search in Start Menu..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Output "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
	Write-Output "Enabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -ErrorAction SilentlyContinue
}

# Disable Activity History feed in Task View
# Note: The checkbox "Store my activity history on this device" ("Let Windows collect my activities from this PC" on older versions) remains checked even when the function is disabled
Function DisableActivityHistory {
	Write-Output "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

# Enable Activity History feed in Task View
Function EnableActivityHistory {
	Write-Output "Enabling Activity History..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue
}

# Disable sensor features (Screen rotation)
Function DisableSensors {
	Write-Output "Disabling sensors..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
}

# Enable sensor features (Screen rotation)
Function EnableSensors {
	Write-Output "Enabling sensors..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -ErrorAction SilentlyContinue
}

# Disable location feature and scripting for the location feature
Function DisableLocation {
	Write-Output "Disabling location services..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
}

# Enable location feature and scripting for the location feature
Function EnableLocation {
	Write-Output "Enabling location services..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -ErrorAction SilentlyContinue
}

# Disable Feedback
Function DisableFeedback {
	Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Enable Feedback
Function EnableFeedback {
	Write-Output "Enabling Feedback..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Tailored Experiences
Function DisableTailoredExperiences {
	Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

	" Tailored experience disabled `n" >> "windows_configuration.log"
}

# Enable Tailored Experiences
Function EnableTailoredExperiences {
	Write-Output "Enabling Tailored Experiences..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue

	" Tailored experience enabled `n" >> "windows_configuration.log"
}

# Disable Advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

	" Advertising ID disabled `n" >> "windows_configuration.log"
}

# Enable Advertising ID
Function EnableAdvertisingID {
	Write-Output "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue

	" Advertising ID enbaled `n" >> "windows_configuration.log"
}

# Disable setting 'Let websites provide locally relevant content by accessing my language list'
Function DisableWebLangList {
	Write-Output "Disabling Website Access to Language List..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1

	" Relevant website content disabled `n" >> "windows_configuration.log"
}

# Enable setting 'Let websites provide locally relevant content by accessing my language list'
Function EnableWebLangList {
	Write-Output "Enabling Website Access to Language List..."
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -ErrorAction SilentlyContinue

	" Relevant website content enabled `n" >> "windows_configuration.log"
}

# Disable access to camera
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.
Function DisableCamera {
	Write-Output "Disabling access to camera..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2

	" Camer access disabled `n" >> "windows_configuration.log"
}

# Enable access to camera
Function EnableCamera {
	Write-Output "Enabling access to camera..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue

	" Camer access enabled `n" >> "windows_configuration.log"
}

# Disable access to microphone
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.
Function DisableMicrophone {
	Write-Output "Disabling access to microphone..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2

	" Microphone access disabled `n" >> "windows_configuration.log"
}

# Enable access to microphone
Function EnableMicrophone {
	Write-Output "Enabling access to microphone..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue

	" Microphone access enabled `n" >> "windows_configuration.log"
}

# Disable Error reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	" Error reporting disabled `n" >> "windows_configuration.log"
}

# Enable Error reporting
Function EnableErrorReporting {
	Write-Output "Enabling Error reporting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	" Error reporting enabled `n" >> "windows_configuration.log"
}

# Stop and disable Connected User Experiences and Telemetry (Diagnostics Tracking Service)
Function DisableDiagTrack {
	Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled

	" User experience and telemetry disabled (Diagnostic tracking) `n" >> "windows_configuration.log"
}

# Enable and start Connected User Experiences and Telemetry (Diagnostics Tracking Service)
Function EnableDiagTrack {
	Write-Output "Enabling and starting Connected User Experiences and Telemetry Service ..."
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue

	" User experience and telemetry disabled (Diagnostic tracking) `n" >> "windows_configuration.log"
}

# Enable clearing of recent files on exit
# Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.
Function EnableClearRecentFiles {
	Write-Output "Enabling clearing of recent files on exit..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1

	" Enabled 'Clear recent files (At logout)' `n" >> "windows_configuration.log"
}

# Disable clearing of recent files on exit
Function DisableClearRecentFiles {
	Write-Output "Disabling clearing of recent files on exit..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue

	" Disabled 'Clear recent files (At logout)' `n" >> "windows_configuration.log"
}

# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.
# There are also user specific keys
Function DisableRecentFiles {
	Write-Output "Disabling recent files lists..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1

	" Disabled recent files (start menu) `n" >> "windows_configuration.log"
}

# Enable recent files lists
Function EnableRecentFiles {
	Write-Output "Enabling recent files lists..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue

	" Enabled recent files (start menu) `n" >> "windows_configuration.log"
}

##################################################################################################################
############################################ Windows 11 22H2 Tweaks ##############################################

# Disable Windows Safe Search (Bing)
Function SafeSearchDisabled {
	Write-Output "Disabling SafeSearch..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -Type DWord -Value 3

	" SafeSearch disabled `n" >> "windows_configuration.log"
}

# Moderate Windows Safe Search (Bing)
Function SafeSearchModerate {
	Write-Output "Setting SafeSearch to moderate..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -Type DWord -Value 2

	" SafeSearch set to moderate `n" >> "windows_configuration.log"
}

# Strict Windows Safe Search
Function SafeSearchStrict {
	Write-Output "Setting SafeSearch to strict..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchSafeSearch" -Type DWord -Value 1

	" SafeSearch disabled `n" >> "windows_configuration.log"
}

# Device Search History
Function DeviceLocalSearchDisabled {
	Write-Output "Disabling device local search history storage..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0

	" Local search history storage disabled `n" >> "windows_configuration.log"
}

# Device Search History
Function DeviceLocalSearchEnabled {
	Write-Output "Enabling device local search history storage..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 1

	" Local search history storage enabled `n" >> "windows_configuration.log"
}

# Disable Online Speech Recognition
Function DisableOnlineSpeechRecognition {
	Write-Output "Disabling Online speech recognition..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechLogging")) {
		New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Setting\OnlineSpeechLogging"
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechLogging" -Name "LoggingAllowed" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -ErrorAction SilentlyContinue

	" Online speech recognition disabled `n" >> "windows_configuration.log"
}

# Enable Online Speech Recognition
Function EnableOnlineSpeechRecognition {
	Write-Output "Enabling Online speech recognition..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
	}
	If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechLogging")) {
		New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechLogging" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechLogging" -Name "LoggingAllowed" -Type DWord -Value 1

	" Online speech recognition enabled `n" >> "windows_configuration.log"
}

# Turn on Inking and Typing
# The HKLM Key 'AllowLinguisticDataCollection' will disbale the setting entierly for all users; it's part of Disable/Enable Telemetry function already.
Function EnableTIPC {
	Write-Output "Turning on Inking and Typing..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Input\TIPC")) {
		New-Item -Path "HKCU:\Software\Microsoft\Input\TIPC" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 1

	" Inking and Typing disabled `n" >> "windows_configuration.log"
}

# Turn off Inking and Typing
Function DisableTIPC {
	Write-Output "Turning off Inking and Typing..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -ErrorAction SilentlyContinue

	" Inking and Typing disabled `n" >> "windows_configuration.log"
}

# Turn on cloud content search for current user
Function TurnOnMSASearch {
	Write-Output "Turning on cloud content search for current MS Account..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsMSACloudSearchEnabled" -Type DWord -Value 1

	" MS Account sarch tuned on `n" >> "windows_configuration.log"
}

# Turn off cloud contet seach for current user
Function TurnOffMSASearch {
	Write-Output "Turning off cloud contetn seach for current MS Account..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsMSACloudSearchEnabled" -ErrorAction SilentlyContinue

	" MS Account search tuner off `n" >> "windows_configuration.log"
}

# Turn on cloud content search for AAD work account
Function TurnOnAADSearch {
	Write-Output "Turning on cloud content search for current AD Account..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsAADCloudSearchEnabled" -Type DWord -Value 1

	" AAD Work account seach turned on `n" >> "windows_configuration.log"
}

# Turn off cloud contet seach for AAD work account
Function TurnOffAADSearch {
	Write-Output "Turning off cloud contetn seach for current AD Account..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsAADCloudSearchEnabled" -ErrorAction SilentlyContinue

	" AAD Work account search turned off `n" >> "windows_configuration.log"
}

# Disable cloud content search entierly
Function DisableCloudContentSearch {
	Write-Output "Cloud content search being disabled..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0

	" Cloud content search disabled `n" >> "windows_configuration.log"
}

# Let user configure cloud content search
Function UserCloudContentSearch {
	Write-Output "Cloud content search left to user choice..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -ErrorAction SilentlyContinue

	" Cloud contetnt search set to default `n" >> "windows_configuration.log"
}

# Turn off Search Highlight
Function TurnOffSearchHighlights {
	Write-Output "Turning off search highlights..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -ErrorAction SilentlyContinue

	" Search highlights turned off `n" >> "windows_configuration.log"
}

# Turn on Seach Highlights
Function TurnOnSearchHighlights {
	Write-Output "Turning on search highlights..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 1

	" Searcg highlights turned on `n" >> "windows_configuration.log"
}

# Enable Search Highlight
Function EnableSearchHighlights {
	Write-Output "Enabling search highlights..."
	Remove-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -ErrorAction SilentlyContinue

	" Search highlights enbaled `n" >> "windows_configuration.log"
}

# Disable Seach Highlights
Function DisableSearchHighlights {
	Write-Output "Turning on search highlights..."
	If (!(Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Type DWord -Value 0

	" Search highlights disabled `n" >> "windows_configuration.log"
}

# Disable Windows 11 Ads
Function DisableAdsWin11 {
	Write-Output "Disabling Windows 11 Ads..."
	If (!(Test-Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\CloudContent" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1

	" File exploter ads disabled `n" >> "windows_configuration.log"
	" Lock screen tips and tricks removed `n" >> "windows_configuration.log"
	" Soft landing disabled `n" >> "windows_configuration.log"
}

# Enable Windows 11 Ads
Function EnableAdsWin11 {
	Write-Output "Enabling Windows 11 Ads..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\CloudContent" -Name "DisableSoftLanding" -ErrorAction SilentlyContinue

	" File explorer ads enabled `n" >> "windows_configuration.log"
	" Lock screen tips and tricks enabled `n" >> "windows_configuration.log"
}

# Disable let app communicate with Unpaired devices
Function DisablePairingWithApps {
	Write-Output "Disable app communication with unpaired devices..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {
		New-item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2

	" App pairing disabled `n" >> "windows_configuration.log"
}

# Enable let app communicate with unpaired devices
Function EnablePairingWithApps {
	Write-Output "Enable app communication with unpaired devices..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {
		New-item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -ErrorAction SilentlyContinue

	" App pairing disabled `n" >> "windows_configuration.log"
}

# Disable Diagnostic Data
Function DisableDiagData {
	Write-Output "Disabling diagnostic data..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableDiagnosticDataViewer" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Name "EnableEventTranscript" -Type DWord -Value 0

	" Diagnostic data disabled `n" >> "windows_configuration.log"
}

# Enable diagnostic data
Function EnableDiagData {
	Write-Output "Enabling diagnostic data..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableDiagnosticDataViewer" -ErrorAction SilentlyContinue

	" Diagnostic data enabled `n" >> "windows_configuration.log"
}

# Disable Wireless Application Protocol (WAP)
# Push message Routing Service. This service helps to collect and send user data to Microsoft.
Function DisableWAP {
	Write-Output "Disablin Wireless Application Protocol (WAP) used for telemetry..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled

	" WAP Service has been disabled `n" >> "windows_configuration.log"
}

# Enable Wireless Application Protocol (WAP)
Function EnableWAP {
	Write-Output "Disablin Wireless Application Protocol (WAP) used for telemetry..."
	Set-Service "dmwappushservice" -StartupType Automatic

	" WAP Service has been enabled `n" >> "windows_configuration.log"
}


#######################################################################################################
#
# 		Web Browser Tweaks
#
#######################################################################################################



# Enable Start Up boost (All Users)
Function EnableEdgeStartUpBoost {
    Write-Output "Enabling MS Edge startup boost..."
    If(!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Type DWord -Value 1

    " Enabled MS Edge startup boost for all users `n" >> "windows_configuration.log"
}

# Disable Start Up boost 
Function DisableEdgeStarUpBoost {
    Write-Output "Disabling MS Edge startup boost..."
    If(!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Type DWord -Value 0
    
    " Disabled MS Edge starup boost for all users `n" >> "windows_configuration.log"
}

# Default User choice for starup boost
function DefaultEdgeStartUpBoost {
    Write-Output "Leaving MS Edge startup boost to user choice..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -ErrorAction SilentlyContinue

    " MS Edge Start up boos user choice `n" >> "windows_configuration.log"    
}

# Turn off Sleeping tabs in MS Edge
Function EnableTabSleep {
    Write-Output "Enabling sleeping tabs in MS Edge..."
    IF (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SleepingTabsEnabled" -Type DWord -Value 1

    " MS Edge Sleeping tabs turned on `n" >> "windows_configuration.log"
}

# Default user choice for sleeping tabs
Function DefaultTabSleep {
    Write-Output "Leaving MS Edge sleeping tabs to user choice..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SleepingTabsEnabled" -ErrorAction SilentlyContinue

    " MS Edge sleeping tabs left to user choice `n" >> "windows_configuration.log"
}

# Put tabs to sleep after 15 minutes
Function EdgeTabSleepTimeout15 {
    Write-Output "Setting edge tab inactivity timoute to 15 min..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SleepingTabsTimeout" -Type DWord 384

    " MS Edge tabs sleep (15 min) `n" >> "windows_configuration.log"
}

# Leave tab timeout to user choice
Function EdgeTabSleepTimeoutDefualt {
    Write-Output "Leaving MS edge tab sleep timeout to user choice..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SleepingTabsTimeout" -ErrorAction SilentlyContinue

    " MS Edge tab sleep left to user choice `n" >> "windows_configuration.log"
}

# Turn on Efficency mode in MS Edge
Function EnableEdgeEfficiencyMode {
    Write-Output "Enabling MS Edge Efficiency mode..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EfficiencyMode" -Type DWord -Value 0

    " MS Edge efficiency mode enabled `n" >> "windows_configuration.log"
}

# Default Efficiency mode
Function DefaultEdgeEfficiencyMode {
    Write-Output "Leaving MS Edge efficiency mode to default..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EfficiencyMode" -ErrorAction SilentlyContinue

    " MS Edge Efficiency mode left to default `n" >> "windows_configuration.log"
}

# Add sites to excluded sleeping tabs
Function EdgeExcludeSitesFromSleep {
    Write-Output "Excluding portal.azure.com from tab inactivity policy..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls" -Name 1 -Type String -Value "https://portal.azure.com/"

    " Added portal.azure.com to exlude from tab sleep `n" >> "windows_configuration.log"
}

# Remove sites to exclude sleeping tabs
Function EdgeRemoveExcludedSitesFromSleep {
    Write-Output "Remove sites from exluded sleeping tab list."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls" -ErrorAction SilentlyContinue

    " Removed sites from excluded sleeping tab list `n" >> "windows_configuration.log"
}

# Ask Before Closing multiple tabs on exit in MS Edge
Function EnableAskBeforeCloseEdge {
    Write-Output "Setting 'Ask before closing tabs' in MS Edge..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AskBeforeCloseEnabled" -Type DWord -Value 1

    " MS Edge 'Ask before close' tabs enabled `n" >> "windows_configuration.log"
}

# Do not ask before closing multiple tabs in MS Edge
Function DefaultAskBeforeCloseEdge {
    Write-Output "Default behavior when closing multiple MS Edge tabs..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AskBeforeCloseEnabled" -ErrorAction SilentlyContinue

    " MS Edge 'Ask before close' default choice `n" >> "windows_configuration.log"
}

######################################### Google Chrome Tweaks ############################################

# Disable google reporter tool
# This scans user system for malicious files and removes them 
# This will disable the software_reporter_tool.exe with registry and shouldn't be re-enabled with google update
Function DisableGoogleSoftwareTool {
	Write-Output "Disabling google software_reporter_tool.exe used for scanning harmful software..."
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupEnabled -Type String -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupReportingEnabled -Type String -Value 0 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name MetricsReportingEnabled -Type String -Value 0 -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name "Debugger" -Type String -Value %windir%\System32\taskkill.exe -Force

	" Google software_reporter_tool.exe disabled `n" >> "windows_configuration.log"
}

# Enable google reporter tool
Function EnableGoogleSoftwareTool {
	Write-Output "Enbaling google software_reporter_tool.exe used for scanning harmful software..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupEnabled -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name ChromeCleanupReportingEnabled -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name MetricsReportingEnabled -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name "Debugger" -ErrorAction SilentlyContinue

	" Goolge software_reporter_tool.exe enbaled `n" >> "windows_configuration.log"
}

# Disable Firefox telemetry
Function DisableFirefoxTelemetry {
	Write-Output "Disabling Firefox default-browser-agent.exe from sending user telemetry..."
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableTelemetry -Type DWord -Value 1 -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableDefaultBrowserAgent -Type DWord -Value 1 -Force

	" Firefox default-browser-agent.exe disabled `n" >> "windows_configuration.log"
}

# Enable Firefox telemetry 
Function EnableFirefoxTelemetry {
	Write-Output "Enabling Firefox defualt-browser-agent.exe tool..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableTelemetry -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name DisableDefaultBrowserAgent -ErrorAction SilentlyContinue

	" Firefox default-browser-agent.exe enbaled `n" >> "windows_configuration.log"
}



#######################################################################################################
#
# 		Security Tweaks
#
#######################################################################################################



# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
	Write-Output "Enabling sharing mapped drives between users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

	" Enabled mapped drive sharing `n" >> "windows_configuration.log"
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue

	" Disabled mapped drive sharing `n" >> "windows_configuration.log"
}

# Disable implicit administrative shares
Function DisableAdminShares {
	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0

	" Enabled administrative shares `n" >> "windows_configuration.log"
}

# Enable implicit administrative shares
Function EnableAdminShares {
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue

	" Disabled administrative shares `n" >> "windows_configuration.log"
}

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security.
# Warning: This may cause old applications and drivers to crash or even cause BSOD
# https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity
Function EnableCIMemoryIntegrity {
	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1

	" Enabled CIM memory (Windows Defender) `n" >> "windows_configuration.log"
}

# Disable Core Isolation Memory Integrity - Applicable since 1803
Function DisableCIMemoryIntegrity {
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue

	" Disabled CIM memory `n" >> "windows_configuration.log"
}

# Hide Account Protection warning in Defender about not using a Microsoft account
Function HideAccountProtectionWarn {
	Write-Output "Hiding Account Protection warning..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
	}
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1

	" Account protection warning disabled `n" >> "windows_configuration.log"
}

# Show Account Protection warning in Defender
Function ShowAccountProtectionWarn {
	Write-Output "Showing Account Protection warning..."
	Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue

	" Account protection warning enabled `n" >> "windows_configuration.log"
}

# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0

	" Windows Scripting host (wscript) disabled `n" >> "windows_configuration.log"
}

# Enable Windows Script Host
Function EnableScriptHost {
	Write-Output "Enabling Windows Script Host..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue

	" Windows scripting host (wscript) enabled `n" >> "windows_configuration.log"
}

# Enable F8 boot menu options
Function EnableF8BootMenu {
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null

	" F8 boot menu enbaled `n" >> "windows_configuration.log"
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set `{current`} BootMenuPolicy Standard | Out-Null

	" F8 boot menu disabled `n" >> "windows_configuration.log"
}

# Disable System Recovery and Factory reset
# Warning: This tweak completely removes the option to enter the system recovery during boot and the possibility to perform a factory reset
Function DisableRecoveryAndReset {
	Write-Output "Disabling System Recovery and Factory reset..."
	reagentc /disable 2>&1 | Out-Null

	" System recovery and reset disbaled `n" >> "windows_configuration.log"
}

# Enable System Recovery and Factory reset
Function EnableRecoveryAndReset {
	Write-Output "Enabling System Recovery and Factory reset..."
	reagentc /enable 2>&1 | Out-Null

	" System recovery and reset enabled `n" >> "windows_configuration.log"
}

###############################################################################################################
###################################### Windows 11 22H2 Tweaks #################################################

# Turn off Smart App Control (SAC)
# NOTE: If you disabled Smart App control, you will have to preform a clean install of Windows 11 to re-enable the settings.
# If you choose to leave the setting untouched it will default to evaluation mode which will decided wether to enable or disable SAC
Function DisableSAC {
	Write-Output "Turning off Smart App Control..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -Type DWord -Value 0

	" SAC Disbaled `n" >> "windows_configuration.log"
}

# Enable Smart App Control (SAC)
Function EnableSAC {
	Write-Output "Turning on Smart App Control..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -Type DWord -Value 1

	" SAC Enabled `n" >> "windows_configuration.log"
}

# Enable Local Security Authority (LSA)
Function EnableLSA {
	Write-Output "Enabling Local Security Authority..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Type DWord -Value 2

	" LSA Enabled `n" >> "windows_configuration.log"
}

# Disable Local Security Authority (LSA)
Function DisableLSA {
	Write-Output "Disabling Local Security Authority..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Type DWord -Value 0

	" LSA Disabled `n" >> "windows_configuration.log"
}

# Enable Local Security Authority (LSA) iwth UEFI Lock for additional security
Function EnableLSAWithUEFI {
	Write-Output "Disabling Local Security Authority..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 1

	" LSA Enabled with UEFI Lock `n" >> "windows_configuration.log"
}

# Turn on Controlled Folder Access
Function EnableControlledFolderAccess {
	Write-Output "Enabling controlled folder access..."
	Set-MpPreference -EnableControlledFolderAccess Enable

	" Controller Folder Access enabled `n" >> "windows_configuration.log"
}

# Turn off Controlled Folder Access
Function DisableControlledFolderAccess {
	Write-Output "Disabling controlled folder access..."
	Set-MpPreference -EnableControlledFolderAccess Disable

	" Controlled Folder Access disabled `n" >> "windows_configuration.log"
}
# Turn on real-time protection for MS defender
Function TurnOnRealTimeProtection {
	Write-Output "Turning on real time protection..."
	Set-MpPreference -DisableRealtimeMonitoring $false

	" Real-time monitoring enabled `n" >> "windows_configuration.log"
}

# Turn of real-time protection for MS defender
Function TurnOffRealTimeProtection {
	Write-Output "Real-time protection is being disabled..."
	Set-MpPreference -DisableRealtimeMonitoring $true

	" Real-time monitoring disabled `n" >> "windows_configuration.log"
}

# Enable tamper protection
Function EnableTamperProtection {
	Write-Output "Enabling tamper protection..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "EnableTamperProtection" -Type DWord -Value 5

	" Tamer protection enabled `n" >> "windows_configuration.log"
}

# Disable tamper protection
Function DisableTamperProtection {
	Write-Output "Disabling tamper protection..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "EnableTamperProtection" -Type DWord -Value 0

	" Tamer protection disabled `n" >> "windows_configuration.log"
}

# Enable SmartScreen Filter for MS Store apps
Function EnableStoreAppSmartScreen {
	Write-Output "Enabling smart screen protection for MS store apps..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -Type DWord -Value 0

	" Smart screen for MS store apps enabled `n" >> "windows_configuration.log"
}

# Disable SmartScreen Filter for MS Store apps
Function DisableStoreAppSmartScreen {
	Write-Output "Disabling smart screen protection for MS store apps..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -Type DWord -Value 0

	" Smart screen for MS store apps disabled `n" >> "windows_configuration.log"
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
	Write-Output "Disabling SmartScreen Filter..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0

	" Smart screeen disabled `n" >> "windows_configuration.log"
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
	Write-Output "Enabling SmartScreen Filter..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue

	" Smart screen enabled `n" >> "windows_configuration.log"
}

# Set innactivity time to lock screen
Function EnableLockAcc {
	Write-Output "Setting user innactivity timeout for lock screen to 5 minutes..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
		New-item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Type DWord -Value 300

	" Inactivity timeout set to 5 minutes `n" >> "windows_configuration.log"
}

# Disable innactivity timeout
Function DisableLockAcc {
	Write-Output "Removing user innactivity timeout for lock screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue

	" Inactivity timeout removed not set `n" >> "windows_configuration.log"
}

# Disable Remote Registry Service
# This allows for remote registry configuration, however, the local user account won't be affected
Function DisableRemoteRegistry {
	Write-Output "Disabling Remote Registry service..."
	Stop-Service "Remote Registry" -WarningAction SilentlyContinue
	Set-Service "Remote Registry" -StartupType Disabled

	" Remote registry configuration disabled `n" >> "windows_configuration.log"
}

# Enable Remote Registry Service
Function EnableRemoteRegistry {
	Write-Output "Disabling Remote Registry service..."
	Set-Service "Remote Registry" -StartupType Automatic

	" Remote registry configuration enabled `n" >> "windows_configuration.log"
}

# Disable Windows Credential Guard
# With windows 11 22h2 microsoft has introduced windows credential guard as a part of virtualisation-based security
# this prevents the user from using RDP service with the saved credentials and ask for authentication each time you try to connect.
Function DisableCredentialsGuard {
	Write-Output "Disabling virtualisation-based security credential guard feature..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Type DWord -Value 0

	" Virtualisation-based security credential guard has been disabled `n" >> "windows_configuration.log"
}

# Enable Windows Credential Guard
Function EnableCredentialGuard {
	Write-Output "Enabling virtualisation-based security credential guard feature..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

	" Credential guard has been enabled `n" >> "windows_configuration.log"
}



#######################################################################################################
#
# 		Network Tweaks
#
#######################################################################################################



# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private

	" Network profile set to private `n" >> "windows_configuration.log"
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public

	" Network profile set to public `n" >> "windows_configuration.log"
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
	Write-Output "Setting unknown networks profile to private..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1

	" Unknown network set to private `n" >> "windows_configuration.log"
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

	" Unknown network set to public `n" >> "windows_configuration.log"
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

	" Automatic installation of net devices disabled `n" >> "windows_configuration.log"
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
	Write-Output "Enabling automatic installation of network devices..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue

	" Automatic installation of net devices enabled `n" >> "windows_configuration.log"
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

	" SMB1 protocol disabled `n" >> "windows_configuration.log"
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

	" SMB1 Protocol enabled `n" >> "windows_configuration.log"
}

# Disable NetBIOS over TCP/IP on all currently installed network interfaces
Function DisableNetBIOS {
	Write-Output "Disabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2

	" NetBIOS disabled `n" >> "windows_configuration.log"
}

# Enable NetBIOS over TCP/IP on all currently installed network interfaces
Function EnableNetBIOS {
	Write-Output "Enabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0

	" NetBIOS enabled `n" >> "windows_configuration.log"
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
	Write-Output "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null

	" Remote assistance disabled `n" >> "windows_configuration.log"
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
	Write-Output "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Add-WindowsCapability -Online | Out-Null

	" Remote assistance enabled `n" >> "windows_configuration.log"
}

# Enable Remote Desktop
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "updateRDStatus" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*"

	" Remote desktop enabled `n" >> "windows_configuration.log"
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "updateRDStatus" -Type DWord -Value 0
	Disable-NetFirewallRule -Name "RemoteDesktop*"

	" Remote desktop disabled `n" >> "windows_configuration.log"
}

# Disable Internet Connection Sharing (e.g. mobile hotspot)
Function DisableConnectionSharing {
	Write-Output "Disabling Internet Connection Sharing..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0

	" Hotspot disabled `n" >> "windows_configuration.log"
}

# Enable Internet Connection Sharing (e.g. mobile hotspot)
Function EnableConnectionSharing {
	Write-Output "Enabling Internet Connection Sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue

	" Hotspot enabled `n" >> "windows_configuration.log"
}

# Disable shared experiances (cross-device experiance).
# Share across devices
Function DisableSharedExperiance {
	Write-Output "Disabling cross-device experiance..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0

	" Shared experiances disbaled `n" >> "windows_configuration.log"
}

# Enbale shared experiances
Function EnableSharedExperiaces {
	Write-Output "Enabling shared experiances..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue

	" Shared experiances enabled `n" >> "windows_configuration.log"
}

# Disable Windows Network Usage Monitor service
Function DisableNetworkUsageMonitor {
	Write-Output "Disabling Network Data Usage Monitor (ndu) service..."
	Stop-Service "ndu" -WarningAction SilentlyContinue
	Set-Service "ndu" -StartupType Disabled

	" Network usage monitor disabled `n" >> "windows_configuration.log"
}

# Enable network usage monitor
Function EnableNetworkUsageMonitor {
	Write-Output "Enable Network Data Usage Monitor (ndu) service..."
	Start-Service "ndu" -WarningAction SilentlyContinue
	Set-Service "ndu" -StartupType Automatic

	" Network usage monitor enabled `n" >> "windows_configuration.log"
}



#######################################################################################################
#
# 		Windows Service Tweaks
#
#######################################################################################################



# Enable receiving updates for other Microsoft products via Windows Update
Function EnableUpdateMSProducts {
	Write-Output "Enabling updates for other Microsoft products..."
	(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null

	" Receiving updates for MS Apps on `n" >> "windows_configuration.log"
}

# Disable receiving updates for other Microsoft products via Windows Update
Function DisableUpdateMSProducts {
	Write-Output "Disabling updates for other Microsoft products..."
	If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
		(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
	}

	" Receiving updates for MS Apps off `n" >> "windows_configuration.log"
}

# Disable nightly wake-up for Automatic Maintenance and Windows Updates
Function DisableMaintenanceWakeUp {
	Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0

	" Maintenance wake-up disabled `n" >> "windows_configuration.log"
}

# Enable nightly wake-up for Automatic Maintenance and Windows Updates
Function EnableMaintenanceWakeUp {
	Write-Output "Enabling nightly wake-up for Automatic Maintenance..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue

	"Maintenance wake-up enabled `n" >> "windows_configuration.log"
}

# Nearby sharing off
Function NearbySharingOff {
	Write-Output "Turning off nearby sharing..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "NearShareChannelUserAuthzPolicy" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolic" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" -Name "BluetoothLastDisabledNearShare" -Type DWord -Value 0

	" Sharing between nearby devices turned off `n" >> "windows_configuration.log"
}

# Nearby sharing for my devices only
Function NearbySharingMyDevices {
	Write-Output "Enabling nearby sharing across my devices..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "NearShareChannelUserAuthzPolicy" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolic" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" -Name "BluetoothLastDisabledNearShare" -Type DWord -Value 1

	" Nearby sharing between my devices turned on `n" >> "windows_configuration.log"
}

# Enable Clipboard History
Function EnableClipboardHistory {
	Write-Output "Enabling Clipboard History..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1

	" Clipboard history enabled `n" >> "windows_configuration.log"
}

# Disable Clipboard History
Function DisableClipboardHistory {
	Write-Output "Disabling Clipboard History..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue

	" Clipboard history disabled `n" >> "windows_configuration.log"
}

# Disable Autoplay
Function DisableAutoplay {
	Write-Output "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

	" autoplay disabled `n" >> "windows_configuration.log"
}

# Enable Autoplay
Function EnableAutoplay {
	Write-Output "Enabling Autoplay..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -ErrorAction SilentlyContinue

	" autoplay enabled `n" >> "windows_configuration.log"
}

# Disable Autorun for all drives
Function DisableAutorun {
	Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 #value [91]

	" autorun disabled `n" >> "windows_configuration.log"
}

# Enable Autorun for removable drives
Function EnableAutorun {
	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

	" autorun disabled `n" >> "windows_configuration.log"
}

# Disable System Restore for system drive - Not applicable to Server
# Note: This does not delete already existing restore points as the deletion of restore points is irreversible. In order to do that, run also following command.
# vssadmin Delete Shadows /For=$env:SYSTEMDRIVE /Quiet
Function DisableRestorePoints {
	Write-Output "Disabling System Restore for system drive..."
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"

	" restore points disabled `n" >> "windows_configuration.log"
}

# Enable System Restore for system drive - Not applicable to Server
# Note: Some systems (notably VMs) have maximum size allowed to be used for shadow copies set to zero. In order to increase the size, run following command.
# vssadmin Resize ShadowStorage /On=$env:SYSTEMDRIVE /For=$env:SYSTEMDRIVE /MaxSize=10GB
Function EnableRestorePoints {
	Write-Output "Enabling System Restore for system drive..."
	Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE"

	" resotre points enabled `n" >> "windows_configuration.log"
}

# Enable Storage Sense - automatic disk cleanup
Function EnableStorageSense {
	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1

	" automatic disk clean ups enabled `n" >> "windows_configuration.log"
}

# Disable Storage Sense - Applicable since 1703
Function DisableStorageSense {
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

	" automatic disk cleanups disabled `n" >> "windows_configuration.log"
}

# Stop and disable Superfetch service - Might be more applicable to older devices so free up some RAM.
Function DisableSuperfetch {
	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled

	" SysMain service disabled `n" >> "windows_configuration.log"
}

# Start and enable Superfetch service - Enabled by default
Function EnableSuperfetch {
	Write-Output "Starting and enabling Superfetch service..."
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue

	" SysMain service enabled `n" >> "windows_configuration.log"
}

# Set BIOS time to UTC
Function SetBIOSTimeUTC {
	Write-Output "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

	" BIOS Time set to UTC `n" >> "windows_configuration.log"
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
	Write-Output "Setting BIOS time to Local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue

	"BIOS time set to local `n" >> "windows_configuration.log"
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0

	" Sleep time disabled (powercfg) `n" >> "windows_configuration.log"
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
	Write-Output "Enabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 45
	powercfg /X monitor-timeout-dc 10
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0

	" Custom sleep timers applied (powercfg) `n" >> "windows_configuration.log"
}

# Disable Fast Startup
Function DisableFastStartup {
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

	" Fast start-up disabled `n" >> "windows_configuration.log"
}

# Enable Fast Startup (Often enabled by default)
Function EnableFastStartup {
	Write-Output "Enabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1

	" Fast start-up enabled `n" >> "windows_configuration.log"
}

# Disable automatic reboot on crash (BSOD) (Often the default setting)
Function DisableAutoRebootOnCrash {
	Write-Output "Disabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0

	" Disable auto re-boot on crash `n" >> "windows_configuration.log"
}

# Enable automatic reboot on crash (BSOD)
Function EnableAutoRebootOnCrash {
	Write-Output "Enabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1

	" Enable auto re-boot on crash `n" >> "windows_configuration.log"
}

###########################################################################################################
#################################	Windows 11 22H2 Tweaks 	###############################################

# Enable Dynamic Lock (Lock the screen as you step away from the computer)
Function EnableDynamicLock {
	Write-Output "Enabling dynamic lock..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableGoodbye" -Type DWord -Value 1

	" Dynamic lock enabled `n" >> "windows_configuration.log"
}

# Disable Dynamic Lock (Default)
Function DisableDynamicLock {
	Write-Output "Disabling dynamic lock..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableGoodbye" -Type DWord -Value 0

	" Dynamic lock disabled `n" >> "windows_configuration.log"
}

# Disable projecting to this PC
Function DisableProjectingToPC {
	Write-Output "Disabling 'Projecting to this PC' settings..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "NetworkQualificationEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" -Name "AutoEnabled" -Type DWord -Value 0

	" projecting to this PC disabled `n" >> "windows_configuration.log"
}

# Enable projecting to this PC only from secure network (And always promt when projecting)
Function EnableProjectingToPC {
	Write-Output "Enabling 'Project tothis PC' only from secure networks..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "NetworkQualificationEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" -Name "AutoEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MiracastReceiver" -Name "ConsentToast" -Type DWord -Value 1

	" projecting to this PC enabled from secure networks `n" >> "windows_configuration.log"
}

# Disable Power throttling
Function DisbalePowerThrottling {
	Write-Output "Power throttling is being disabled..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Type DWord -Value 1

	" Power throttling has been disabled `n" >> "windows_configuration.log"
}

# Enable Power Throttling
Function EnablePowerThrottling {
	Write-Output "Enabling power throttling..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue

	" Power throttling has been enbaled `n" >> "windows_configuration.log"
}

# Disable ActiveX installer (AxInstSV) 
# This service is used to connect windows with IoT devices such as Smart TV's, light bulbs etc.
Function DisableIoTConnectivity {
	Write-Output "Disabling ActiveX Installer (AxInstSV) service for IoT devices..."
	Stop-Service "AxInstSV" -WarningAction SilentlyContinue
	Set-Service "AxInstSV" -StartupType Disabled

	" ActiveX service disabled `n" >> "windows_configuration.log"
}

# Enable ActiveX Installer service
Function EnableIoTConnectivity {
	Write-Output "Enabling ActiveX Installer service..."
	Set-Service "DiagTrack" -StartupType Automatic

	" ActiveX service enabled `n" >> "windows_configuration.log"
} 




#######################################################################################################
#
# 		User Interface (UI) Tweaks
#
#######################################################################################################



# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

	" Visual effects adjusted for performance `n" >> "windows_configuration.log"
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1

	" Visual effect adjusted for appearance `n" >> "windows_configuration.log"
}

# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
	Write-Output "Hiding network options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1

	" Network hidden from lock screen `n" >> "windows_configuration.log"
}

# Show network options on lock screen
Function ShowNetworkOnLockScreen {
	Write-Output "Showing network options on Lock Screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue

	" Network icon enabled on lock screen `n" >> "windows_configuration.log"
}

# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
	Write-Output "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0

	" Shutdown removed from lock screen `n" >> "windows_configuration.log"
}

# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
	Write-Output "Showing shutdown options on Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1

	" Shutdown enabled from lock screen `n" >> "windows_configuration.log"
}

# Disable Lock screen Blur - Applicable since 1903
Function DisableLockScreenBlur {
	Write-Output "Disabling Lock screen Blur..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1

	" Lock screen blur disabled `n" >> "windows_configuration.log"
}

# Enable Lock screen Blur - Applicable since 1903
Function EnableLockScreenBlur {
	Write-Output "Enabling Lock screen Blur..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue

	" Lock screen blur enabled `n" >> "windows_configuration.log"
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
	Write-Output "Disabling search for app in store for unknown extensions..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

	" Do not search for app in store `n" >> "windows_configuration.log"
}

# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
	Write-Output "Enabling search for app in store for unknown extensions..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue

	" Search for apps in MS store `n" >> "windows_configuration.log"
}

# Hide recently added apps in Start Menu (Disable setting)
Function HideRecentlyAddedApps {
	Write-Output "Hiding recently added apps in the start menu (Disabled)..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1

	" Recently added apps setting disabled (hiude) `n" >> "windows_configuration.log"
}

# Show 'recently added apps in Start Menu (Disable setting)
Function ShowRecentlyAddedApps {
	Write-Output "Showing recently added apps in start menu (disabled)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue

	" Recently added apps setting disabled (show) `n" >> "windows_configuration.log"
}

# Hide most used apps in star menu (Disable setting)
Function HideMostUsedApps {
	Write-Output "Hiding most used apps in start menu (Disabled)..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowOrHideMostUsedApps" -Type DWord -Value 2
}

# Show show most used apps in start menu (Disable setting)
Function ShowMostUsedApps {
	Write-Output "Showing most used app in start menu (Disbaled)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue

	" Most used apps setting disabled (Visible) `n" >> "windows_configuration.log"
}

# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
	Write-Output "Setting Control Panel view to small icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1

	" Small icons in control panel `n" >> "windows_configuration.log"
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
	Write-Output "Setting Control Panel view to large icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0

	" Large icons in control panel `n" >> "windows_configuration.log"
}

# Set Control Panel view to categories
Function SetControlPanelCategories {
	Write-Output "Setting Control Panel view to categories..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue

	" Categories in control panel `n" >> "windows_configuration.log"
}

# Set Dark Mode for Applications
Function SetAppsDarkMode {
	Write-Output "Setting Dark Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0

	" App dark mode set `n" >> "windows_configuration.log"
}

# Set Light Mode for Applications
Function SetAppsLightMode {
	Write-Output "Setting Light Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1

	" App light mode set `n" >> "windows_configuration.log"
}

# Set Light Mode for System - Applicable since 1903
Function SetSystemLightMode {
	Write-Output "Setting Light Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1

	" System light mode set `n" >> "windows_configuration.log"
}

# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode {
	Write-Output "Setting Dark Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

	" System dark mode set `n" >> "windows_configuration.log"
}

# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

	" Num lock enabled (default) `n" >> "windows_configuration.log"
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

	" Num lock disabled (default) `n" >> "windows_configuration.log"
}

# Disable enhanced pointer precision
Function DisableEnhPointerPrecision {
	Write-Output "Disabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"

	" Enhanced mouse pointer disabled `n" >> "windows_configuration.log"
}

# Enable enhanced pointer precision
Function EnableEnhPointerPrecision {
	Write-Output "Enabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10"

	" Enhanced mouse pointed enabled `n" >> "windows_configuration.log"
}

# Set Highest Mouse sensitivity
Function MaxMouseSpeed {
	Write-Output "Increasing mouse speed to the maximum..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 20

	" Mouse speed increased to the maximum `n" >> "windows_configuration.log"
}

# Set Medium Mouse Sensitivity
Function MediumMouseSpeed {
	Write-Output "Setting mouse speed at the medium..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 20

	" Mouse speed set to medium `n" >> "windows_configuration.log"
}

# Enable verbose startup/shutdown status messages
Function EnableVerboseStatus {
	Write-Output "Enabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1
	} Else {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	}

	" Verbose logon enabled `n" >> "windows_configuration.log"
}

# Disable verbose startup/shutdown status messages
Function DisableVerboseStatus {
	Write-Output "Disabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0
	}

	" Verbose logon disabled `n" >> "windows_configuration.log"
}

# Dispaly information about previous logon
Function DisplayPreviousLogOn {
	Write-Output "Displaying previous logon information..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisplayLastLogonInfo" -Type DWord -Value 1
	} Else {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisplayLastLogonInfo" -ErrorAction SilentlyContinue
	}

	" Last logon info enabled `n" >> "windows_configuration.log"
}

# Hide information about previous logon
Function HidePreviousLogOn {
	Write-Output "Hide previous logon information..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisplayLastLogonInfo" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisplayLastLogonInfo" -Type DWord -Value 0
	}

	" Last logon info disabled `n" >> "windows_configuration.log"
}

# Disable F1 Help key in Explorer and on the Desktop
Function DisableF1HelpKey {
	Write-Output "Disabling F1 Help key..."
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""

	" F1 Key (Help) disabled `n" >> "windows_configuration.log"
}

# Enable F1 Help key in Explorer and on the Desktop
Function EnableF1HelpKey {
	Write-Output "Enabling F1 Help key..."
	Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue

	" F1 Key (Help) enabled `n" >> "windows_configuration.log"
}

################################################################################################################
####################################### Windows 11 22H2 Tweaks #################################################

# Center Align Taskbar icons
Function CenterAlignTaskbar {
	Write-Output "Aligning Taskabr icons to the center..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 1

	" Taskbar icons aligned in center `n" >> "windows_configuration.log"
}

# Left Align Taskbar icons
Function LeftAlignTaskbar {
	Write-Output "Aligning Taskbar icons to the left..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -ErrorAction SilentlyContinue

	" Taskbar icons aligned to the left `n" >> "windows_configuration.log"
}

# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

	" Taskbar search icon hidden `n" >> "windows_configuration.log"
}

# Show Taskbar Search icon
Function ShowTaskbarSearch {
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1

	" Taskabr search icon visible `n" >> "windows_configuration.log"
}

# Hide Task View button
Function HideTaskView {
	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

	" Task view button hidden `n" >> "windows_configuration.log"
}

# Show Task View button
Function ShowTaskView {
	Write-Output "Showing Task View button..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue

	" Task view button visible `n" >> "windows_configuration.log"
}

# Set taskbar buttons to show labels and combine when taskbar is full
Function SetTaskbarCombineWhenFull {
	Write-Output "Setting taskbar buttons to combine when taskbar is full..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 1

	" Combine labels when taskbar is full `n" >> "windows_configuration.log"
}

# Set taskbar buttons to show labels and never combine
Function SetTaskbarCombineNever {
	Write-Output "Setting taskbar buttons to never combine..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2

	" Never combine task bar labels `n" >> "windows_configuration.log"
}

# Set taskbar buttons to always combine and hide labels
Function SetTaskbarCombineAlways {
	Write-Output "Setting taskbar buttons to always combine, hide labels..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -ErrorAction SilentlyContinue

	" Always combine taskbar labels `n" >> "windows_configuration.log"
}

# Hide Widget icon
Function HideWidgetsIcon {
    Write-Output "Hiding Widget icon..."
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Dsh")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Dsh" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWORD -Value 0

	" Remove the widgets icon `n" >> "windows_configuration.log"
}

# Show Widget icon
Function ShowWidgetsIcon {
    Write-Output "Show Widget icon..."
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Dsh")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Dsh" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWORD -Value 1 

	" Enable widgets icon `n" >> "windows_configuration.log"
}

# Hide Taskbar Chat icon
Function HideTaskbarChatIcon {
	Write-Output "Hiding Chat icon..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0

	" Chat icon hidden `n" >> "windows_configuration.log"
}

# Show Taskbar Chat icon
Function ShowTaskbarChatIcon {
	Write-Output "Showing Chat icon..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -ErrorAction SilentlyContinue

	" Chat icon visible `n" >> "windows_configuration.log"
}

# Set start menu to show even amount of recommendations and pins
Function EvenStartMenu {
    Write-Output "Showing even amount of recommendations and pins in Start menu..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 0

	" Event the odds (start menu) `n" >> "windows_configuration.log"
}

# Set start menu to show more pins
Function ShowMorePinsInStartMenu {
    Write-Output "Showing more pins in Start menu..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 1

	" More pins in start menu `n" >> "windows_configuration.log"
}

# Set start menu to show more recomendations
Function ShowMoreRecommendationsInStartMenu {
    Write-Output "Showing more recommendations in Start menu..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Type DWord -Value 2

	" More recommendations in start menu `n" >> "windows_configuration.log"
}

# Improve JPEG Wallpapper quality
Function ImproveWallpapper {
	Write-Output "Improving wallpapper quality..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type DWord -Value 64

	" JPEG & JPG Wallpaper quality improved `n" >> "windows_configuration.log"
}

# Reduce JPEG Wallpapper quality
Function ReduceWallpapper {
	Write-Output "Reducing wallpapper quality..."
	Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -ErrorAction SilentlyContinue

	" Wallappper quality reduces `n" >> "windows_configuration.log"
}

# Removed taskbar icon thumbnail hover speed delay
Function RemoveThumbnailHoverDelay {
	Write-Output "Removed taskbar icon thumbnail hover delay..."
	If (!(Test-Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ExtendedUIHoverTime" -Type DWord -Value 1

	" Taskbar icon thumbnail hover speed removed `n" >> "windows_configuration.log"
}

# Set taskbar icon thumbnail hover speed delay back to default
Function DefaultThumbnailHoverDelay {
	Write-Output "Taskbar icon thumbnail hover speed set back to default..."
	Remove-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ExtendedUIHoverTime" -ErrorAction SilentlyContinue

	" Taskbar icon thumbnail hover speed set to default `n" >> "windows_configuration.log"
}

########################## Time & Region Settings ######################################

# Show seconds in taskbar
# Hide seconds from taskbar
Function HideSecondsFromTaskbar {
	Write-Output "Hiding seconds from taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue

	" Seconds hiden from taskabr `n" >> "windows_configuration.log"
}

# Show seconds in taskbar
Function ShowSecondsOnTaskbar {
	Write-Output "Adding second counter to the system clock on the taskbar..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1

	" Second count added to clock `n" >> "windows_configuration.log"
}

# Set region to en-GB, but change time format to follow US e.g. 9:40 AM dd.mm.yy
Function SetRegionCustomGB {
	Write-Output "Changing region to en-GB with short time format..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocalName" -Type String -Value "en-GB"
	Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongDate" -Type String -Value "dddd, MMMM d, yyyy"
	Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Type String -Value "M/d/yyyy"
	Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortTime" -Type String "h:mm tt"

	" Region set to custom en-GB `n" >> "windows_configuration.log"
}

# Set to default en-GB region format
Function SetRegionDefaultGB {
	Write-Output "Changing region format to default en-GB..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "LocaleName" -Type String -Value "en-GB"

	" Region set to default en-GB `n" >> "windows_configuration.log"
}

########################## Typing settings ######################################

 # Highlight misspelled words
 Function EnableSpellingHighlights {
	Write-Output "Enabling missplled word highlights..."
	If (!(Test-Path "HKCU:\Software\Microsoft\TabletTip\1.7")) {
		New-Item -Path "HKCU:\Software\Microsoft\TabletTip\1.7" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableSpellchecking" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableAutocorrection" -Type DWord -Value 1

	" Missplled word highlights enabled `n" >> "windows_configuration.log"
}

# Do not highlight missplled words
Function DisableSpellingHighlights {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableSpellchecking" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableAutocorrection" -Type DWord -Value 0

	" Misspeled word highlights disabled `n" >> "windows_configuration.log"
}

# Disable Text suggestions
Function DisableTextSuggestions {
	Write-Output "Disabling Text suggestions..."
	If (!(Test-Path "HKCU:\Software\Microsoft\input\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\input\Settings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "EnableHwkbTextPrediction" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "MultilingualEnabled" -Type DWord -Value 0

	" Text suggestions disabled `n" >> "windows_configuration.log"
}

# Enable Text suggestions
Function EnableTextSuggestions {
	Write-Output "Enabling Text suggestions..."
	If (!(Test-Path "HKCU:\Software\Microsoft\input\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\input\Settings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "EnableHwkbTextPrediction" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "MultilingualEnabled" -Type DWord -Value 1

	" Text suggestions enabled `n" >> "windows_configuration.log"
}

# Enable Typing insights
Function EnableTypingInsights {
	Write-Output "Enabling typing insights..."
	Set-ItemProperty -Path "HKCU:\Software\Input\Settings" -Name "InsightsEnabled" -Type DWord -Value 1

	" Typing insights enabled `n" >> "windows_configuration.log"
}

# Disable typing insights
Function DisableTypingInsights {
	Write-Output "Disabling typing insights..."
	Set-ItemProperty "HKCU:\Software\Microsoft\Input\Settings" "InsightsEnabled" -Type DWord -Value 0

	" Typing insights disabled `n" >> "windows_configuration.log"
}



#######################################################################################################
#
# 		Explorer (UI) Tweaks
#
#######################################################################################################



# Show compact view in File Explorer
Function UseCompactMode {
	Write-Output "Changing to compact view in file explorer..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -Type DWord -Value 1

	" Compact mode set in file explorer `n" >> "windows_configuration.log"
}

# Show expanded view in file explorer
Function UseExpandedMode {
	Write-Output "Changing to expanded view in file explorer..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -ErrorAction SilentlyContinue

	" Expanded mode set in file explorer `n" >> "windows_configuration.log"
}

# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

	" Show file extensions `n" >> "windows_configuration.log"
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1

	" Hide file extensions `n" >> "windows_configuration.log"
}

# Show hidden files
Function ShowHiddenFiles {
	Write-Output "Showing hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

	" Show hidden files `n" >> "windows_configuration.log"
}

# Hide hidden files
Function HideHiddenFiles {
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2

	" Hide hidden files `n" >> "windows_configuration.log"
}

# Show protected operating system files
Function ShowSuperHiddenFiles {
	Write-Output "Showing protected operating system files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1

	" Show protected system files `n" >> "windows_configuration.log"
}

# Hide protected operating system files
Function HideSuperHiddenFiles {
	Write-Output "Hiding protected operating system files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 0

	" Hide protected system files `n" >> "windows_configuration.log"
}

# Show empty drives (with no media)
Function ShowEmptyDrives {
	Write-Output "Showing empty drives (with no media)..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value 0

	" Show empty driver `n" >> "windows_configuration.log"
}

# Hide empty drives (with no media)
Function HideEmptyDrives {
	Write-Output "Hiding empty drives (with no media)..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -ErrorAction SilentlyContinue

	" Hide empty drives `n" >> "windows_configuration.log"
}

# Show coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
Function ShowEncCompFilesColor {
	Write-Output "Showing coloring of encrypted or compressed NTFS files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1

	" Show encrypted file coloring `n" >> "windows_configuration.log"
}

# Hide coloring of encrypted or compressed NTFS files
Function HideEncCompFilesColor {
	Write-Output "Hiding coloring of encrypted or compressed NTFS files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction SilentlyContinue

	" Hide encrypted file coloring `n" >> "windows_configuration.log"
}

# Hide recently and frequently used item shortcuts in Explorer
# Note: This is only UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.
Function HideRecentShortcuts {
	Write-Output "Hiding recent shortcuts in Explorer..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0

	" Hide shortcuts in explorer `n" >> "windows_configuration.log"
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
	Write-Output "Showing recent shortcuts in Explorer..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue

	" Show shortcuts in explorer `n" >> "windows_configuration.log"
}

# Show Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function ShowBuildNumberOnDesktop {
	Write-Output "Showing Windows build number on desktop..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1

	" Build number added to desktop `n" >> "windows_configuration.log"
}

# Remove Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function HideBuildNumberFromDesktop {
	Write-Output "Hiding Windows build number from desktop..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0

	" Build number removed from desktop `n" >> "windows_configuration.log"
}


################################################################################################################
####################################### Windows 11 22H2 Tweaks #################################################


# Change default Explorer view to This PC
Function SetExplorerThisPC {
	Write-Output "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

	" Open 'This PC' in explorer `n" >> "windows_configuration.log"
}

# Change default Explorer view to Home Folder (Default in 22H2)
Function SetExplorerHomeFolder {
	Write-Output "Changing default Explorer view to Home Folder..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 2

	" Open 'Home' in explorer `n" >> "windows_configuration.log"
}

# Hide all icons from desktop
Function HideDesktopIcons {
	Write-Output "Hiding all icons from desktop..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

	" Desktop icons hidden `n" >> "windows_configuration.log"
}

# Show all icons on desktop
Function ShowDesktopIcons {
	Write-Output "Showing all icons on desktop..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 0

	" Desktop icons visible `n" >> "windows_configuration.log"
}

# Show cloud files in Explorer quick access
Function ShowCloudFiles {
	Write-Output "Showing cloud files in Explorer..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCloudFilesInQuickAccess" -Type DWord -Value 1

	" Cloud files added to exolorer `n" >> "windows_configuration.log"
}

# Hide cloud files in Explorer quick access
Function HideCloudFiles {
	Write-Output "Hiding cloud files in Explorer..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCloudFilesInQuickAccess" -Type DWord -Value 0

	" Cloud files hidden from exolorer `n" >> "windows_configuration.log"
}

# Add user folder to Navigation pane in explorer namespace tree
# This will use your MS Account nave if signed in, otherwise local account name
# This is different from pinnig the folder to Faavorites as it will allow you to expande the items
Function PinUserFolderNavPane {
	Write-Output "Pinning User folder to navigation pane namcespace..."
	If (!(Test-Path "HKCU:\Software\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")) {
		New-Item -Path "HKCU:\Software\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1

	" User folder pinned to navigatio pane `n" >> "windows_configuration.log"
}

# Remove user folder from Navigation pane in explorer namespace tree
Function UnpinUserFolderNavPane {
	Remove-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue

	" User folder removed from navigation pane `n" >> "windows_configuration.log"
}

# Hide Network from Navigation pane
Function HideNetNavPane {
	Write-Output "Hidding network location from navigation pane namespace..."
	Remove-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue

	" Removed network from navigation pane `n" >> "windows_configuration.log"
}

Function PinNetNavPane {
	Write-Output "Pinning network location to navigation pane namcespace..."
	If (!(Test-Path "HKCU:\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")) {
		New-Item -Path "HKCU:\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1

	" Network location pinned to navigatio pane `n" >> "windows_configuration.log"
}

# Create temp folder in C:\ drive
Function MkdirTemp {
	Write-Output "Creating 'temp' folder in '$env:SystemDrive'..."
	If(!(Test-Path "$env:SystemDrive\temp")) {
		New-Item -Path "$env:SystemDrive\temp"
	}

	" temp folder created in C:\ drive `n" >> "windows_configuration.log"
}

# Create Dev folder in user profile folder
Function MkdirDev {
	Write-Output "Creating 'dev' folder in '$HOME'..."
	If (!(Test-Path "$HOME\Dev")) {
		New-Item -Path "$HOME\Dev" | Out-Null
	}

	" Dev folder created `n" >> "windows_configuration.log"
}


#######################################################################################################
#
# 		Application Tweaks
#
#######################################################################################################



# Disable automatic Maps updates
Function DisableMapUpdates {
	Write-Output "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

	" Map updates disabled `n" >> "windows_configuration.log"
}

# Enable automatic Maps updates
Function EnableMapUpdates {
	Write-Output "Enable automatic Maps updates..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue

	"Map updates enabled `n" >> "windows_configuration.log"
}

# Disable OneDrive
Function DisableOneDrive {
	Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}

# Enable OneDrive
Function EnableOneDrive {
	Write-Output "Enabling OneDrive..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue

	" OneDrive has been disabled `n" >> "windows_configuration.log"
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	}
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

	" OneDrive has been enabled `n" >> "windows_configuration.log"
}

# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
	Write-Output "Installing OneDrive..."
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow

	" OneDrive installed `n" >> "windows_configuration.log"
}

# Remove all Apps except MS Store
Function UninstallAllApps {
	Write-Output "Uninstalling all default apps except MS Store..."
	Get-AppxPackage -AllUsers | Where-Object {$_.name -notlike "*store*"} | Remove-AppxPackage

	" All default MS apps uninstalled `n" >> "windows_configuration.log"
}

# Uninstall default Microsoft applications
Function UninstallMsftBloat {
	Write-Output "Uninstalling default Microsoft applications..."
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Whiteboard" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsScan" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
	Get-AppxPackage "MicrosoftTeams" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.PowerAutomateDesktop" | Remove-AppPackage
	Get-AppxPackage "MicrosoftCorporationII.QuickAssist" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GamingApp" | Remove-AppxPackage
	Get-AppxPackage "Clipchamp.Clipchamp" | Remove-AppxPackage
	Get-AppPackage "MicrosoftWindows.Client.WebExperience" | Remove-AppxPackage
}

# Uninstall default third party applications
function UninstallThirdPartyBloat {
	Write-Output "Uninstalling default third party applications..."
	Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage
	Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage
	Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage
	# Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
}

# Disable Xbox features - Not applicable to Server
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameCallableUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
	Stop-Service "XboxNetApiSvc" -WarningAction SilentlyContinue
	Set-Service "XboxNetApiSvc" -StartupType Disabled
	Stop-Service "XblGameSave" -WarningAction SilentlyContinue
	Set-Service "XblGameSave" -StartupType Disabled
	Stop-Service "XblAuthManager" -WarningAction SilentlyContinue
	Set-Service "XblAuthManager" -StartupType Disabled

	" Xbox features disbaled `n" >> "windows_configuration.log"
}

# Enable Xbox features - Not applicable to Server
Function EnableXboxFeatures {
	Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
	Set-Service "XboxNetApiSvc" -StartupType Automatic
	Set-Service "XblGameSave" -StartupType Automatic
	Set-Service "XblAuthManager" -StartupType Automatic

	" Xbox features enabled `n" >> "windows_configuration.log"
}

# Disable "Hi!" First Logon Animation (it will be replaced by "Preparing Windows" message)
Function DisableFirstLogonAnimation {
	Write-Output "Disabling First Logon Animation..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Type DWord -Value 0

	" First logon message disabled `n" >> "windows_configuration.log"
}

# Enable "Hi!" First Logon Animation
Function EnableFirstLogonAnimation {
	Write-Output "Enabling First Logon Animation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -ErrorAction SilentlyContinue

	" First logon message enabled `n" >> "windows_configuration.log"
}

# Enable Developer Mode
Function EnableDeveloperMode {
	Write-Output "Enabling Developer Mode..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1

	" Enabled developer mode `n" >> "windows_configuration.log"
}

# Disable Developer Mode
Function DisableDeveloperMode {
	Write-Output "Disabling Developer Mode..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -ErrorAction SilentlyContinue

	" Disabled developer mode `n" >> "windows_configuration.log"
}

# Install Linux Subsystem (Ubunut by default and kali-linux additionaly)
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	wsl --install ; wsl --install -d kali-linux ; wsl --install -d Ubunut-22.04

	" WSL2 (Ubuntu and Kali) Installed `n" >> "windows_configuration.log"
}

# Uninstall Linux Subsystem
Function UninstallLinuxSubsystem {
	Write-Output "Uninstalling Linux Subsystem..."
	wsl --unregister *

	" WSL2 Unregistred `n" >> "windows_configuration.log"
}

# Install Hyper-V
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Hyper-V-All" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}

	" Hyper-V installed (All tools) `n" >> "windows_configuration.log"
}

# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
	Write-Output "Uninstalling Hyper-V..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Hyper-V-All" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}

	" Hyper-V uninstalled (All tools) `n" >> "windows_configuration.log"
}

# Install Windows RSAT tools
Function InstallRSAT {
	Write-Output "Installing windows remote server administration tools..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
	}

	" RSAT have been installed `n" >> "windows_configuration.log"
}

# Uninstall Windows RSAT tools
Function UnisntallRAST {
	Write-Output "Uninstalling windows remote server administration tools..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsCapability -Name RSAT* -Online | Remove-WindowsCapability 
	}
	
	" RSAT have been uninstalled `n" >> "windows_configuration.log"
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null

	" XPS Doc writer unisntalled `n" >> "windows_configuration.log"
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
	Write-Output "Installing Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null

	" XPS Doc writer installed `n" >> "windows_configuration.log"
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
	Write-Output "Removing Default Fax Printer and disabling service..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
	Stop-Service "fxssvc.exe" -WarningAction SilentlyContinue
	Set-Service "fxssvc.exe" -StartupType Disabled

	" Fax printer removed `n" >> "windows_configuration.log"
}

# Add Default Fax Printer
Function AddFaxPrinter {
	Write-Output "Adding Default Fax Printer adn re-enabling service..."
	Add-Printer -Name "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:" -ErrorAction SilentlyContinue
	Set-Service "fxssvc.exe" -StartupType Automatic

	" Fax printer added `n" >> "windows_configuration.log"
}

# Uninstall Windows Fax and Scan Services - Not applicable to Server
Function UninstallFaxAndScan {
	Write-Output "Uninstalling Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null

	" fax and scan services uninstalled `n" >> "windows_configuration.log"
}

# Install Windows Fax and Scan Services - Not applicable to Server
Function InstallFaxAndScan {
	Write-Output "Installing Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Add-WindowsCapability -Online | Out-Null

	" fax and scan services isntalled `n" >> "windows_configuration.log"
}

########################################################################################################
############################	Windows 11 22H2 Tweaks 	################################################

# Set app sharing across devices off
Function AppSharingOff {
	Write-Output "Disabling app sharing across devices..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Type DWord -Value 0

	" app sharing across devices turned off `n" >> "windows_configuration.log"
}

# Set app sharing across devices to only my devices (MS Account connected)
Function AppSharingMyDevices {
	Write-Output "Enabling app sharing across my connected devices..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Type DWord -Value 1

	" app sharing set between my devices `n" >> "windows_configuration.log"
}



#######################################################################################################
#
# 		Windows Server Tweaks
#
#######################################################################################################



# Hide Server Manager after login
Function HideServerManagerOnLogin {
	Write-Output "Hiding Server Manager after login..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}

# Show Server Manager after login
Function ShowServerManagerOnLogin {
	Write-Output "Showing Server Manager after login..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}

# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
	Write-Output "Disabling Shutdown Event Tracker..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}

# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
	Write-Output "Enabling Shutdown Event Tracker..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}

# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
	Write-Output "Disabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
	Write-Output "Enabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
	Write-Output "Disabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}

# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
	Write-Output "Enabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}

# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
	Write-Output "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}

# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
	Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}

# Enable Audio
Function EnableAudio {
	Write-Output "Enabling Audio..."
	Set-Service "Audiosrv" -StartupType Automatic
	Start-Service "Audiosrv" -WarningAction SilentlyContinue
}

# Disable Audio
Function DisableAudio {
	Write-Output "Disabling Audio..."
	Stop-Service "Audiosrv" -WarningAction SilentlyContinue
	Set-Service "Audiosrv" -StartupType Manual
}



#######################################################################################################
#
# 		Unpin icons Tweaks
#
#######################################################################################################



# Unpin all Start Menu tiles
# Note: This function has no counterpart. You have to pin the tiles back manually.
Function UnpinStartMenuTiles {
	Write-Output "Unpinning all Start Menu tiles..."
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

# Unpin all Taskbar icons
# Note: This function has no counterpart. You have to pin the icons back manually.
Function UnpinTaskbarIcons {
	Write-Output "Unpinning all Taskbar icons..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}



#######################################################################################################
#
# 		Auxilary Functions
#
#######################################################################################################



# Wait for key to be presses and proceed
Function WaitForKey {
	Write-Output "`nPress any key to restart..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}

############# Export functions ###############
Export-ModuleMember -Function *