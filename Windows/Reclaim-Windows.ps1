# Default preset
$tweaks = @(
	### Require administrator privileges ###
	"RequireAdmin",

	### Privacy Tweaks ###
	"DisableTelemetry",             # "EnableTelemetry",
	"DisableWiFiSense",             # "EnableWiFiSense",
	"DisableSmartScreen",         # "EnableSmartScreen",
	"DisableWebSearch",             # "EnableWebSearch",
	"DisableAppSuggestions",        # "EnableAppSuggestions",
	"DisableActivityHistory",       # "EnableActivityHistory",
	#"DisableBackgroundApps",        # "EnableBackgroundApps",
	"DisableLocationTracking",      # "EnableLocationTracking",
	"DisableMapUpdates",            # "EnableMapUpdates",
	"DisableFeedback",              # "EnableFeedback",
	"DisableTailoredExperiences",   # "EnableTailoredExperiences",
	"DisableAdvertisingID",         # "EnableAdvertisingID",
	"DisableCortana",               # "EnableCortana",
	"DisableErrorReporting",        # "EnableErrorReporting",
	"SetP2PUpdateLocal",          # "SetP2PUpdateInternet",
	"DisableDiagTrack",             # "EnableDiagTrack",
	"DisableWAPPush",               # "EnableWAPPush",

	### Security Tweaks ###
	# "SetUACLow",                  # "SetUACHigh",
	# "EnableSharingMappedDrives",  # "DisableSharingMappedDrives",
	# "DisableAdminShares",           # "EnableAdminShares",
	"DisableSMB1",                # "EnableSMB1",
	# "DisableSMBServer",           # "EnableSMBServer",
	# "DisableLLMNR",               # "EnableLLMNR",
	"SetCurrentNetworkPrivate",     # "SetCurrentNetworkPublic",
	# "SetUnknownNetworksPrivate",  # "SetUnknownNetworksPublic",
	# "DisableNetDevicesAutoInst",  # "EnableNetDevicesAutoInst",
	# "EnableCtrldFolderAccess",    # "DisableCtrldFolderAccess",
	# "DisableFirewall",            # "EnableFirewall",
	# "DisableDefender",            # "EnableDefender",
	# "DisableDefenderCloud",       # "EnableDefenderCloud",
	"EnableF8BootMenu",             # "DisableF8BootMenu",
	#"SetDEPOptOut",                 # "SetDEPOptIn",
	# "EnableCIMemoryIntegrity",    # "DisableCIMemoryIntegrity",
	#"DisableScriptHost",            # "EnableScriptHost",
	#"EnableDotNetStrongCrypto",     # "DisableDotNetStrongCrypto",
	# "EnableMeltdownCompatFlag"    # "DisableMeltdownCompatFlag",

	### Service Tweaks ###
	# "DisableUpdateMSRT",          # "EnableUpdateMSRT",
	# "DisableUpdateDriver",        # "EnableUpdateDriver",
	"DisableUpdateRestart",         # "EnableUpdateRestart",
	"DisableHomeGroups",          # "EnableHomeGroups",
	# "DisableSharedExperiences",     # "EnableSharedExperiences",
	# "DisableRemoteAssistance",      # "EnableRemoteAssistance",
	# "EnableRemoteDesktop",          # "DisableRemoteDesktop",
	"DisableAutoplay",              # "EnableAutoplay",
	"DisableAutorun",               # "EnableAutorun",
	# "EnableStorageSense",         # "DisableStorageSense",
	# "DisableDefragmentation",     # "EnableDefragmentation",
	# "DisableSuperfetch",          # "EnableSuperfetch",
	# "DisableIndexing",            # "EnableIndexing",
	# "SetBIOSTimeUTC",             # "SetBIOSTimeLocal",
	# "EnableHibernation",          # "DisableHibernation",
	# "DisableSleepButton",         # "EnableSleepButton",
	# "DisableSleepTimeout",        # "EnableSleepTimeout",
	# "DisableFastStartup",         # "EnableFastStartup",

	### UI Tweaks ###
	# "DisableActionCenter",          # "EnableActionCenter",
	# "DisableLockScreen",            # "EnableLockScreen",
	# "DisableLockScreenRS1",       # "EnableLockScreenRS1",
	# "HideNetworkFromLockScreen",    # "ShowNetworkOnLockScreen",
	# "HideShutdownFromLockScreen",   # "ShowShutdownOnLockScreen",
	# "DisableStickyKeys",            # "EnableStickyKeys",
	"ShowTaskManagerDetails"        # "HideTaskManagerDetails",
	"ShowFileOperationsDetails",    # "HideFileOperationsDetails",
	# "EnableFileDeleteConfirm",    # "DisableFileDeleteConfirm",
	#"HideTaskbarSearch",
	"ShowTaskbarSearchIcon",      # "ShowTaskbarSearchBox",
	# "HideTaskView",                 # "ShowTaskView",
	# "ShowSmallTaskbarIcons",        # "ShowLargeTaskbarIcons",
	# "SetTaskbarCombineWhenFull",    # "SetTaskbarCombineNever",     # "SetTaskbarCombineAlways",
	# "HideTaskbarPeopleIcon",        # "ShowTaskbarPeopleIcon",
	# "ShowTrayIcons",                # "HideTrayIcons",
	# "DisableSearchAppInStore",      # "EnableSearchAppInStore",
	# "DisableNewAppPrompt",          # "EnableNewAppPrompt",
	# "SetControlPanelSmallIcons",  # "SetControlPanelLargeIcons",  # "SetControlPanelCategories",
	# "SetVisualFXPerformance",       # "SetVisualFXAppearance",
	# "AddENKeyboard",              # "RemoveENKeyboard",
	# "EnableNumlock",              # "DisableNumlock",

	### Explorer UI Tweaks ###
	"ShowKnownExtensions",          # "HideKnownExtensions",
	# "ShowHiddenFiles",              # "HideHiddenFiles",
	# "HideSyncNotifications"         # "ShowSyncNotifications",
	# "HideRecentShortcuts",          # "ShowRecentShortcuts",
	"SetExplorerThisPC",            # "SetExplorerQuickAccess",
	"ShowThisPCOnDesktop",          # "HideThisPCFromDesktop",
	# "ShowUserFolderOnDesktop",    # "HideUserFolderFromDesktop",
	# "HideDesktopFromThisPC",        # "ShowDesktopInThisPC",
	# "HideDesktopFromExplorer",    # "ShowDesktopInExplorer",
	# "HideDocumentsFromThisPC",      # "ShowDocumentsInThisPC",
	# "HideDocumentsFromExplorer",  # "ShowDocumentsInExplorer",
	# "HideDownloadsFromThisPC",      # "ShowDownloadsInThisPC",
	# "HideDownloadsFromExplorer",  # "ShowDownloadsInExplorer",
	# "HideMusicFromThisPC",          # "ShowMusicInThisPC",
	# "HideMusicFromExplorer",      # "ShowMusicInExplorer",
	# "HidePicturesFromThisPC",       # "ShowPicturesInThisPC",
	# "HidePicturesFromExplorer",   # "ShowPicturesInExplorer",
	# "HideVideosFromThisPC",         # "ShowVideosInThisPC",
	# "HideVideosFromExplorer",     # "ShowVideosInExplorer",
	"Hide3DObjectsFromThisPC",      # "Show3DObjectsInThisPC",
	# "Hide3DObjectsFromExplorer",  # "Show3DObjectsInExplorer",
	# "DisableThumbnails",          # "EnableThumbnails",
	# "DisableThumbsDB",              # "EnableThumbsDB",

	### Application Tweaks ###
	# "DisableOneDrive",              # "EnableOneDrive",
	# "UninstallOneDrive",            # "InstallOneDrive",
	# "UninstallMsftBloat",           # "InstallMsftBloat",
	"UninstallThirdPartyBloat",     # "InstallThirdPartyBloat",
	# "UninstallWindowsStore",      # "InstallWindowsStore",
	# "DisableXboxFeatures",          # "EnableXboxFeatures",
	# "DisableAdobeFlash",            # "EnableAdobeFlash",
	# "UninstallMediaPlayer",       # "InstallMediaPlayer",
	# "UninstallInternetExplorer",  # "InstallInternetExplorer",
	# "UninstallWorkFolders",       # "InstallWorkFolders",
	# "InstallLinuxSubsystem",      # "UninstallLinuxSubsystem",
	# "InstallHyperV",              # "UninstallHyperV",
	"SetPhotoViewerAssociation",    # "UnsetPhotoViewerAssociation",
	"AddPhotoViewerOpenWith",       # "RemovePhotoViewerOpenWith",
	# "UninstallPDFPrinter",        # "InstallPDFPrinter",
	# "UninstallXPSPrinter",          # "InstallXPSPrinter",
	# "RemoveFaxPrinter",             # "AddFaxPrinter",

	### Server Specific Tweaks ###
	# "HideServerManagerOnLogin",   # "ShowServerManagerOnLogin",
	# "DisableShutdownTracker",     # "EnableShutdownTracker",
	# "DisablePasswordPolicy",      # "EnablePasswordPolicy",
	# "DisableCtrlAltDelLogin",     # "EnableCtrlAltDelLogin",
	# "DisableIEEnhancedSecurity",  # "EnableIEEnhancedSecurity",
	# "EnableAudio",                # "DisableAudio",

	### Unpinning ###
	"UnpinStartMenuTiles",
	#"UnpinTaskbarIcons",

	### Auxiliary Functions ###
	"WaitForKey"
	"Restart"
)

##########
# Privacy Tweaks
##########

# Disable Telemetry
# Note: This tweak may cause Enterprise edition to stop receiving Windows updates.
# Windows Update control panel will then show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again. See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57
Function DisableTelemetry {
	Write-Output "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

	" Telemetry has been disabled `n" >> "windows_configuration.xml"
}
# Enable Telemetry
Function EnableTelemetry {
	Write-Output "Enabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

	" Telemetry has been enabled `n" >> "windows_configuration.xml"
}
# Disable Web Search in Start Menu
Function DisableWebSearch {
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

	" Web Search has been disabled in Start Menu `n" >> "windows_configuration.xml"
}
# Enable Web Search in Start Menu
Function EnableWebSearch {
	Write-Output "Enabling Bing Search in Start Menu..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue

	" Web Search has been enabled in Start Menu `n" >> "windows_configuration.xml"
}
# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
	Write-Output "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

	" App Suggestion and automatic updates disabled `n" >> "windows_configuration.xml"
}

# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
	Write-Output "Enabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue

	" App Suggestion and automatic updates enabled `n" >> "windows_configuration.xml"
}
# Disable Location Tracking
Function DisableLocationTracking {
	Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

	" Location tracking disabled `n" >> "windows_configuration.xml"
}

# Enable Location Tracking
Function EnableLocationTracking {
	Write-Output "Enabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1

	" Location tracking enabled `n" >> "windows_configuration.xml"
}
# Disable Feedback
Function DisableFeedback {
	Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

	" Feedback disabled `n" >> "windows_configuration.xml"
}

# Enable Feedback
Function EnableFeedback {
	Write-Output "Enabling Feedback..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

	" Feedback enabled `n" >> "windows_configuration.xml"
}

# Disable Tailored Experiences
Function DisableTailoredExperiences {
	Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

	" Tailored experiances disabled `n" >> "windows_configuration.xml"
}

# Enable Tailored Experiences
Function EnableTailoredExperiences {
	Write-Output "Enabling Tailored Experiences..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue

	" Tailored experiances enabled `n" >> "windows_configuration.xml"
}

# Disable Advertising ID
Function DisableAdvertisingID {
	Write-Output "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

	" Advertising ID disabled `n" >> "windows_configuration.xml"
}

# Enable Advertising ID
Function EnableAdvertisingID {
	Write-Output "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue

	" Advertising ID enabled `n" >> "windows_configuration.xml"
}

# Disable Cortana
Function DisableCortana {
	Write-Output "Disabling Cortana..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

	" Cortana disabled `n" >> "windows_configuration.xml"
}

# Enable Cortana
Function EnableCortana {
	Write-Output "Enabling Cortana..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue

	" Cortana enabled `n" >> "windows_configuration.xml"
}

# Disable Error reporting
Function DisableErrorReporting {
	Write-Output "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	" Error reporting disabled `n" >> "windows_configuration.xml"
}

# Enable Error reporting
Function EnableErrorReporting {
	Write-Output "Enabling Error reporting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	" Error reporting enabled `n" >> "windows_configuration.xml"
}
# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled

	" Diagnostics disabled `n" >> "windows_configuration.xml"
}

# Enable and start Diagnostics Tracking Service
Function EnableDiagTrack {
	Write-Output "Enabling and starting Diagnostics Tracking Service..."
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue

	" Diagnostics enabled `n" >> "windows_configuration.xml"
}
# Enable Remote Desktop w/o Network Level Authentication
Function EnableRemoteDesktop {
	Write-Output "Enabling Remote Desktop w/o Network Level Authentication..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*"

	" Remote desktop enabled `n" >> "windows_configuration.xml"
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"

	" Remote desktop disabled `n" >> "windows_configuration.xml"
}
# Set BIOS time to UTC
Function SetBIOSTimeUTC {
	Write-Output "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

	" BIOS Time set to UTC `n" >> "windows_configuration.xml"
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
	Write-Output "Setting BIOS time to Local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue

	" BIOS Time set to local `n" >> "windows_configuration.xml"
}
# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

	" Hidden taskbar search icon `n" >> "windows_configuration.xml"
}

# Show Taskbar Search icon
Function ShowTaskbarSearchIcon {
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1

	" Show taskbar search icon `n" >> "windows_configuration.xml"
}

# Show Taskbar Search box
Function ShowTaskbarSearchBox {
	Write-Output "Showing Taskbar Search box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2

	" Show taskbar search box `n" >> "windows_configuration.xml"
}

# Hide Task View button
Function HideTaskView {
	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

	" Hidden taskbar Task View icon `n" >> "windows_configuration.xml"
}

# Show Task View button
Function ShowTaskView {
	Write-Output "Showing Task View button..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue

	" Show taskbar Task View icon `n" >> "windows_configuration.xml"
}
# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
	Write-Output "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

	" Hidden task bar People icon `n" >> "windows_configuration.xml"
}

# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
	Write-Output "Showing People icon..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue

	" Hidden task bar People icon `n" >> "windows_configuration.xml"
}
# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
	Write-Output "Setting Control Panel view to small icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1

	" Control Panel icons set to small `n" >> "windows_configuration.xml"
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
	Write-Output "Setting Control Panel view to large icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0

	" Control Panel icons set to large `n" >> "windows_configuration.xml"
}
# Enable NumLock after startup
Function EnableNumlock {
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

	" Num lock enabled `n" >> "windows_configuration.xml"
}

# Disable NumLock after startup
Function DisableNumlock {
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

	" Num lock disabled `n" >> "windows_configuration.xml"
}
##########
# Explorer UI Tweaks
##########

# Show known file extensions
Function ShowKnownExtensions {
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

	" Show file extensions `n" >> "windows_configuration.xml"
}

# Hide known file extensions
Function HideKnownExtensions {
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1

	" Hide file extensions `n" >> "windows_configuration.xml"
}

# Show hidden files
Function ShowHiddenFiles {
	Write-Output "Showing hidden files..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

	" Show hidden files `n" >> "windows_configuration.xml"
}

# Hide hidden files
Function HideHiddenFiles {
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2

	" Hide hidden items `n" >> "windows_configuration.xml"
}
# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
	Write-Output "Hiding recent shortcuts..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0

	" Hide recent shortcuts in explorer `n" >> "windows_configuration.xml"
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
	Write-Output "Showing recent shortcuts..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue

	" Show recent and frequent items in explorer  `n" >> "windows_configuration.xml"
}
# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

	" Hide 3D Objects from Explorer `n" >> "windows_configuration.xml"
}

# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer {
	Write-Output "Showing 3D Objects icon in Explorer namespace..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue

	" Show 3D Objects from Explorer `n" >> "windows_configuration.xml"
}
##########
# Application Tweaks
##########

# Disable OneDrive
Function DisableOneDrive {
	Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

	" Hide 3D Objects from Explorer `n" >> "windows_configuration.xml"
}

# Enable OneDrive
Function EnableOneDrive {
	Write-Output "Enabling OneDrive..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue

	" OneDrive Enabled `n" >> "windows_configuration.xml"
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

	" OneDrive uninstalled `n" >> "windows_configuration.xml"
}

# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
	Write-Output "Installing OneDrive..."
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow

	" OneDrive installed `n" >> "windows_configuration.xml"
}
# Uninstall all default apps excpet MS Store
Function UninstallAllApps {
	Write-Output "Uninstalling all default apps except MS Store..."
	Get-AppxPackage -AllUsers | Where-Object {$_.name -notlike "*store*"} | Remove-AppxPackage

	" All default MS apps uninstalled `n" >> "windows_configuration.xml"
}
# Uninstall default Microsoft applications
Function UninstallMsftBloat {
	Write-Output "Uninstalling default Microsoft applications..."
	Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.PowerAutomateDesktop" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.XboxGameCallableUI" | Remove-AppxPackage -AllUsers
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage -AllUsers

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

	" MS Bloatware removed `n" >> "windows_configuration.xml"
}
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
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage

	" 3rd party bloatware removed `n" >> "windows_configuration.xml"
}
# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

	" Xbox features disabled `n" >> "windows_configuration.xml"
}

# Enable Xbox features
Function EnableXboxFeatures {
	Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue

	" Xbox features enabled `n" >> "windows_configuration.xml"
}
# Install Linux Subsystem - Applicable to 1607 or newer
Function InstallLinuxSubsystem {
	Write-Output "Installing Linux Subsystem..."
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
	}
	Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null

	" WSL Installed `n" >> "windows_configuration.xml"
}
# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
	Write-Output "Installing Hyper-V..."
	If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	} Else {
		Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	}

	" Hyper-V installed `n" >> "windows_configuration.xml"
}
##########
# Auxiliary Functions
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

# Wait for key press
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}
##########
# Parse parameters and apply tweaks
##########

# Normalize path to preset file
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}

# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }

##### Call functions ########

DisableTelemetry
EnableTelemetry
DisableWebSearch
EnableWebSearch
DisableAppSuggestions
EnableAppSuggestions
DisableLocationTracking
EnableLocationTracking
DisableFeedback
EnableFeedback
DisableTailoredExperiences
EnableTailoredExperiences
DisableAdvertisingID
EnableAdvertisingID
DisableCortana
EnableCortana
DisableErrorReporting
EnableErrorReporting
DisableDiagTrack
EnableDiagTrack
EnableRemoteDesktop
DisableRemoteDesktop
SetBIOSTimeUTC
SetBIOSTimeLocal
HideTaskbarSearch
ShowTaskbarSearchIcon
ShowTaskbarSearchBox
HideTaskView
ShowTaskView
HideTaskbarPeopleIcon
ShowTaskbarPeopleIcon
SetControlPanelSmallIcons
SetControlPanelLargeIcons
EnableNumlock
DisableNumlock
ShowKnownExtensions
HideKnownExtensions
ShowHiddenFiles
HideHiddenFiles
HideRecentShortcuts
ShowRecentShortcuts
Hide3DObjectsFromExplorer
Show3DObjectsInExplorer
DisableOneDrive
EnableOneDrive
UninstallOneDrive
InstallOneDrive
UninstallAllApps
UninstallMsftBloat
UninstallThirdPartyBloat
DisableXboxFeatures
EnableXboxFeatures
InstallLinuxSubsystem
InstallHyperV
RequireAdmin
WaitForKey
Restart
