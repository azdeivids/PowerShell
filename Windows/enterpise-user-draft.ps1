<#
.DESCRIPTION
    These function will configure and disable (gray out) the options entierly. Might be more suitable for enterpise setup rather than Home or Pro use as
    you would have to get back in registry to re-configure the settings.
#>


#######################################################################################################
#
# 		Privacy Tweaks
#
#######################################################################################################



# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.
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

# Disable cloud content search entierly
Function DisableCloudContentSearch {
	Write-Output "Cloud content search being disabled..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0

	" Cloud content search disabled `n" >> "windows_configuration.log"
}

Function EnableCloudContentSearch {
	Write-Output "Cloud content search being enabled..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 1

	" Cloud content search Enabled `n" >> "windows_configuration.log"
}

# Let user configure cloud content search
Function UserCloudContentSearch {
	Write-Output "Cloud content search left to user choice..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -ErrorAction SilentlyContinue

	" Cloud contetnt search set to default `n" >> "windows_configuration.log"
}

# Enable Search Highlight
Function EnableSearchHighlights {
	Write-Output "Enabling search highlights..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 1
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
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -ErrorAction SilentlyContinue

	" Search highlights disabled `n" >> "windows_configuration.log"
}

# Restrict Windows Update P2P delivery optimization to computers in local network - Default since 1703
Function SetP2PUpdateLocal {
	Write-Output "Restricting Windows Update P2P optimization to local network..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1
	} Else {
		# Method used since 1703
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	}
}

# Unrestrict Windows Update P2P delivery optimization to both local networks and internet - Default in 1507 - 1607
Function SetP2PUpdateInternet {
	Write-Output "Unrestricting Windows Update P2P optimization to internet..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 3
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	} Else {
		# Method used since 1703
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 3
	}
}

# Disable Windows Update P2P delivery optimization completely
# Warning: Completely disabling delivery optimization can break Windows Store downloads - see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/281
Function SetP2PUpdateDisable {
	Write-Output "Disabling Windows Update P2P optimization..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
	} Else {
		# Method used since 1511
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 100
	}
}

#######################################################################################################
#
# 		Application Tweaks
#
#######################################################################################################



# Disable Shared Experiences completely - Not applicable to Server
Function DisableSharedExperiences {
	Write-Output "Disabling Shared Experiences..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
    }
    Set-ItemPropert -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0

    " Shared experiance value set and setting disabled `n" >> "windows_configuration.log"
}

# Enable Shared Experiences - Not applicable to Server
Function EnableSharedExperiences {
	Write-Output "Enabling Shared Experiences..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "CdpSessionUserAuthzPolicy" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 1

    " Shared app experiance enabled `n" >> "windows_configuration.log"
}


