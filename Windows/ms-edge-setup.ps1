############# MS Edge Tweaks ###############

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

# Add Azure to excluded sleeping tabs
Function EdgeExcludeAzureFromSleep {
    Write-Output "Excluding portal.azure.com from tab inactivity policy..."
    If
}