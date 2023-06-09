#Perform the following actions.
    $Server = "$($Env:Computername).$($Env:UserDnsDomain.ToLower())"
    
    Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Stop
    
    $Domain = Get-ADDomain -Server $Server
    
    $DomainDN = $Domain.DistinguishedName
    
    $Forest = $Domain.Forest

# This will be 'Google_Groups'.
    $UserGroupParentOUName = Read-Host "Group organizational unit for which to perform the check"

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq '$UserGroupParentOUName'" -Server $Server -ErrorAction SilentlyContinue
    if ($ParentOU) {
        $ParentOUPath = $ParentOU.DistinguishedName
    } else {
        Write-Host "Parent OU '$UserGroupParentOUName' not found. Exiting..."
        exit
    }

    $IntakeYear = Read-Host "What is the user intake year"

    # Check if the group already exists
    $GroupExists = Get-ADGroup -Filter "Name -eq '$IntakeYear'" -SearchBase $ParentOUPath -Server $Server -ErrorAction SilentlyContinue

    if ($GroupExists) {
        Write-Host "Group '$IntakeYear' already exists. Skipping group creation."
    } else {
        try {
            # Create the group
            New-ADGroup -Name $IntakeYear -SamAccountName $IntakeYear -GroupCategory Security -GroupScope Global -Path $ParentOUPath -Description "Groups Synched with Google Apps" -Verbose -OtherAttributes @{"Mail"="$($IntakeYear.Replace(' ',''))@$Forest"} -Server $Server -PassThru
            Write-Host "Group '$IntakeYear' created."
        } catch {
            Write-Host "Failed to create group. Error: $_"
        }
    }

    Write-Host ""