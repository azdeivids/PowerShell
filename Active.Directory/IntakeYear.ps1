#Perform the following actions.
    $Server = "$($Env:Computername).$($Env:UserDnsDomain.ToLower())"
    
    Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Stop
    
    $Domain = Get-ADDomain -Server $Server
    
    $DomainDN = $Domain.DistinguishedName
    
    $Forest = $Domain.Forest

# TODO: Must Create additional grooup here    
# This will be 'Google_Groups'.
    $UserGroupParentOUName = Read-Host "Group organizational unit for which to perform the check"

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq '$UserGroupParentOUName'" -Server $Server -ErrorAction SilentlyContinue
    if ($ParentOU) 
    {
        $ParentOUPath = $ParentOU.DistinguishedName
    } 
    else 
    {
        Write-Host "Parent OU '$UserGroupParentOUName' not found. Exiting..."
        exit
    }

    $IntakeYear = Read-Host "What is the user intake year"

# Check if the group already exists
    $GroupExists = Get-ADGroup -Filter "Name -eq '$IntakeYear'" -SearchBase $ParentOUPath -Server $Server -ErrorAction SilentlyContinue

    if ($GroupExists) 
    {
        Write-Host "Group '$IntakeYear' already exists. Skipping group creation."
    } 
    else 
    {
        try {
            # Create the group
            New-ADGroup -Name $IntakeYear -SamAccountName $IntakeYear -GroupCategory Security -GroupScope Global -Path $ParentOUPath -Description "Groups Synched with Google Apps" -Verbose -OtherAttributes @{"Mail"="$($IntakeYear.Replace(' ',''))@$Forest"} -Server $Server -PassThru
            Write-Host "Group '$IntakeYear' created."
        } catch {
            Write-Host "Failed to create group. Error: $_"
        }
    }

    Write-Host ""

# This will be SHS-Users
    $StudentOUName = Read-Host "User organizational unit for which to perform the check"

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq '$StudentOUName'" -Server $Server -ErrorAction SilentlyContinue
    if ($ParentOU) 
    {
        $ParentOUPath = $ParentOU.DistinguishedName
    } 
    else 
    {
        Write-Host "Parent OU '$StudentOUName' not found. Exiting..."
        exit
    }    

# // TODO: OU is Created in the students OU, whic does not work.
# Check if the OU already exists
    $IntakeOU = Get-ADOrganizationalUnit -Filter "Name -eq '$IntakeYear'" -SearchBase $ParentOUPath -SearchScope Subtree -Server $Server -ErrorAction SilentlyContinue

    if ($IntakeOU) 
    {
        Write-Host "OU '$IntakeYear' already exists. Skipping OU creation."
    }
    else 
    {
        try {
            # Create the OU
            $IntakeOU = New-ADOrganizationalUnit -Name $IntakeYear -Path $ParentOUPath -Verbose -PassThru -Server $Server -ErrorAction Stop
            Write-Host "OU '$IntakeYear' created."
        } catch {
            Write-Host "Failed to create OU. Error: $_"
        }

#Initial Password for all users
    $InitialPassword = Read-Host "Provide the password used during account creation"
    
    $Content = Import-CSV -Path "$($ScriptDir)\$($ScriptName).csv" -ErrorAction Stop

    $Users = $Content | Select-Object `
            @{Name="Name";Expression={"$($_.Surname), $($_.GivenName)"}},`
            @{Name="Description";Expression={"Intake @$($IntakeYear)"}},`
            @{Name="SamAccountName"; Expression={"$($IntakeYear.ToString().Substring(2))$($_.GivenName.Substring(0,1))$($_.Surname)"}},`
            @{Name="UserPrincipalName"; Expression={"$($IntakeYear.ToString().Substring(2))$($_.GivenName.Substring(0,1))$($_.Surname)@$($Forest)"}},`
            @{Name="GivenName"; Expression={$_.GivenName}},`
            @{Name="Surname"; Expression={$_.Surname}},`
            @{Name="DisplayName"; Expression={"$($_.GivenName) $($_.Surname)"}},`
            @{Name="EmailAddress"; Expression={"$($IntakeYear.ToString().Substring(2))$($_.GivenName.Substring(0,1))$($_.Surname)@$($Forest)"}},`
            @{Name="AccountPassword"; Expression={ (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force)}},`
            @{Name="Enabled"; Expression={$True}},`
            @{Name="PasswordNeverExpires"; Expression={$True}}
        }

        Write-Host ""

        foreach ($User in $Users) {

            $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq '$IntakeYear'" -SearchBase $ParentOU.DistinguishedName -Server $Server

            $CreateADUser = $User | Select-Object -Property @{Name="Path"; Expression={$DestinationOU.DistinguishedName}}, * | New-ADUser -Verbose -Server $Server -PassThru

            $AddADUserToGroup = Add-ADGroupMember -Identity $User.IntakeYear -Members $User.SamAccountName -Server $Server -Verbose

            Write-Host ""
        }

#Stop logging script output 
    $($NewLine)
#Write-Warning -Message "Run `'$($ScriptName).ps1`' twice if nothing happens initially. This is due to the OU deletion confirmation prompt."
    Stop-Transcript