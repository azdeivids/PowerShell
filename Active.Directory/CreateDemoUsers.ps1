#Start logging script output
Start-Transcript -Path "$Temp\$ScriptName.log" -Force

$Server = "$($Env:Computername).$($Env:UserDnsDomain.ToLower())"

Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Stop

$Domain = Get-ADDomain -Server $Server

$DomainDN = $Domain.DistinguishedName

$Forest = $Domain.Forest

$UserGroupParentOUName = Read-Host "What is the user group parent OU name"

$UserParentOUName = Read-Host "What is the name of the parent OU"

If ((Get-ADOrganizationalUnit -Filter "Name -eq `"$UserGroupParentOUName`"" -Server $Server -ErrorAction SilentlyContinue)) 
{
    Get-ADOrganizationalUnit -Filter "Name -eq `"$UserGroupParentOUName`"" -SearchScope SubTree -Server $Server | Set-ADObject -ProtectedFromAccidentalDeletion:$True -Server $Server -PassThru
    Write-Host "" 
}
Else 
{
    New-ADOrganizationalUnit -Name $UserGroupParentOUName -Path $DomainDN -Verbose -Server $Server -ErrorAction Stop

    $GroupParentOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$UserGroupParentOUName`"" -Server $Server
    
    $IntakeYear = Read-Host "What is the user intake year"

    $GroupOU = New-ADOrganizationalUnit -Name $IntakeYear -Path $GroupParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Stop

    New-ADGroup -Name "$IntakeYear" -SamAccountName "$IntakeYear" -GroupCategory Security -GroupScope Global -Path $GroupOU.DistinguishedName -Description "Groups Synched with Google Apps" -Verbose -OtherAttributes @{"Mail"="$($IntakeYear.Replace(' ',''))@$($Forest)"} -Server $Server -PassThru
    Write-Host ""
}

If ((Get-ADOrganizationalUnit -Filter "Name -eq `"$UserParentOUName`"" -Server $Server -ErrorAction SilentlyContinue))
{
    Get-ADOrganizationalUnit -Filter "Name -eq `"$UserParentOUName`"" -SearchScope SubTree -Server $Server | Set-ADObject -ProtectedFromAccidentalDeletion:$False -Server $Server -PassThru | Remove-ADOrganizationalUnit -Confirm:$True -Server $Server -Recursive -Verbose
    Write-Host ""
}
Else
{
    New-ADOrganizationalUnit -Name $UserParentOUName -Path $DomainDN -Verbose -Server $Server -ErrorAction Stop

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$UserParentOUName`"" -Server $Server

    $UserOU = New-ADOrganizationalUnit -Name "$IntakeYear" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Stop

    $UserCount = 1000

    #Initial Password for all users
    $InitialPassword = Read-Host "Provide the password used during account creation:" 
    
    $Content = Import-CSV -Path "$($ScriptDir)\$($ScriptName).csv" -ErrorAction Stop | Get-Random -Count $UserCount | Sort-Object -Property State

    $Users = $Content | Select-Object `
        @{Name="Name";Expression={"$($_.Surname), $($_.GivenName)"}},`
        @{Name="Description";Expression={"User account for $($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="SamAccountName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)"}},`
        @{Name="UserPrincipalName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)@$($Forest)"}},`
        @{Name="GivenName"; Expression={$_.GivenName}},`
        @{Name="Surname"; Expression={$_.Surname}},`
        @{Name="DisplayName"; Expression={"$($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="IntakeYear"; Expression={$_.IntakeYear}},`
        @{Name="EmailAddress"; Expression={"$($_.IntakeYear.Substring($_.IntakeYear.Length - 2))$($_.GivenName.ToCharArray()[0])($_.Surname)@$($Forest)"}},`
        @{Name="AccountPassword"; Expression={ (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force)}},`
        @{Name="Department"; Expression={$_.Department},`
        @{Name="Enabled"; Expression={$True}},`
        @{Name="PasswordNeverExpires"; Expression={$True}}
    }
 
    Write-Host ""

    ForEach ($User In $Users) {
        
    }

    ForEach ($User In $Users)
        {
       
            $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.IntakeYear)`"" -SearchBase $DepartmentOU.DistinguishedName -Server $Server

            $CreateADUser = $User | Select-Object -Property @{Name="Path"; Expression={$DestinationOU.DistinguishedName}}, * | New-ADUser -Verbose -Server $Server -PassThru
    
            $AddADUserToGroup = Add-ADGroupMember -Identity $User.IntakeYear -Members $User.SamAccountName -Server $Server -Verbose

            Write-Host ""
        }
    
    # ForEach ($Department In $Departments.Name)
    #     {
    #         $DepartmentManager = Get-ADUser -Filter {(Title -eq "Student") -and (Department -eq $Department)} -Server $Server | Sort-Object | Select-Object -First 1
    #         $SetDepartmentManager = Get-ADUser -Filter {(Department -eq $Department)} | Set-ADUser -Manager $DepartmentManager -Verbose
    #     }

    Write-Host ""
}

#Stop logging script output 
$($NewLine)
# Write-Warning -Message "Run `'$($ScriptName).ps1`' twice if nothing happens initially. This is due to the OU deletion confirmation prompt."
Stop-Transcript