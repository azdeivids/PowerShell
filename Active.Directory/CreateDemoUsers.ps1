$Server = "$($Env:Computername).$($Env:UserDnsDomain.ToLower())"

Import-Module -Name 'ActiveDirectory' -Force -NoClobber -ErrorAction Stop

$Domain = Get-ADDomain -Server $Server

$DomainDN = $Domain.DistinguishedName

$Forest = $Domain.Forest

If ((Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -Server $Server -ErrorAction SilentlyContinue))
{
    Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -SearchScope SubTree -Server $Server | Set-ADObject -ProtectedFromAccidentalDeletion:$False -Server $Server -PassThru | Remove-ADOrganizationalUnit -Confirm:$True -Server $Server -Recursive -Verbose
    Write-Host ""
}
Else
{
    # Set-ADDefaultDomainPasswordPolicy $Forest -ComplexityEnabled $False -MaxPasswordAge "1000" -PasswordHistoryCount 0 -MinPasswordAge 0 -Server $Server
    
    New-ADOrganizationalUnit -Name $ParentOUName -Path $DomainDN -Verbose -Server $Server -ErrorAction Stop

    $ParentOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$ParentOUName`"" -Server $Server

    $UserOU = New-ADOrganizationalUnit -Name "Users" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Stop
    $GroupOU = New-ADOrganizationalUnit -Name "Groups" -Path $ParentOU.DistinguishedName -Verbose -PassThru -Server $Server -ErrorAction Stop

    $InitialPassword = Read-Host "Provide the password used during account creation:" #Initial Password for all users

    $Company = Read-Host "Provide the company name:"
    
    $Content = Import-CSV -Path "$($ScriptDir)\$($ScriptName).csv" -ErrorAction Stop | Get-Random -Count $UserCount | Sort-Object -Property State

    $YearGroup =  Read-Host "Provide the year group:"

    $Users = $Content | Select-Object `
        @{Name="Name";Expression={"$($_.Surname), $($_.GivenName)"}},`
        @{Name="Description";Expression={"User account for $($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="SamAccountName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)"}},`
        @{Name="UserPrincipalName"; Expression={"$($_.GivenName.ToCharArray()[0])$($_.MiddleInitial)$($_.Surname)@$($Forest)"}},`
        @{Name="GivenName"; Expression={$_.GivenName}},`
        @{Name="Surname"; Expression={$_.Surname}},`
        @{Name="DisplayName"; Expression={"$($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},`
        @{Name="State"; Expression={$_.State}},`
        @{Name="YearGroup"; Expression={$_.YearGroup}},`
        @{Name="EmailAddress"; Expression={"$($_.YearGroup.Substring($_.YearGroup.Length - 2))$($_.GivenName.ToCharArray()[0])($_.Surname)@$($Forest)"}},`
        @{Name="AccountPassword"; Expression={ (ConvertTo-SecureString -String $InitialPassword -AsPlainText -Force)}},`
        @{Name="Department"; Expression={$_.Department},`
        @{Name="Enabled"; Expression={$True}},`
        @{Name="PasswordNeverExpires"; Expression={$True}}
    }
 
    New-ADGroup -Name "$YearGroup" -SamAccountName "$YearGroup" -GroupCategory Security -GroupScope Global -Path $GroupOU.DistinguishedName -Description "Security Group for all $YearGroup users" -Verbose -OtherAttributes @{"Mail"="$($YearGroup.Replace(' ',''))@$($Forest)"} -Server $Server -PassThru

    Write-Host ""

    ForEach ($User In $Users)
        {
            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Department)`"" -SearchBase $UserOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $Department = New-ADOrganizationalUnit -Name $User.Department -Path $UserOU.DistinguishedName -Department $User.Department -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $DepartmentOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.YearGroup)`"" -Server $Server
                }

            If (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.YearGroup)`"" -SearchBase $DepartmentOU.DistinguishedName -Server $Server -ErrorAction SilentlyContinue))
                {
                    $YearGroupOU = New-ADOrganizationalUnit -Name $User.YearGroup -Path $DepartmentOU.DistinguishedName -YearGroup $User.YearGroup -Department $User.Department -Verbose -Server $Server -PassThru
                    Write-Host ""
                }
            Else
                {
                    $YearGroupOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.YearGroup)`"" -Server $Server
                }
       
            $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.YearGroup)`"" -SearchBase $DepartmentOU.DistinguishedName -Server $Server

            $CreateADUser = $User | Select-Object -Property @{Name="Path"; Expression={$DestinationOU.DistinguishedName}}, * | New-ADUser -Verbose -Server $Server -PassThru
    
            $AddADUserToGroup = Add-ADGroupMember -Identity $User.YearGroup -Members $User.SamAccountName -Server $Server -Verbose

            Write-Host ""
        }
    
    ForEach ($Department In $Departments.Name)
        {
            $DepartmentManager = Get-ADUser -Filter {(Title -eq "Student") -and (Department -eq $Department)} -Server $Server | Sort-Object | Select-Object -First 1
            $SetDepartmentManager = Get-ADUser -Filter {(Department -eq $Department)} | Set-ADUser -Manager $DepartmentManager -Verbose
        }

    Write-Host ""
}

#Stop logging script output 
$($NewLine)
Write-Warning -Message "Run `'$($ScriptName).ps1`' twice if nothing happens initially. This is due to the OU deletion confirmation prompt."
Stop-Transcript