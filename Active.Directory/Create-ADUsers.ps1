<#
.SYNOPSIS
Create Active Directory users in bulk from a CSV file.
.DESCRIPTION
Create Active Directory users in bulk from a CSV file.
.PARAMETER filepath
The path and file name to the CSV containing the details for account creation. This parameter is mandatory.
.PARAMETER upnsuffix
The UPN suffix to be added to the user. Will be used for their email address field as well. This parameter is mandatory.
.PARAMETER OrganizationalUnit
Path to the Organizational Unit in Active Directory where all the users should be placed during the creation. This parameter is mandatory.
.PARAMETER ADGroup
Group name where the users are to be joined. Can accept multiple values. This parameter is optional.
.PARAMETER Credentials
Password to be set for the users during the account creation. 
.PARAMETER PasswordReset
Enable or disabled the option for the created users to reset their password.
.EXAMPLE
~.\Create-ADUsers.ps1 -Csv \\dc2k22\Folder\sub-folder\Newusers.csv -OU 'ou=NewUsers,ou=AllUsers,dc=deividsegle,dc=com' -Group 'cn=UserGroup,ou=SecurityGroup,dc=deividsegle,dc=com' -Upn deividsegle.com

This will read the contents within the CSV file and create the users within the NewUser Organizational Unit. All the new users will be part of the UserGroup. All the user UPNs will be newuser@deividsegle.com
It is implied at the begning that the script is executed from the user home drive eg. C:\Users\deivids\Create-ADUsers.ps1, and that the CSV file is stored within a share on the domain controler.

~.\Create-ADUsers.ps1 -Csv \\dc2k22\Folder\sub-folder\Newusers.csv -OU 'ou=NewUsers,ou=AllUsers,dc=deividsegle,dc=com' -Upn deividsegle.com

This will do the same as the command above, except the users will not be placed in any specified groups.

~.\Create-ADUsers.ps1 -Csv \\dc2k22\Folder\sub-folder\Newusers.csv -OU 'ou=NewUsers,ou=AllUsers,dc=deividsegle,dc=com' -Upn deividsegle.com -PasswordReset $True

This will do the same as the command above; additionaly, the users will be forced to reset their password during the initial login. Set to $False to disable the option.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [Alias("Csv")]
    $filepath,
    [Parameter(Mandatory=$True)]
    [Alias("Upn")]
    $upnsuffix,
    [Parameter(Mandatory=$True)]
    [Alias("OU")]
    $OrganizationalUnit,
    [Alias("Group")]
    $ADGroup,
    [Alias("Dept")]
    $Department,
    [Alias("Password")]
    $Credentials,
    $PasswordReset
)
If (Test-Path -LiteralPath $filepath)
{

    $UserCSV = Import-Csv -Path $filepath


    ForEach ($User in $UserCSV)
    {
        $Displayname = $User.Firstname + " "  + $User.Lastname
        $UserFirstName = $User.Firstname
        $UserLastName = $User.Lastname
        $samAccountName = $User.samAccountName
        $Upn = $samAccountName + "@$upnsuffix"
        $Credentials = $User.Credentials

        $ValidateUser = Get-ADUser -Filter "samAccountName -eq '$samAccountName'"

        If ($ValidateUser -eq $null)
        {
            New-ADUser -Name $DisplayName -DisplayName $Displayname -GivenName $UserFirstName -Surname $UserLastName -SamAccountName $samAccountName -UserPrincipalName $upn -Department $Department -EmailAddress $upn -ChangePasswordAtLogon $PasswordReset -AccountPassword (ConvertTo-SecureString $Credentials -AsPlainText) -Enabled $true -PasswordNeverExpires $False -Verbose

            If ($AdGroup)
            {
                Add-ADGroupMember -Identity "$AdGroup" -Members $samAccountName -Verbose
            }
        }

        else 
        {
            Write-Host "User $samAccountName already exists."
        }
    }
}

else 
{
     Write-Host "There is no user list to work with." -ForegroundColor Magenta
}


.\Create-ADUsers.ps1 -Csv C:\scripts\Newusers.csv -OU 'OU=HR,OU=Department,OU=Users,OU=Org,DC=deividsegle,DC=com' -Upn 'deividsegle.com'