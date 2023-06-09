# Set the domain name and administrator password
$DomainName = "deividsegle.com"
$AdminPassword = Read-Host "Enter the domain administrator password."

# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote the server to a domain controller
$PromotionParams = @{
    Credential = (Get-Credential -Message "Enter the credentials of a domain administrator")
    DomainName = $DomainName
    NoRebootOnCompletion = $true
}
Install-ADDSForest @PromotionParams -SafeModeAdministratorPassword (ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force)

# Restart the server if required
if ((Get-ADDomainController -Filter * | Measure-Object).Count -eq 0) {
    Restart-Computer -Force
}