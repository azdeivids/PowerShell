Add-PSSnapIn Specops.Adx,Specops.Gpupdate -ErrorAction:0

$logFile = 'C:\Scripts\Startup Scripts\HR Daily Startup.csv'

$OUFilter = Get-AdComputer -Filter * -SearchBase "OU=HR,OU=Staff,OU=Desktops,OU=Workstations,DC=msdeivids,DC=local"

# Get all computers where the command succeeded, and add a timestamp to each one of them
$successful = @()
$successful += Get-SpecopsADComputer -name:$OUFilter.Name | 
               Sort-Object -Property:Name | 
               Start-SpecopsComputer -PassThru -ErrorAction:SilentlyContinue -ErrorVariable:cmdErrors | 
               Add-Member -MemberType NoteProperty -Name:Timestamp -Value:(get-Date) -Passthru

# Figure out what properties to use in the log file
$logProperties = @('Name','Status')
if ($successful){
   $logProperties += $successful | Get-Member -MemberType NoteProperty | ForEach { $_.Name }
   $successful | Add-Member -MemberType:NoteProperty -Name:Status -Value:Success
}
if ($cmdErrors){
   $logProperties += 'ErrorMessage'
   $cmdErrorComputers = $cmdErrors | ForEach { $_.TargetObject | 
      Add-Member -MemberType:NoteProperty -Name:Status -Value:Error -Passthru |
      Add-Member -MemberType:NoteProperty -Name:ErrorMessage -Value:$_.Exception.Message -Passthru
   } | 
   Sort-Object -Property:Name
}

# Export to the log file
$result = $successful + $cmdErrorComputers
if ($result){
   $result | Select-Object -Property:$logProperties | 
   Export-Csv -Path $logFile -NoTypeInformation

}

# throw if there are errors to make PowerShell return with a non-zero exit code.
if ($cmdErrors){
   throw "Error exists. Check log file at $logFile"
}
