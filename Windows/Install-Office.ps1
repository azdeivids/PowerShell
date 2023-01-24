#Get computers to install office on
$Computers = (Get-ADComputer -Filter * -SearchBase "OU=wcps,OU=computers,OU=student,OU=ict,DC=wcps,DC=co.uk").Name
ForEach ($Computer in $Computers)
{
	Write-Host "Working on $Computer" -ForegroundColor White
	
	Write-Host "Testing connectivity to $Computer" -ForegroundColor White
	$HostUp = Test-Connection -ComputerName $Computer -BufferSize 12 -Count 1
	If (!($HostUp))
	{
		Write-Warning -Message "Remote Host is not accessible!"	}
	Else
	{
		Write-Host "Connection successful!" -ForegroundColor Green
		$items = Get-Item -Path 'D:\software\MS Office*'
		Write-Host "Creating Office folder on $Computer" -ForegroundColor Yellow
		New-Item -Path \\$computer\c$\Office -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
		foreach ($item in $items)
		{
			Write-Host "Copying $Item over to $Computer\c$\Office\" -ForegroundColor Yellow
			Copy-Item -Path $item -Destination \\$Computer\C$\Office\ -Force
		}
		Write-Host "Starting installation on $Computer" -ForegroundColor White
		
		Invoke-Command -ScriptBlock { set-location "C:\Office\"; .\setup.exe /configure configuration.xml } -ComputerName $Computer -AsJob
	}
}
Get-Job | Format-Table