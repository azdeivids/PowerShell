"############################################### SOFTWARE ISNTALLATION LOG ############################################### `n" >> "software_installation.log"

Function Install-Software {
	# Bypass ExecutionPolicy and install Chocolatey if not installed
	if (!(Get-Command choco.exe -ErrorAction SilentlyContinue)) {
		Set-ExecutionPolicy Bypass -Scope Process -Force
		Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

		" Installation of Chocolatey done `n" >> "software_installation.log"
	}
    
    choco install adobereader --params '"/UpdateMode:4"' -y
    choco install googlechrome -y
    choco install firefox --params '"/NoTaskbarShortcut /NoDesktopShortcut /RemoveDistributionDir"' -y
    choco install python3 -y
    choco install 7zip -y
    choco install vlc -y
    choco install notepadplusplus -y
    choco install git --params '"/NoGitLfs /SChannel"' -y
    choco install vscode --params '/NoDesktopIcon' -y
    choco install putty -y
    choco install pdfcreator --ia '"/NOICONS /TASKS=!winexplorer"' -y
    choco install spotify -y
    choco install winscp -y
    choco install wireshark -y
    choco install nmap -y
    choco install azure-cli -y
    choco install terraform -y
    choco install kubernetes-cli -y
    choco install kubernetes-helm -y
    choco install dotnetfx --pre -y
    choco install docker-desktop -y
    choco install signal --params '"/NoTray /NoShortcut"' -y
    choco install microsoftazurestorageexplorer -y
    choco install whatsapp -y
    choco install qbittorrent -y
    choco install fiddler -y
    choco install speedtest -y
    choco install cpu-z -y
    choco install starship -y
    choco install icloud -y
    choco install sysinternals -y
    choco install powertoys -y
    choco install googledrive -y
    choco install google-workspace-sync -y
    choco install obsidian -y
    choco install rufus -y
    choco install advanced-ip-scanner -y
    choco install brave -y
    choco install nodejs -y
    choco install nerdfont-hack -y
    choco install rsat -y
    choco install teamviewer9 -y

    " Adobe Reader installed `n" >> "software_installation.log"
    " Google Chrome installed `n" >> "software_installation.log"
    " Firefox browser installed `n" >> "software_installation.log"
    " Python 3 `n" >> "software_installation.log"
    " 7zip installed `n" >> "software_installation.log"
    " VLC installed `n" >> "software_installation.log"
    " Notepad++ installed `n" >> "software_installation.log"
    " Git installed `n" >> "software_installation.log"
    " VSCode installed `n" >> "software_installation.log"
    " PuTTy installed `n" >> "software_installation.log"
    " PDF Creator installed `n" >> "software_installation.log"
    " Spotify installed `n" >> "software_installation.log"
    " WinSCP installed `n" >> "software_installation.log"
    " Wireshark installed `n" >> "software_installation.log"
    " nmap installed `n" >> "software_installation.log"
    " Azure CLI installed `n" >> "software_installation.log"
    " Terraform installed `n" >> "software_installation.log"
    " Kubectl installed `n" >> "software_installation.log"
    " Helm installed `n" >> "software_installation.log"
    " MS .NET Framework installed installed `n" >> "software_installation.log"
    " Docker desktop installed `n" >> "software_installation.log"
    " Signal installed `n" >> "software_installation.log"
    " Azure Storage Explorer installed `n" >> "software_installation.log"
    " Whatsapp installed `n" >> "software_installation.log"
    " qBittorrent installed `n" >> "software_installation.log"
    " Fiddler installed `n" >> "software_installation.log"
    " Speedtest installed `n" >> "software_installation.log"
    " CPU-Z installed `n" >> "software_installation.log"
    " starship installed `n" >> "software_installation.log"
    " iCloud installed `n" >> "software_installation.log"
    " sysinternals installed `n" >> "software_installation.log"
    " power toys installed `n" >> "software_installation.log"
    " googledrive installed `n" >> "software_installation.log"
    " google workspace sync installed `n" >> "software_installation.log"
    " obsidian markdown installed `n" >> "software_installation.log"
    " rufus installed `n" >> "software_installation.log"
    " advanced IP scanner installed `n" >> "software_installation.log"
    " brave browser installed `n" >> "software_installation.log"
    " Node JS installed installed `n" >> "software_installation.log"
    " Nerd Hack Fonts installed `n" >> "software_installation.log"
    " RSAT Tools installed `n" >> "software_installation.log"
    " Team Viewer installed `n" >> "software_installation.log"

    $UnifiSearchUrl = "https://github.com/Crypto-Spartan/unifi-search-tool/releases/download/2.0.1/unifi-search-tool_v2.0.1.exe"
    $UnifiSearchUrlOutpath = "unifi-search-tool.exe"

    Invoke-WebRequest -Uri $UnifiSearchUrl -OutFile $UnifiSearchUrlOutpath
    Write-Output "Downloading Crypto Spartan UniFi Search tool..."
    .\unifi-search-tool.exe
    
    " unifi-search-tool installed `n" >> "software_installation.log"

    Start-Sleep -Seconds 30
    Remove-Item .\unifi-search-tool.exe -Force

    Invoke-RestMethod get.scoop.sh | Invoke-Expression
    " scoop isntalled `n" >> "software_installation.log"

    "############################################### SOFTWARE ISNTALLATION LOG ############################################### `n" >> "software_installation.log"
}