# Install
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1',$P);;Iex ""$P -Application AdobeAcrobatReaderDC -Language French -Architecture x86 -SetAsDefault"""

#Uninstall
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1',$P);Iex ""$P -Application AdobeAcrobatReaderDC -Uninstall"""

#Stage without install
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1',$P);Iex ""$P -Application AdobeAcrobatReaderDC -PreDownloadPath 'C:\temp' -Language French -Architecture x86"""

#Install staged content
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1',$P);Iex ""$P -Application AdobeAcrobatReaderDC -InstallSourcePath 'C:\temp\AdobeAcrobatReaderDC\App.exe' -SetAsDefault"""