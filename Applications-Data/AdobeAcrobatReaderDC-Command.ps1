# Install
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/Greenstaller/master/Greenstaller.ps1',$P);;Iex ""$P -Application AdobeAcrobatReaderDC -Language French -Architecture x86 -SetAsDefault"""

#Uninstall
#Powershell.exe -executionpolicy bypass -command "$P=$($env:temp+'\'+(New-guid)+'.Ps1');(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Diagg/Greenstaller/master/Greenstaller.ps1',$P);Iex ""$P -Application AdobeAcrobatReaderDC -Uninstall"""
