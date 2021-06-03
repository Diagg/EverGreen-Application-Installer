#Powershell.exe -executionpolicy bypass -command "$P=$ENV:TEMP+'\'+$(new-guid)+'.ps1';(Invoke-WebRequest 'https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1').content|Out-File $P -Encoding UTF8 -width 320;$A = @('-Application','GoogleChrome','-Architecture','x64','-SetAsDefault');Iex ""$P $A"""
#Powershell.exe -executionpolicy bypass -command "$P=$ENV:TEMP+'\'+$(new-guid)+'.ps1';(Invoke-WebRequest 'https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1').content|Out-File $P -Encoding UTF8 -width 320;$A = @('-Application', 'GoogleChrome', '-Uninstall');Iex ""$P $A"""



$install ={
# Install Google Chrome
$Path = "$($ENV:TEMP)\$(new-guid).ps1"
$ScriptFromGitHub = (Invoke-WebRequest 'https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1').content
$ScriptFromGitHub|Out-File -FilePath $Path -Encoding UTF8 -width 320
$argumentList = @('-Application', 'GoogleChrome', '-Architecture', 'x64', '-SetAsDefault')
Invoke-Expression "$Path $argumentList"
}

$Uninstall ={
# UnInstall Google Chrome
$Path = "$($ENV:TEMP)\$(new-guid).ps1"
$ScriptFromGitHub = (Invoke-WebRequest 'https://raw.githubusercontent.com/Diagg/EverGreen-Application-Installer/master/EverGreen Apps Installer/BootStrap-EverGreenInstaller.ps1').content
$ScriptFromGitHub|Out-File -FilePath $Path -Encoding UTF8 -width 320
$argumentList = @('-Application', 'GoogleChrome', '-Uninstall')
Invoke-Expression "$Path $argumentList"
}

Write-Host "Install command:"
$Encoded =[convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($install))
Write-Host "Lenght: $($Encoded.Length) (must be less than 8000)"
Write-host ' '
Write-Host "Powershell.exe -EncodedCommand $Encoded"
Write-host ' '

Write-Host "UnInstall command:"
$Encoded =[convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($Uninstall))
Write-Host "Lenght: $($Encoded.Length) (must be less than 8000)"
Write-host ' '
Write-Host "Powershell.exe -EncodedCommand $Encoded" 