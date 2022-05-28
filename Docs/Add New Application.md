# Adding support for new application

## Prerequists

On a development computer,  install Powershell modules Evergreen and Nevergreen
```powershell
Install-Module EverGreen 
Import-module EverGreen

Install-Module NeverGreen 
Import-module Nevergreen
```

## Find the name of your application

Both modules uses concatenated names to identify application.  
To find the name you should use with EverGreen type ```(Find-EvergreenApp).Name```:
```powershell
(Find-EvergreenApp).Name

1Password
7zip
7ZipZS
AdobeAcrobat
AdobeAcrobatReaderDC
AdobeBrackets
AdoptiumTemurin11
AdoptiumTemurin16
...
```
To find the name you should use with NeverGreen type ```Find-NevergreenApp```:
```powershell
Find-NevergreenApp

8x8Work
AdobeAcrobat
AdobeAcrobatReader
AdobeCreativeCloud
AdobeDigitalEditions
AdvancedInstaller
AdvancedIPScanner
AdvancedPortScanner
...
```
Once the name is found, copy the file ```TEMPLATEDEFAULT-Data.ps1``` and replace ```TEMPLATEDEFAULT``` with the name you've just found. The name must be in upper case.

Ex: if the app. name is 7zip, the renamed file should be ```7ZIP-Data.ps1```

## Editing data file

The data file is the core component regarding application installation, it's built around six functions that will take care of the following aspect:

#### Getting application infos

###### Get-AppInfo function:  
Define default parameters if nothing is specified  
Define Install/Uninstall command lines.  
Define Friendly name.  
Define preferred languages, Architecture, Release Channel.  
Define return code.  
Define install option (Standard/NoUpdate/Enterprise).  

###### Get-AppInstallStatus function:
If application is already installed, Gather info on it.

###### Get-AppUpdateStatus function:
If application is already installed, check if it needs update.  



#### Additional Installation/Uninstallation

###### Invoke-AdditionalInstall Function:
Set Default File association.
Apply 'Default'Settings.
Apply 'No update' settings if selected.
Apply 'Enterprise' settings if selected.

###### Invoke-AdditionalUnInstall Function:
Restore File association.
Remove clutter that uninstall does not handle.

