<#
.SYNOPSIS
Bootstrapper that seek and download Evergreen application installer.

.DESCRIPTION
Performs download and execution of evergreen application installer from the Powershell Gallery
Minimal parameter requieres the name of the application that you wish to install
Default behavior will silent install the lastest x64 version 

.PARAMETER Application
Application Name you wish to install

.PARAMETER Architecture
Application Architecture. If omitted, it will default to x64

.PARAMETER Edition
Application Edition. may not apply to all application 

.PARAMETER DisableUpdate
Will disable all update mechanisme of Google Chrome after installation

.PARAMETER Uninstall
Will Silently uninstall any installed version of Google Chrome

.PARAMETER PreScriptURI
Will download and execute a script from github/gist before installing the application

.PARAMETER PostScriptURI
Will download and execute a script from github/gist after installing the application

.PARAMETER Log
Path to log file. If not specified will default to 
C:\Windows\Logs\EvergreenApplication\EverGreen-Installer.log 

.OUTPUTS
all action are logged to the log file specified by the log parameter

.EXAMPLE
C:\PS> .\BootStrap-EverGreenInstallation -Application GoogleChrome -Architecture x86

Download and silently Install the lastest x86 version of Google Chrome.

.EXAMPLE
C:\PS> .\BootStrap-EverGreenInstallation -Application GoogleChrome -DisableUpdate

Download and silently Install the lastest x64 version of Google Chrome.
And disable all update mechanism

.EXAMPLE
C:\PS> .\BootStrap-EverGreenInstallation -Application GoogleChrome -Uninstall

Uninstall any locally installed version of Google Chrome

.EXAMPLE
C:\PS> .\BootStrap-EverGreenInstallation -Application GoogleChrome -PostScriptURI https://gist.github.com/smuel1414/87ca0ab4544d95556c778908afad2f1d -GithubToken 992a03b2846cb2d1d3e323ca25f1e60e7caabf0a

Download and silently Install the lastest x64 version of Google Chrome,
Then download and execute the script from gist repo.

.EXAMPLE
Powershell.Exe -executionpolicy bypass -file BootStrap-EverGreenInstaller.ps1 -Application GoogleChrome -Architecture x64

Syntaxe for Intune Integration

.LINK
http://www.OSD-Couture.com

.NOTES
By Diagg/OSD-Couture.com - 
Twitter: @Diagg

Additional Credits
Get-ECKGithubContent function based on work by Darren J. Robinson 
https://blog.darrenjrobinson.com/searching-and-retrieving-your-github-gists-using-powershell/

X64 Relaunch based on work by Nathan ZIEHNERT
https://z-nerd.com/blog/2020/03/31-intune-win32-apps-powershell-script-installer/

Write-EckLog based on work by someone i could not remember (Feel free to reatch me if you recognize your code)

#>

##############
# Product Name: Greenstaller
# Publisher: OSD-Couture.com
# Product Code: 4ec8022d-0366-4909-8240-20c1c89e0d40
# Auto Update: YES
# By Diagg/OSD-Couture.com
# 
# Script Version:  0.37 - 08/06/2021 - Inital release 
# Script Version:  0.4 - 19/03/2022 - Fully reworked to support Module EndPointCloudKit.
# Script Version:  0.5 - 22/03/2022 - Script logic changed to support unstallation before installation, added parameter Channel to allow application selection by channel. 
# Script Version:  0.6 - 24/03/2022 - Removed Invoke-AsCurrentUser and Invoke-AsSystemNow Functions


#Requires -Version 5
#Requires -RunAsAdministrator 

[CmdletBinding()]
param(

        [Parameter(Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [ValidateSet("1Password","7zip","AdobeAcrobat","AdobeAcrobatReaderDC","AdobeBrackets","AdoptOpenJDK","Anki","AtlassianBitbucket","BISF","BitwardenDesktop","CitrixAppLayeringFeed",
        "CitrixApplicationDeliveryManagementFeed","CitrixEndpointManagementFeed","CitrixGatewayFeed","CitrixHypervisorFeed","CitrixLicensingFeed","CitrixReceiverFeed","CitrixSdwanFeed",
        "CitrixVirtualAppsDesktopsFeed","CitrixVMTools","CitrixWorkspaceApp","CitrixWorkspaceAppFeed","ControlUpAgent","ControlUpConsole","Cyberduck","dnGrep","FileZilla","Fork",
        "FoxitReader","Gimp","GitForWindows","GitHubAtom","GitHubRelease","GoogleChrome","Greenshot","Handbrake","JamTreeSizeFree","JamTreeSizeProfessional","KeePass","KeePassXCTeamKeePassXC",
        "LibreOffice","Microsoft.NET","Microsoft365Apps","MicrosoftAzureDataStudio","MicrosoftBicep","MicrosoftEdge","MicrosoftFSLogixApps","MicrosoftOneDrive","MicrosoftPowerShell",
        "MicrosoftPowerToys","MicrosoftSsms","MicrosoftTeams","MicrosoftVisualStudio","MicrosoftVisualStudioCode","MicrosoftWindowsPackageManagerClient","MicrosoftWvdBootloader",
        "MicrosoftWvdInfraAgent","MicrosoftWvdRemoteDesktop","MicrosoftWvdRtcService","MozillaFirefox","MozillaThunderbird","mRemoteNG","NETworkManager","NotepadPlusPlus","OpenJDK","OpenShellMenu",
        "OracleJava8","OracleVirtualBox","PaintDotNet","PDFForgePDFCreator","PeaZipPeaZip","ProjectLibre","RCoreTeamRforWindows","RingCentral","ScooterBeyondCompare","ShareX","Slack","StefansToolsgregpWin",
        "SumatraPDFReader","TeamViewer","TelegramDesktop","TelerikFiddlerEverywhere","Terminals","VastLimitsUberAgent","VercelHyper","VideoLanVlcPlayer","VMwareTools","Win32OpenSSH",
        "WinMerge","WinSCP","WixToolset","Zoom")]
        [Alias('app')]        
        [string]$Application,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [string]$GithubRepo = "https://github.com/Diagg/EverGreen-Application-Installer",


        [Parameter(ParameterSetName='Predownload', Mandatory = $true, Position = 0)]
        [string]$PreDownloadPath,

        [Parameter(ParameterSetName='Offline', Mandatory = $true, Position = 0)]
        [string]$InstallSourcePath,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [ValidateSet("x86", "x64")]
        [Alias('arch')]
        [string]$Architecture = "X64",

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]        
        [string]$Log = $("$env:Windir\Logs\Greenstaller\Intaller.log"),

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [Alias('lng')]        
        [string]$Language = $Null,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Alias('default')]
        [switch]$SetAsDefault = $true,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Alias('ent')]
        [switch]$EnterpriseMode,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [switch]$DisableUpdate,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]        
        [switch]$Uninstall,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [string]$GithubToken,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [string]$PreScriptURI,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [string]$PostScriptURI,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [string]$UpdatePolicyURI,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [Alias('Release','Branch')]
        [string]$Channel= "stable"
     )

##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$CurrentScriptName = $MyInvocation.MyCommand.Name
$CurrentScriptFullName = $MyInvocation.MyCommand.Path
$CurrentScriptPath = split-path $MyInvocation.MyCommand.Path
$Version = Select-String -Pattern "# Script Version:" -Path $Script:CurrentScriptFullName -CaseSensitive
$Version = $Version[$Version.count - 3].line.replace('# Script Version: ','').split("-").trim()
$ProductName = Select-String -Pattern "# Product Name:" -Path $Script:CurrentScriptFullName -CaseSensitive
$ProductName = $ProductName[$ProductName.count - 3].line.replace('# Product Name: ','').trim()
$Publisher = Select-String -Pattern "# Publisher:" -Path $Script:CurrentScriptFullName -CaseSensitive
$Publisher = $Publisher[$Publisher.count - 3].line.replace('# Publisher: ','').trim()
$ProductCode = Select-String -Pattern "# Product Code:" -Path $Script:CurrentScriptFullName -CaseSensitive
$ProductCode = $ProductCode[$ProductCode.count - 3].line.replace('# Product Code: ','').trim()
$AutoUpdate = Select-String -Pattern "# Auto Update:" -Path $Script:CurrentScriptFullName -CaseSensitive
$AutoUpdate = $AutoUpdate[$AutoUpdate.count - 3].line.replace('# Auto Update: ','').trim()

##== Relaunch in X64 if needed
if ( $PSHome -match 'syswow64')
    {
        foreach($k in $MyInvocation.BoundParameters.keys)
            {
                switch($MyInvocation.BoundParameters[$k].GetType().Name)
                    {
                        "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $argsString += "-$k " } }
                        "String"          { $argsString += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
                        "Int32"           { $argsString += "-$k $($MyInvocation.BoundParameters[$k]) " }
                        "Boolean"         { $argsString += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
                    }
            }

        $Process = Start-Process -FilePath "$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:CurrentScriptFullName)`" $($argsString)" -NoNewWindow -PassThru -Wait
        Exit $($process.ExitCode)
    }

##== Set Log path
If ($log -eq $("$env:Windir\Logs\Greenstaller\Intaller.log")) {$Log = $log.Replace(".log","-$Application.log")}
If (-not(Test-path $(split-path $Log))){New-Item -Path $(split-path $Log) -ItemType Directory -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}

##== Set Content path
$script:ContentPath = 'C:\ProgramData\ARI-DSI\Greenstaller-Content'
If (-not(Test-path $script:ContentPath)){New-Item -Path $script:ContentPath -ItemType Directory -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}

$Acl = Get-ACL $script:ContentPath
$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule($((Get-LocalGroup -SID S-1-5-32-545).Name),"modify","ContainerInherit,Objectinherit","none","Allow")
$Acl.AddAccessRule($AccessRule)
Set-Acl $script:ContentPath $Acl

##== Do that Omega supreme stuffs and load Includes, environment and dependancies
Try
    {
        If ((get-module 'EndpointCloudKit' -ListAvailable -OutVariable ECKMod).Version.Build -gt 11)
            {
                If(-not (get-module 'EndpointCloudKit')){$ECKMod | Sort-Object Version -Descending  | Select-Object -First 1|Import-module -Force}
                New-ECKEnvironment -LogPath $Log
                Initialize-ECKPrereq -Module "Evergreen" -ContentToLoad 'https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1' -ContentPath $script:ContentPath -LogPath $log
            }
        Else
            {
                $ScriptURI = "https://raw.githubusercontent.com/Diagg/EndPoint-CloudKit-Bootstrap/master/Initialize-ECKPrereq.ps1"
                $Fileraw = (Invoke-WebRequest -URI $ScriptURI -UseBasicParsing -ErrorAction Stop).content
                Invoke-Expression ("<#" + $Fileraw) -ErrorAction Stop
                Initialize-ECKPrereq -Module "Evergreen" -ContentToLoad 'https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1' -ContentPath $script:ContentPath -LogPath $log
            }
    }
catch 
    {Write-Error "[ERROR] Unable to load includes, Aborting !" ; Exit 1}


Try
    {
        ##== Local Constantes
        $AppDownloadDir = "$env:Public\Downloads\$Application"
        If ([String]::IsNullOrWhiteSpace($InstallSourcePath)){If(-not(Test-path $AppDownloadDir)){New-Item $AppDownloadDir -Force -ItemType Directory -ErrorAction SilentlyContinue|Out-Null}} 

        $StartupTime = [DateTime]::Now
        Write-EckLog "***************************************************************************************************" -Path $log
        Write-EckLog "***************************************************************************************************" -Path $log
        Write-EckLog "Release $((Select-String -Pattern "Version:" -Path $Script:CurrentScriptFullName -CaseSensitive).Line[0])" -Path $log
        Write-EckLog "Started processing time: [$StartupTime]" -Path $log
        Write-EckLog "Script Name: $CurrentScriptFullName" -Path $log
        Write-EckLog "Selected Application: $Application" -Path $log
        If ($Uninstall -ne $true) {Write-EckLog "Selected Application Architecture: $Architecture" -Path $log}
        Write-EckLog "***************************************************************************************************" -Path $log
        Write-EckLog "Powershell Home: $PSHOME" -Path $log
        Write-EckLog "Current Session ID: $PID" -Path $log
        Write-EckLog "Log Path: $log" -Path $log
        Write-EckLog "System Host Name: $($ECK.SystemHostName)" -Path $log
        Write-EckLog "System IP Address: $($ECK.SystemIPAddress)" -Path $log
        Write-EckLog "System OS version: Windows $($ECK.OSVersion) - Build $($ECK.OSBuild) ($($ECK.OsFriendlyName))" -Path $log
        Write-EckLog "System OS Architecture is x64: $($ECK.OSArchitectureIsX64)" -Path $log
        Write-EckLog "Logged on user: $($ECK.User)" -Path $log
        Write-EckLog "Logged on user UPN: $($ECK.UserUPN)" -Path $log
        Write-EckLog "Execution Context is Admin: $($ECK.UserIsAdmin)" -Path $log 
        Write-EckLog "Execution Context is System: $($ECK.UserIsSystem)" -Path $log
        Write-EckLog "Execution Context is TrustedInstaller: $($ECK.RunAsTrustedInstaller)" -Path $log 


        If ($Uninstall -eq $true)
            {Write-EckLog "Selected Action: Uninstallation" -Path $log}
        Elseif (-not([String]::IsNullOrWhiteSpace($InstallSourcePath)))
            {
                Write-EckLog "Selected Action: Installation from offline source" -Path $log
                Write-EckLog "Install Option: Offline location $InstallSourcePath" -Path $log
                $OfflineInstall = $true
            }
        ElseIf ($DisableUpdate -eq $true)
            {Write-EckLog "Install Option: Disabling update feature" -Path $log}
        ElseIf (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
            {
                Write-EckLog "Selected Action: Predownloading without installation" -Path $log
                Write-EckLog "Install Option: Download location $PreDownloadPath" -Path $log
            }           
        Else
            {Write-EckLog "Selected Action: Installation" -Path $log}
    

        ##== Download APP Data
        Write-EckLog "Retriving data from Github for Application $Application" -Path $log
        $AppDataCode = Get-ECKGithubContent -URI "$GithubRepo/blob/master/EverGreen%20Apps%20Installer/Applications-Data/$($Application.toUpper())-Data.ps1"
        Try 
            {
                If ($AppDataCode -ne $False){Invoke-Expression $AppDataCode -ErrorAction Stop} 
                Else{Write-EckLog "[Error] Unable to execute $Application data garthering, bad return code, Aborting !!!" -Type 3 -Path $log ; Exit} 
            }
        Catch 
            {
                Write-EckLog "[Error] Unable to execute $Application data garthering, logical error occurs, Aborting !!!" -Type 3 -Path $log
                Write-EckLog $Error[0].InvocationInfo.PositionMessage.ToString() -type 3 -Path $log
                Write-EckLog $Error[0].Exception.Message.ToString() -type 3 -Path $log
                Exit 1
            }


        ##############################
        #### Gather Informations
        ##############################
        $Script:AppInfo = Get-AppInfo -Architecture $Architecture -Language $Language -DisableUpdate $DisableUpdate.IsPresent -EnterpriseMode $EnterpriseMode.IsPresent -channel $Channel
        Get-AppInstallStatus

        If ($Script:AppInfo.AppIsInstalled -eq $true)
            {
                Write-EckLog "Version $($Script:AppInfo.AppInstalledVersion) of $Application detected!" -Path $log
                If ($Script:AppInfo.AppMustUninstallBeforeUpdate -eq $true){$Uninstall = $true}
            }
        Else
            {
                $AppInstallNow = $true
                Write-EckLog "No Installed version of $Application detected!" -Path $log
            }


        ##############################
        #### Pre-Script
        ##############################
        If ($PreScriptURI)
            {
                Write-EckLog "Invoking Prescript" -Path $log
                If ($GithubToken){$PreScript = Get-ECKGithubContent -URI $PreScriptURI -GithubToken $GithubToken} Else {$PreScript = Get-ECKGithubContent -URI $PreScriptURI}
                Try {Invoke-Command $PreScript}
                Catch {Write-EckLog "[Error] Prescript Failed to execute" -Type 3 -Path $log}
            }

        
        ###############################
        #### Application Uninstallation
        ###############################

        If (($Uninstall.IsPresent) -or ($Uninstall -eq $true) -or ($Script:AppInfo.AppMustUninstallBeforeUpdate -eq $true) -or ($Script:AppInfo.AppInstallArchitecture -ne $Script:AppInfo.AppArchitecture -and $Script:AppInfo.AppMustUninstallOnArchChange -eq $true))
            {
                If ($Script:AppInfo.AppIsInstalled -eq $False)
                    {Write-EckLog "Application $Application is not installed, nothing to uninstall ! All operation finished!!" -Path $log}
                Else
                    {
                        ##== Uninstall
                        Write-EckLog "Uninstalling $Application !" -Path $log
                        Write-EckLog "About to run $($Script:AppInfo.AppUninstallCMD) $($Script:AppInfo.AppUninstallParameters)" -Path $log
                        $Iret = (Start-Process $Script:AppInfo.AppUninstallCMD -ArgumentList $Script:AppInfo.AppUninstallParameters -Wait -Passthru).ExitCode
                        If ($Script:AppInfo.AppUninstallSuccessReturnCodes -contains $Iret)
                            {Write-EckLog "Application $Application - version $($Script:AppInfo.AppInstalledVersion) Uninstalled Successfully !!!" -Path $log}
                        Else
                            {Write-EckLog "[Warning] Application $Application - version $($Script:AppInfo.AppInstalledVersion) returned code $Iret while trying to uninstall !!!" -Type 2 -Path $log}

                        ##== Additionnal removal action
                        Write-EckLog "Uninstalling additionnal items !" -Path $log
                        Invoke-AdditionalUninstall
                        Remove-Item "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application" -Recurse -Force -ErrorAction SilentlyContinue
                    }
            }


        ##############################
        #### Application installation
        ##############################

        If ($InstallSourcePath){$AppInstallNow = $true}
        
        ##==Check for latest version
        $Script:AppEverGreenInfo = Get-EvergreenApp -Name $Application | Where-Object Architecture -eq $Architecture
        If (-not([string]::IsNullOrWhiteSpace($Script:AppInfo.AppInstallLanguage))){$Script:AppEverGreenInfo = $Script:AppEverGreenInfo|Where-Object Language -eq $Script:AppInfo.AppInstallLanguage}
        If (-not([string]::IsNullOrWhiteSpace($Script:AppInfo.AppInstallChannel))){$Script:AppEverGreenInfo = $Script:AppEverGreenInfo|Where-Object Channel -eq $Script:AppInfo.AppInstallChannel}

        ##==Check if we need to update
        $AppUpdateStatus = Get-AppUpdateStatus
        If ($AppUpdateStatus)
            {
                $AppInstallNow = $true
                Write-EckLog "New version of $($Script:AppInfo.AppInstallName) detected! Release version: $($Script:AppEverGreenInfo.Version)" -Path $log
            }    
        Else 
            {
                $AppInstallNow = $False
                Write-EckLog "Version Available online is similar to installed version, Nothing to install !" -Path $log
            } 

        ##==Download
        if (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
            {
                $PreDownloadPath = "$PreDownloadPath\$Application"
                If (-not(Test-path $PreDownloadPath))
                    {
                        $Iret = New-Item $PreDownloadPath -ItemType Directory -Force -ErrorAction SilentlyContinue
                        If ([string]::IsNullOrWhiteSpace($Iret)){Write-EckLog "[ERROR] Unable to create download folder at $PreDownloadPath, Aborting !!!" -Type 3 -Path $log ; Exit}
                    }
                
                $AppDownloadDir = $PreDownloadPath
                $AppInstallNow = $False
            }

        If (([String]::IsNullOrWhiteSpace($InstallSourcePath) -and $AppInstallNow -eq $True) -or (-not([String]::IsNullOrWhiteSpace($PreDownloadPath))))
            {
                Write-EckLog "Found $Application - version: $($Script:AppEverGreenInfo.version) - Architecture: $Architecture - Release Date: $($Script:AppEverGreenInfo.Date) available on Internet" -Path $log
                Write-EckLog "Download Url: $($Script:AppEverGreenInfo.uri)" -Path $log
                Write-EckLog "Downloading installer for $Application - $Architecture"  -Path $log
                $InstallSourcePath = $Script:AppEverGreenInfo|Save-EvergreenApp -Path $AppDownloadDir
                Write-EckLog "Successfully downloaded $( Split-Path $InstallSourcePath -Leaf) to folder $(Split-Path $InstallSourcePath)" -Path $log
            }

        ##==Install
        if ($AppInstallNow -eq $True)
            {
                ## Rebuild Parametrers
                Write-EckLog "Download directory: $InstallSourcePath" -Path $log
                If ((Test-Path $InstallSourcePath) -and (([System.IO.Path]::GetExtension($InstallSourcePath)).ToUpper() -eq $Script:AppInfo.AppExtension.ToUpper()))
                    {
                        $Script:AppInfo.AppInstallParameters = $Script:AppInfo.AppInstallParameters.replace("##APP##",$InstallSourcePath)
                        $Script:AppInfo.AppInstallCMD  = $Script:AppInfo.AppInstallCMD.replace("##APP##",$InstallSourcePath)
                    }
                Else
                    {Write-EckLog "[ERROR] Unable to find application at $InstallSourcePath or Filename with extension may be missing, Aborting !!!" -Type 3 -Path $log ; Exit}

                
                ## Execute Intall Program
                Write-EckLog "Installing $Application with command $($Script:AppInfo.AppInstallCMD) and parameters $($Script:AppInfo.AppInstallParameters)" -Path $log
                $Iret = (Start-Process $Script:AppInfo.AppInstallCMD -ArgumentList $Script:AppInfo.AppInstallParameters -Wait -Passthru).ExitCode
                If ($Script:AppInfo.AppInstallSuccessReturnCodes -contains $Iret)
                    {
                        Write-EckLog "Application $Application - version $($Script:AppEverGreenInfo.version) Installed Successfully !!!" -Path $log
                        $Script:AppInfo.AppArchitecture = $Architecture.ToUpper()
                        $Script:AppInfo.AppInstalledVersion = $($Script:AppEverGreenInfo.version)
                    }
                Else
                    {Write-EckLog "[ERROR] Application $Application - version $($Script:AppEverGreenInfo.version) returned code $Iret while trying to Install !!!" -Type 3 -Path $log}


                ##== Install Additionnal Componants
                Write-EckLog "Installing additionnal Componants !" -Path $log
                Invoke-AdditionalInstall -SetAsDefault $SetAsDefault.IsPresent -EnterpriseMode $EnterpriseMode.IsPresent


                ## Clean Download Folder
                if ([String]::IsNullOrWhiteSpace($PreDownloadPath) -and $OfflineInstall -ne $true )
                    {
                        Write-EckLog "cleaning Download folder" -Path $log
                        If (test-path $InstallSourcePath){Remove-Item $InstallSourcePath -recurse -Force -Confirm:$false -ErrorAction SilentlyContinue}
                    }
            }

 
        ##== Remove Update capabilities
        If ($DisableUpdate -and [String]::IsNullOrWhiteSpace($PreDownloadPath))
            {
                Write-EckLog "Disabling $Application update feature !" -Path $log
                Invoke-DisableUpdateCapability
            }



        If ([String]::IsNullOrWhiteSpace($PreDownloadPath))
            {
                ##== Tag registry
                Get-AppInstallStatus
                Write-EckLog "Tagging in the registry !" -Path $log
                
                $RegTag = "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application"

                $Tags = [PSCustomObject]@{
                    GreenAppName = $Application
                    InstallDate = $([DateTime]::Now)
                    Version = $($Script:AppInfo.AppInstalledVersion)
                    Architecture = $($Script:AppInfo.AppArchitecture)
                    Status = 'UpToDate'
                }

                If (-not([string]::IsNullOrWhiteSpace($Script:AppInfo.AppInstallLanguage))){$Tags|Add-Member -MemberType NoteProperty -Name 'Language' -Value $($Script:AppInfo.AppInstallLanguage) -Forcel}
                New-ECKTag -Regpath $RegTag -TagsObject
                

                ##== Create Scheduled task
                Write-EckLog "Creating Update Evaluation Scheduled Task !" -Path $log
                $ScriptBlock_UpdateEval = {

                    Get-Module 'EndpointCloudkit' -ListAvailable | Sort-Object Version -Descending  | Select-Object -First 1|Import-module -Force -Global -PassThru
                    $LogPath = "C:\Windows\Logs\Greenstaller\Evergreen-ApplicationUpdateEvaluation.log"
                    New-ECKEnvironment -LogPath $LogPath

                    ##== Main
                    $StartupTime = [DateTime]::Now
                    Write-EckLog 
                    Write-EckLog "***************************************************************************************************"
                    Write-EckLog "***************************************************************************************************"
                    Write-EckLog "Started processing time: [$StartupTime]"
                    Write-EckLog "Script Name: ApplicationUpdateEvaluation"
                    Write-EckLog "***************************************************************************************************"

                    $RegTag = "HKLM:\SOFTWARE\OSDC\EverGreenInstaller"
                    If (test-path $RegPath)
                        {
                            $EverGreenApps = (Get-ChildItem $RegTag).PSChildName

                            ForEach ($Regitem in $EverGreenApps)
                                {
                                    $AppInfo = Get-ItemProperty -Path "$RegTag\$Regitem"
                                    If (-not ([string]::IsNullOrWhiteSpace($AppInfo)))
                                        {
                                            Write-EckLog "Application : $Regitem"
                                            $AppInstalledVersion = $AppInfo.DisplayVersion
                                            $AppInstalledArchitecture = $AppInfo.Architecture
                                            Write-EckLog "Installed version : $AppInstalledVersion"

                                            Write-EckLog "Checking for Newer version online..."
                                            $AppEverGreenInfo = Get-EvergreenApp -Name $Regitem | Where-Object Architecture -eq $AppInstalledArchitecture
                                            Write-EckLog "Latest version available online: $($AppEverGreenInfo.Version)"

                                            If ([version]($AppEverGreenInfo.Version) -gt [version]$AppInstalledVersion)
                                                {
                                                    Set-ItemProperty "$RegTag\$Regitem" -name 'Status' -Value "Obsolete" -force|Out-Null
                                                    Write-EckLog "$Regitem application status changed to Obsolete !"
                                                }
                                        }
                                }
                            }

                    $FinishTime = [DateTime]::Now
                    Write-EckLog "***************************************************************************************************"
                    Write-EckLog "Finished processing time: [$FinishTime]"
                    Write-EckLog "Operation duration: [$(($FinishTime - $StartupTime).ToString())]"
                    Write-EckLog "All Operations Finished!! Exit !"
                    Write-EckLog "***************************************************************************************************"  
                }

                ## Run ScriptBlock
                $trigger = New-JobTrigger -Daily -At 12:00
                Invoke-ECKScheduledTask -TaskName "Greenstaller Update Evaluation" -$NormalTaskName -triggerObject $trigger -ScriptBlock $ScriptBlock_UpdateEval
                Write-EckLog "Update Evaluation Scheduled task installed successfully under name $Taskname!"          
            }
  

        ##############################
        #### Post-Script
        ##############################
        If ($PostScriptURI)
            {
                Write-EckLog "Invoking Postscript" -LogPath $log
                If ($GithubToken){$PostScript = Get-ECKGithubContent -URI $PostScriptURI -GithubToken $GithubToken} Else {$PostScript = Get-ECKGithubContent -URI $PostScriptURI}
                Try {Invoke-Expression $PostScript -ErrorAction Stop}
                Catch {Write-EckLog "[Error] Postscript Failed to execute" -Type 3 -Path $log}
            }

        $FinishTime = [DateTime]::Now
        Write-EckLog "***************************************************************************************************" -Path $log
        Write-EckLog "Finished processing time: [$FinishTime]" -Path $log
        Write-EckLog "Operation duration: [$(($FinishTime - $StartupTime).ToString())]" -Path $log
        Write-EckLog "All Operations for $Application Finished!! Exit !" -Path $log
        Write-EckLog "***************************************************************************************************" -Path $log
        Exit 0 
     }   
Catch
    {
        Write-EckLog "[ERROR] Fatal Error, the program has stopped !!!" -Type 3 -Path $log
        Write-EckLog $Error[0].InvocationInfo.PositionMessage.ToString() -type 3 -Path $log
        Write-EckLog $Error[0].Exception.Message.ToString() -type 3 -Path $log
        Exit 99
    }           