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


.LINK
http://www.OSD-Couture.com

.NOTES
By Diagg/OSD-Couture.com - 
Twitter: @Diagg

Additional Credits
Get-GistContent by Darren J. Robinson 
https://blog.darrenjrobinson.com/searching-and-retrieving-your-github-gists-using-powershell/



Release date: 09/03/2021
Version: 0.2
#>

#Requires -Version 4
#Requires -RunAsAdministrator 

[CmdletBinding()]
param(

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName='Online')]
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
        [string]$Application,

        [Parameter(ParameterSetName='Predownload', Mandatory = $true, Position = 0)]
        [string]$PreDownloadPath,

        [Parameter(ParameterSetName='Offline', Mandatory = $true, Position = 0)]
        [string]$InstallSourcePath,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]
        [ValidateSet("x86", "x64")]
        [string]$Architecture = "X64",

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [Parameter(ParameterSetName = 'Predownload')]        
        [string]$Log,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]
        [switch]$DisableUpdate,

        [Parameter(ParameterSetName = 'Online')]
        [Parameter(ParameterSetName = 'Offline')]        
        [switch]$Uninstall,

        [Parameter(ParameterSetName = 'Online')]
        [string]$GithubToken,

        [Parameter(ParameterSetName = 'Online')]
        [string]$PreScriptURI,

        [Parameter(ParameterSetName = 'Online')]
        [string]$PostScriptURI
     )

##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$Script:CurrentScriptName = $MyInvocation.MyCommand.Name
$Script:CurrentScriptFullName = $MyInvocation.MyCommand.Path
$Script:CurrentScriptPath = split-path $MyInvocation.MyCommand.Path

##== Local Variables
$Script:SystemHostName = [System.Environment]::MachineName
$Script:SystemIPAddress = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -AddressState Preferred).IPAddress
$Script:SystemOSversion = [System.Environment]::OSVersion.VersionString
$Script:SystemOSArchitectureIsX64 = [System.Environment]::Is64BitOperatingSystem
$Script:UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Script:UserIsAdmin = (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$Script:UserIsSystem = [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem 


##== Functions
function Write-log 
    {
         Param(
              [parameter()]
              [String]$Path=$Script:log,

              [parameter(Position=0)]
              [String]$Message,

              [parameter()]
              [String]$Component=$Script:CurrentScriptName,

		      #Severity  Type(1 - Information, 2- Warning, 3 - Error)
		      [parameter(Mandatory=$False)]
		      [ValidateRange(1,3)]
		      [Single]$Type = 1
        )

		# Create Folder path if not present
        $oFolderPath = Split-Path $Path
		If (-not (test-path $oFolderPath)){New-Item -Path $oFolderPath -ItemType Directory -Force|out-null}

        # Create a log entry
        $Content = "<![LOG[$Message]LOG]!>" +`
            "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +`
            "date=`"$(Get-Date -Format "M-d-yyyy")`" " +`
            "component=`"$Component`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$Type`" " +`
            "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
            "file=`"`">"

        # Write the line to the log file
        Add-Content -Path $Path -Value $Content -Encoding UTF8 -ErrorAction SilentlyContinue
    }


Function Get-GithubContent
    {
        param(

            [Parameter(Mandatory = $true, Position=0)]
            [string]$URI,
            
            [string]$GithubToken,

            [string]$ScriptName
         )
        
        <#
         If ($PreScriptURI)
            {
                $URI = $PreScriptURI
                $ScriptName = 'Pre-Script.ps1'
            } 
        Else 
            {
                $URI = $PostScriptURI
                $ScriptName = 'Post-Script.ps1'                
            }
        #>

        If([string]::IsNullOrWhiteSpace($GithubToken))
            {
                ## This a public Repo/Gist

                If($URI -like '*/gist.github.com*')
                    {
                        ##This is a Gist
                        $URI = $URI.replace("gist.github.com","gist.githubusercontent.com")
                        If ($URI.Split("/")[$_.count-1] -notlike '*raw*'){$URI = "$URI/raw"}
                    }
                ElseIf($URI -like '*//gist.githubusercontent.com*')
                    {
                        ##This is a Github raw content
                    }
                ElseIf($URI -like '*/github.com*')
                    {
                        ##This is a Github repo
                        $URI = $URI.replace("github.com","raw.githubusercontent.com")
                        $URI = $URI.replace("blob/","")
                    } 
                ElseIf($URI -like '*/raw.githubusercontent.com*')
                    {
                        ##This is a Github raw content
                    }
                Else
                    {
                       Write-Error "[ERROR] Unsupported URI $URI, Aborting !!!"
                       Return $false     
                    } 

                
                Try 
                    {
                        $Fileraw = Invoke-WebRequest -URI $URI
                        $Fileraw = $fileraw.Content
                    }
                Catch
                    {
                        Write-Error "[ERROR] Unable to get script content, Aborting !!!" 
                        Write-Error $Error[0].InvocationInfo.PositionMessage.ToString()
                        Write-Error $Error[0].Exception.Message.ToString()
                        $Fileraw = $False
                    }
                
                Return $fileraw
            }
        Else
            {
                ## This a private Repo/Gist




                # Authenticate 
                $clientID = $URI.split("/")[3]
                $GistID = $URI.split("/")[4]
        
                # Basic Auth
                $Bytes = [System.Text.Encoding]::utf8.GetBytes("$($clientID):$($GithubToken)")
                $encodedAuth = [Convert]::ToBase64String($Bytes)

                $Headers = @{Authorization = "Basic $($encodedAuth)"; Accept = 'application/vnd.github.v3+json'}
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $githubURI = "https://api.github.com/user"

                $githubBaseURI = "https://api.github.com"
                $auth = Invoke-RestMethod -Method Get -Uri $githubURI -Headers $Headers -SessionVariable GITHUB -ErrorAction SilentlyContinue

                if ($auth) 
                    {
                        If($URI -like '*/gist.github.com*')
                            { 
                                # Get my GISTS
                                $myGists = Invoke-RestMethod -method Get -Uri "$($githubBaseURI)/users/$($clientID)/gists" -Headers $Headers -WebSession $GITHUB
                                $script = $myGists | Select-Object | Where-Object {$_.id -eq $GistID}
            
                                if ($script)
                                    {
                                        foreach ($fileObj in ($script.files| Get-Member  | Where-Object {$_.memberType -eq "NoteProperty"}))
                                            {
                                                $File = $fileObj.definition

                                                $File = $File -split("@")
                                                $File = ($File[1]).replace("{","").replace("}","")
                                                $File = ($File.split(";")).trim()|ConvertFrom-StringData

                                                # Get File
                                                If (($File.Filename).ToUpper() -eq $ScriptName.ToUpper())
                                                    {
                                                        $rawURL = $File.raw_url
                                                        $fileraw = Invoke-RestMethod -Method Get -Uri $rawURL -WebSession $GITHUB
                                                        Return $fileraw  
                                                    } 
                                            }
                                    }
                            }
                        ElseIf($URI -like '*/github.com*')
                            {

                                Function Local:Explore-Repo
                                    {
                                        param (
                                            [Parameter( Position = 0, Mandatory = $True )]
                                            [String]$Path
                                        )



                                        $myGithubRepos = Invoke-RestMethod -method Get -Uri $path -Headers $Headers -WebSession $GITHUB

	                                    $files = $myGithubRepos | where {$_.type -eq "file"}
	                                    $directories = $myGithubRepos | where {$_.type -eq "dir"}

                                        $directories | ForEach-Object {Explore-Repo -path ($_._links).self}
        
                                        foreach ($file in $files) 
                                            {
                                                If (($File.Name).toUpper() -eq $ScriptName.ToUpper())
                                                    {
                                                        $rawURL = $File.download_url
                                                        $fileraw = Invoke-RestMethod -Method Get -Uri $rawURL -WebSession $GITHUB
                                                        $fileraw
                                                        break
                                                    }
                                            }
                                        Return
                                    }
                                
                                # Get my GItHub
                                $SelectedFile = Explore-Repo -path "$($githubBaseURI)/repos/$($clientID)/$($GistID)/contents"
                                Return $SelectedFile
                            }
                        Else
                            {
                               Write-Error "[ERROR] Unsupported URI $URI, Aborting !!!"
                               Return $false  
                            }
                    }
                Else
                    {
                        Write-Error "[ERROR] Unable to authenticate to github, Aborting !!!" 
                        Write-Error $Error[0].InvocationInfo.PositionMessage.ToString()
                        Write-Error $Error[0].Exception.Message.ToString()
                    }
            }
    }


Function Invoke-AsSystemNow
    {
        Param(
                [Parameter(Mandatory = $true)]
                [scriptblock]$ScriptBlock
            )
        
        $TaskName = "EverGreen Installer"
        $SchedulerPath = "\Microsoft\Windows\PowerShell\ScheduledJobs"
        $trigger = New-JobTrigger -AtStartup
        $options = New-ScheduledJobOption -StartIfOnBattery  -RunElevated

        $task = Get-ScheduledJob -Name $taskName  -ErrorAction SilentlyContinue
        if ($null -ne $task){Unregister-ScheduledJob $task -Confirm:$false}

        Register-ScheduledJob -Name $taskName  -Trigger $trigger  -ScheduledJobOption $options -ScriptBlock $ScriptBlock|Out-Null
        $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount  -RunLevel Highest
        Set-ScheduledTask -TaskPath $SchedulerPath -TaskName $taskName -Principal $principal|Out-Null
        Start-Job -DefinitionName $taskName|Out-Null

        $attempts = 1
        While ((get-job -Name $taskname).State -ne "Completed" -or $attempts -le 15)
            {
                Start-Sleep -Seconds 1
                $attempts += 1
            }

        If ((get-job -Name $taskname).State -eq "Completed")
            {
                Unregister-ScheduledJob $TaskName -Confirm:$false
                Return $true
            }
        Else
            {
                Write-log "[Error] Scheduled job with name $TaskName, returned with status $((get-job -Name $taskname).State)"
                Unregister-ScheduledJob $TaskName -Confirm:$false
                Return $false                        
            }
    }


Function Initialize-Prereq
    {
        Try 
            {
                ## Set Tls to 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                ## Add Scripts path to $env:PSModulePath
                $CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
                If ($CurrentValue -notlike "*C:\Program Files\WindowsPowerShell\scripts*") {[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + [System.IO.Path]::PathSeparator + "C:\Program Files\WindowsPowerShell\Scripts", "Machine")}


                ## install providers
                If (-not(Test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"))
                    {
                        Write-log "Nuget provider is not to up to date, Installing Latest version !"
                        Install-PackageProvider -Name 'nuget' -Force |Out-Null
                    }

                Write-log "Nuget provider installed version: $(((Get-PackageProvider -Name 'nuget'|Sort-Object|Select-Object -First 1).version.tostring()))"
        
                If ((Get-PSRepository -Name "PsGallery").InstallationPolicy -ne "Trusted"){Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted}                
                If ([version]((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()) -lt [version]"2.2.5" )
                    {
                        Write-log "Powershell provider is not to up to date, Installing Latest version !"
                        Install-Module -Name PowerShellGet -MinimumVersion 2.2.5 -Force
                    }
        
                Import-Module PowershellGet
                Write-log "PowershellGet module installed version: $(((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()))"
            } 
        Catch 
            {Write-log "[Error] Unable to install default providers, Aborting!!!" -type 3 ; Exit}


        ##== Get evergreen
        Try 
            {
                If ($null -eq (Get-module -Name "evergreen" -ListAvailable))
                    {
                        Write-log "Installing Evergreen Module"
                        Install-Module "Evergreen" -MinimumVersion 2104.337 -force
                    }
                Else 
                    {
                        Write-log "Updating Evergreen Module"
                        Update-Module "evergreen" 
                    }

                Import-Module "Evergreen"    
                Write-log "Evergreen module installed version: $(((Get-Module Evergreen|Sort-Object|Select-Object -First 1).version.tostring()))"
            }
        Catch
            {Write-log "[Error] Unable to install Evergreen, Aborting!!!" ; Exit}
    } 


##== Initializing Environement
If (-not [string]::IsNullOrWhiteSpace($Log))
    {$Script:Log = $Log}
Else    
    {$Script:Log = $("$env:Windir\Logs\EvergreenApplication\EverGreen-" + $Application + "_" + $Architecture + "_" + "Intaller.log")}

$StartupTime = [DateTime]::Now
Write-log 
Write-log "***************************************************************************************************"
Write-log "***************************************************************************************************"
Write-log "Started processing time: [$StartupTime]"
Write-log "Script Name: $CurrentScriptName"
Write-log "Selected Application: $Application"
Write-log "Selected Application Architecture: $Architecture"
Write-log "***************************************************************************************************"
Write-log "Log Path: $log"
Write-log "System Host Name: $SystemHostName"
Write-log "System IP Address: $SystemIPAddress"
Write-log "System OS version: $SystemOSversion"
Write-log "System OS Architecture is x64: $SystemOSArchitectureIsX64"
Write-Log "User Name: $UserName"
Write-Log "User is Admin: $UserIsAdmin" 
Write-Log "User is System: $UserIsSystem" 



If ($Uninstall -eq $true){Write-log "Selected Action: Uninstallation"}
else{Write-log "Selected Action: Installation"}

If ($DisableUpdate -eq $true){Write-log "Install Option: Disabling update feature"}

##== Init        
Initialize-Prereq

##== Download APP Data
Write-Log "Retriving data from Github for Application $Application"
$AppDataCode = Get-GithubContent -URI "https://github.com/Diagg/EverGreen-Application-Installer/blob/master/EverGreen%20Apps%20Installer/Applications-Data/$Application-Data.ps1"
Try 
    {
        If ($AppDataCode -ne $False) 
            {
                $AppDataScriptPath = "$($env:temp)\Github-GoogleChrome-Data.ps1"
                $AppDataCode|Out-File $AppDataScriptPath
                ."$AppDataScriptPath"
            } 
        Else
            {Write-log "[Error] Unable to execute $Application data garthering, bad return code, Aborting !!!" -Type 3 ; Exit} 
    }
Catch 
    {
        Write-log "[Error] Unable to execute $Application data garthering, logical error occurs, Aborting !!!" -Type 3
        Write-log $Error[0].InvocationInfo.PositionMessage.ToString() -type 3
        Write-log $Error[0].Exception.Message.ToString() -type 3
        Exit
    }

##############################
#### Pre-Script
##############################
If ($PreScriptURI -and $GithubToken)
    {
        Write-log "Invoking Prescript"
        $PreScript = Get-GistContent -PreScriptURI $PreScriptURI -GithubToken $GithubToken
        Try {Invoke-Command $PreScript}
        Catch {Write-log "[Error] Prescript Failed to execute" -Type 3}
    }


##############################
#### Application installation
##############################


$SeekApp = Find-Script -Name $Application -ErrorAction SilentlyContinue
If (-not([String]::IsNullOrWhiteSpace($SeekApp)))
    {Install-Script $SeekApp -NoPathUpdate  -ErrorAction SilentlyContinue}
Else    
    {Write-log "[Error] Unable to find $Application on PoweShell Gallery, Aborting !!!" -Type 3 ; Exit}


$AppInfo = Get-InstalledScript -Name $SeekApp.Name
$Command = $(".\" + $AppInfo.Name + ".Ps1" + " -Log " + $Global:Log + " -Architecture " + $Architecture + " -DontPrecheck")
$Command = $(".\Invoke-EverGreenGoogleChrome.ps1" + " -Log " + $Global:Log + " -Architecture " + $Architecture + " -DontPrecheck")

If ($DisableUpdate) {$Command += " -DisableUpdate"}
If ($Uninstall) {$Command += " -Uninstall"}        

Write-log "Launching command $Command"

$CurrentLoc = Get-Location
Set-Location $AppInfo.InstalledLocation
Invoke-Expression -Command $Command
Set-Location $currentLoc

##############################
#### Post-Script
##############################
If ($PostScriptURI -and $GithubToken)
    {
        Write-log "Invoking Postscript"
        $PostScript = Get-GistContent -PreScriptURI $PreScriptURI -GithubToken $GithubToken
        Try {Invoke-Command $PostScript}
        Catch {Write-log "[Error] Postscript Failed to execute" -Type 3}
    }


$FinishTime = [DateTime]::Now
Write-log "***************************************************************************************************"
Write-log "Finished processing time: [$FinishTime]"
Write-log "Migration duration: [$(($FinishTime - $StartupTime).ToString())]"
Write-log "All Operations for $Application Finished!! Exit !"
Write-log "***************************************************************************************************"    