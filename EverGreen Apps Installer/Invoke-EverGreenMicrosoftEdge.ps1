<#
.SYNOPSIS
Download and install Latest version of Microsoft Edge.

.DESCRIPTION
Performs download, silent installation, silent uninstallation and installation
with disabled update of the lastest version of Microsoft Edge using the EverGreen Module.
Default behavior without parameters will silent install x64 version of the latest Microsoft Edge

.PARAMETER Architecture
Microsoft Edge Architecture. If omitted, it will default to x64

.PARAMETER DisableUpdate
Will disable all update mechanisme of Microsoft Edge after installation

.PARAMETER Uninstall
Will Silently uninstall any installed version of Microsoft Edge

.PARAMETER PreDownloadPath
Will only download Microsoft Edge to specified path, if Architecture is omited, it will default to x64

.PARAMETER InstallSourcePath
Will only install Microsoft Edge from the specified source path

.PARAMETER Log
Path to log file. If not specified will default to 
C:\Windows\Logs\EvergreenApplication\EverGreen-MicrosoftEdge.log 

.OUTPUTS
all action are logged to the log file specified by the log parameter

.EXAMPLE
C:\PS> .\Invoke-EverGreenMicrosoftEdge -Architecture x86

Download and silently Install the lastest x86 version of Microsoft Edge.

.EXAMPLE
C:\PS> .\Invoke-EverGreenMicrosoftEdge -DisableUpdate

Download and silently Install the lastest x64 version of Microsoft Edge.
And disable all update mechanism

.EXAMPLE
C:\PS> .\Invoke-EverGreenMicrosoftEdge -Uninstall

Uninstall any locally installed version of Microsoft Edge

.LINK
http://www.OSD-Couture.com

.NOTES
By Diagg/OSD-Couture.com - 
Twitter: @Diagg

Release date: 04/07/2021
Version: 0.913 
#>

#Requires -Version 4
#Requires -RunAsAdministrator 

[CmdletBinding()]
param(
        [Parameter(ParameterSetName='Online')]
        [Parameter(ParameterSetName='Predownload')]
        [ValidateSet("x86", "x64")]
        [string]$Architecture = "X64",

        [Parameter(ParameterSetName='Online')]
        [Parameter(ParameterSetName='Offline')]
        [Parameter(ParameterSetName='Predownload')]
        [string]$Log,

        [Parameter(ParameterSetName='Online')]
        [Parameter(ParameterSetName='Offline')]
        [Parameter(ParameterSetName='Predownload')]
        [switch]$DontPrecheck,
        
        [Parameter(ParameterSetName='Online')]
        [Parameter(ParameterSetName='Offline')]
        [switch]$DisableUpdate,
        
        [Parameter(ParameterSetName='Online')]
        [Parameter(ParameterSetName='Offline')]
        [switch]$Uninstall,

        [Parameter(ParameterSetName='Predownload', Mandatory = $true, Position = 0)]
        [string]$PreDownloadPath,

        [Parameter(ParameterSetName='Offline', Mandatory = $true, Position = 0)]
        [string]$InstallSourcePath
     )

##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$Script:CurrentScriptName = $MyInvocation.MyCommand.Name
$Script:CurrentScriptFullName = $MyInvocation.MyCommand.Path
$Script:CurrentScriptPath = split-path $MyInvocation.MyCommand.Path

$AppDownloadDir = "$env:Public\Downloads"
$AppName = "MicrosoftEdge"
$AppExtension = ".msi"
$AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
$AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$AppInstallCMD = "MsiExec"
$AppInstallParameters = "/i ##APP## ALLUSERS=1 /qb"
$AppInstallSuccessReturnCodes = @(0,3010)
$AppUninstallSuccessReturnCodes = @(0,3010)

If ([string]::IsNullOrWhiteSpace($Log)){$Log = "$env:Windir\Logs\EvergreenApplication\EverGreen-$($AppName.Replace(' ','')).log"}


##== Function
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



##== Initializing Environement
$StartupTime = [DateTime]::Now
Write-log 
Write-log "***************************************************************************************************"
Write-log "***************************************************************************************************"
Write-log "Started processing time: [$StartupTime]"
Write-log "Script Name: $CurrentScriptName"
Write-log "***************************************************************************************************"
Write-log "Application: $AppName"
Write-log "***************************************************************************************************"
Write-log "log: $log"

IF (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
    {Write-log "Action requested: Pre-Downloading $AppName to $PreDownloadPath"}
ElseIf(-not([String]::IsNullOrWhiteSpace($InstallSourcePath)))
    {Write-log "Action requested: Installation with local source $InstallSourcePath"}
ElseIf ($Uninstall -eq $true)
    {Write-log "Action requested: UnInstallation"}
Else
    {Write-log "Action requested: Installation with online source"}

If ($DisableUpdate -eq $true){Write-log "Install Option: Disabling update feature"}

If(($Uninstall -ne $true) -and [String]::IsNullOrWhiteSpace($InstallSourcePath))
    {     
        ### Check Pre Reqs
        If ($DontPrecheck -ne $true)
            { 
                ## Set Tls to 1.2
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                ## install providers
                Try
                    {
                        If (-not(Test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"))
                            {
                                Write-log "Nuget provider is not to up to date, Installing new one !"
                                Install-PackageProvider -Name 'nuget' -Force
                            }

                        Write-log "Nuget provider installed version: $(((Get-PackageProvider -Name 'nuget'|Sort-Object|Select-Object -First 1).version.tostring()))"
              
                        If ((Get-PSRepository -Name "PsGallery").InstallationPolicy -ne "Trusted"){Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted}                
                        If ([version]((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()) -lt [version]"2.2.5" )
                            {
                                Write-log "Powershell provider is not to up to date, Installing new one !"
                                Install-Module -Name PowerShellGet -MinimumVersion 2.2.5 -Force
                            }
                
                        Import-Module PowershellGet
                        Write-log "PowershellGet module installed version: $(((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()))"
                    }
                Catch
                    {Write-log "[Error] Unable to install default providers, Aborting!!!" ; Exit}

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

            ##==Check for latest version
            $AppInfos = Get-EvergreenApp -Name $AppName | Where-Object { $_.Architecture -eq $Architecture -and $_.Channel -eq "Stable" }
    }


##== Check if Application is Already installed 
If (($null -ne (Get-ItemProperty "$AppDetection_X64\*" | Where-Object { $_.DisplayName -eq $AppName })))
    {
        $AppIsInstalled = $true 
        $AppDetection = $AppDetection_X64
    }  
Elseif (($null -ne (Get-ItemProperty "$AppDetection_X86\*" | Where-Object { $_.DisplayName -eq $AppName })))
    {
        $AppIsInstalled = $true 
        $AppDetection = $AppDetection_X86
    }
Else
    {
        $AppIsInstalled = $false
        $AppInstallNow = $true        
    }         
   
     
##== Gather Informations
If ($AppIsInstalled)
    {
        $AppUninstallCommand = (Get-ItemProperty "$AppDetection\*" | Where-Object { $_.DisplayName -eq $AppName }).UninstallString
        $AppInstalledVersion = (Get-ItemProperty "$AppDetection\*" | Where-Object { $_.DisplayName -eq $AppName }).DisplayVersion
        Write-log "Version $AppInstalledVersion of $AppName detected!"
    }
Else
    {Write-log "No Installed version of $AppName detected!"}



##==Check if we need to update
If ($AppIsInstalled -and $Uninstall -ne $true)
    {
        If ([version]($AppInfos.Version) -gt [version]$AppInstalledVersion)
            {$AppInstallNow = $true ; Write-log "No previous version of $AppName detected!"} 
        Else 
            {$AppInstallNow = $False ;Write-log "Version Available online equals Installed version, Nothing to install !"} 
    }



##== UnInstall Application
If ($AppIsInstalled -and $UnInstall -eq $True)
    {
        $AppUninstallCMD = $AppUninstallCommand.Split(" ")[0]
        $AppUninstallParameters = $($AppUninstallCommand.Replace($AppUninstallCMD, "").trim() + " /qb")
        write-log "UnInstalling $AppName"
        
        ##== Uninstall
        $Iret = (Start-Process $AppUninstallCMD -ArgumentList $AppUninstallParameters -Wait -Passthru).ExitCode
        If ($AppUninstallSuccessReturnCodes -contains $Iret)
            {Write-log "Application $AppName - version $AppInstalledVersion Uninstalled Successfully !!!"}
        Else
            {Write-log "[Warning] Application $AppName - version $AppInstalledVersion returned code $Iret while trying to uninstall !!!" -Type 2}

        ##== Additionnal removal action
        If (Test-Path ("C:\Program Files (x86)\Google\NOUpdate")){Run-AsSystemNow -ScriptBlock {Remove-Item "C:\Program Files (x86)\Google\NOUpdate" -Force -Recurse|Out-Null}}
        If (Test-Path ("C:\Program Files (x86)\Google\Update")){Run-AsSystemNow -ScriptBlock {Remove-Item "C:\Program Files (x86)\Google\Update" -Force -Recurse|Out-Null}}
        If (Test-Path ("$env:UserProfile\Desktop\Microsoft Edge.lnk")){Remove-Item "$env:UserProfile\Desktop\Microsoft Edge.lnk" -Force|Out-Null}    
    }


##== Download and Install
If (($AppInstallNow -eq $true -and $UnInstall -eq $false) -or (-not([String]::IsNullOrWhiteSpace($PreDownloadPath))) -or (-not([String]::IsNullOrWhiteSpace($InstallSourcePath))) )
    {
        
        ##== Get latest Version From EverGreen
        IF([String]::IsNullOrWhiteSpace($InstallSourcePath))
            {
                $AppInstaller = split-path $AppInfos.uri -Leaf
                Write-log "Found $AppName - version: $($AppInfos.version) - Architecture: $Architecture - Release Date: $($AppInfos.Date) available on Internet"
                Write-log "Download Url: $($AppInfos.uri)"
                Write-log "Downloading installer for $AppName - $Architecture"

                if (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
                    {
                        If (-not(Test-path $PreDownloadPath)){$Iret = New-Item $PreDownloadPath -ItemType Directory -Force -ErrorAction SilentlyContinue}
                        If ([string]::IsNullOrWhiteSpace($Iret)){Write-log "[ERROR] Unable to create download folder at $PreDownloadPath, Aborting !!!" -Type 3 ; Exit}
                        $AppDownloadDir = $PreDownloadPath
                    }

                ## Downloading...
                Write-log "Download directory: $AppDownloadDir\$AppInstaller"
                Invoke-WebRequest -Uri $AppInfos.uri -OutFile "$AppDownloadDir\$AppInstaller" -ErrorAction Stop
             }
                
        ##== Set App Properties
        if ([String]::IsNullOrWhiteSpace($PreDownloadPath))
            {
                If (-not([String]::IsNullOrWhiteSpace($InstallSourcePath)))
                    {
                        If ((Test-Path $InstallSourcePath) -and (([System.IO.Path]::GetExtension($InstallSourcePath)).ToUpper() -eq $AppExtension.ToUpper()))
                            {$AppInstallParameters = $AppInstallParameters.replace("##APP##",$InstallSourcePath)}
                        Else
                            {Write-log "[ERROR] Unable to find application at $InstallSourcePath, Aborting !!!" -Type 3 ; Exit}
                    }
                Else
                    {$AppInstallParameters = $AppInstallParameters.replace("##APP##","$AppDownloadDir\$AppInstaller")}

                ##== Install
                write-log "Installing $AppName"
                $Iret = (Start-Process $AppInstallCMD -ArgumentList $AppInstallParameters -Wait -Passthru).ExitCode
                If ($AppInstallSuccessReturnCodes -contains $Iret)
                    {Write-log "Application $AppName - version $($AppInfos.version) Installed Successfully !!!"}
                Else
                    {Write-log "[ERROR] Application $AppName - version $($AppInfos.version) returned code $Iret while trying to Install !!!" -Type 3}
            }
    }

##== Remove Update capabilities
If ($DisableUpdate -and $Uninstall -ne $true -and [String]::IsNullOrWhiteSpace($PreDownloadPath))
    {
        Write-log "Disabling $APPNAME update feature !"

        $DisableUpdate_ScriptBlock = { 
                set-Service MicrosoftEdgeElevationService -StartupType Disabled -Status Stopped
                set-Service Gupdate -StartupType Disabled -Status Stopped
                set-Service Gupdatem -StartupType Disabled -Status Stopped
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false
                Rename-Item "C:\Program Files (x86)\Google\Update" -NewName "C:\Program Files (x86)\Google\NOUpdate" -Force
            }
        
        If (([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem)
            {$Iret = Invoke-Command -ScriptBlock $DisableUpdate_ScriptBlock}
        Else
            {$Iret = Invoke-AsSystemNow -ScriptBlock $DisableUpdate_ScriptBlock}

        If (-Not (Test-path "C:\Program Files (x86)\Google\Update") -and (Test-path "C:\Program Files (x86)\Google\NOUpdate"))
            {Write-log "Update feature for $APPNAME disabled successfully !"}
        Else
            {Write-log "[Error] Unable to remove $AppName Update feature !" -Type } 

    }

$FinishTime = [DateTime]::Now
Write-log "***************************************************************************************************"
Write-log "All $AppName related operations Finished !!!"
Write-log "Total processing time: [$(($FinishTime - $StartupTime).ToString())]"
Write-log "***************************************************************************************************"