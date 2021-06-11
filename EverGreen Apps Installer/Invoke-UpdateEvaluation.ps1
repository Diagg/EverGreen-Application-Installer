#Requires -Version 5
#Requires -RunAsAdministrator 

[CmdletBinding()]
param(

        [string]$GithubRepo = "https://github.com/Diagg/EverGreen-Application-Installer",

        [string]$Log = "$env:Windir\Logs\EvergreenApplication\EverGreen-UpdateEvaluation.log",

        [string]$GithubToken,

        [string]$UpdatePolicyURI
     )


function Write-log 
    {
        Param(
            [parameter()]
            [String]$Path="C:\Windows\Logs\EvergreenApplication\Evergreen-ApplicationUpdateEvaluation.log",

            [parameter(Position=0)]
            [String]$Message,

            [parameter()]
            [String]$Component="ApplicationUpdateEvaluation",

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
        $Content|Out-File $Path -Append -ErrorAction SilentlyContinue -Encoding utf8
    }



##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$Script:CurrentScriptName = $MyInvocation.MyCommand.Name
$Script:CurrentScriptFullName = $MyInvocation.MyCommand.Path
$Script:CurrentScriptPath = split-path $MyInvocation.MyCommand.Path
$Script:Log = $Log

##== Main
$StartupTime = [DateTime]::Now
Write-log 
Write-log "***************************************************************************************************"
Write-log "***************************************************************************************************"
Write-log "Started processing time: [$StartupTime]"
Write-log "Script Name: ApplicationUpdateEvaluation"
Write-log "***************************************************************************************************"

$RegTag = "HKLM:\SOFTWARE\OSDC\EverGreenInstaller"
If (test-path $RegPath)
    {
        $EverGreenApps = (Get-ChildItem $RegTag).PSChildName

        ForEach ($Regitem in $EverGreenApps)
            {
                $AppInfo = Get-ItemProperty -Path "$RegTag\$Regitem"
                If (-not ([string]::IsNullOrWhiteSpace($AppInfo)))
                    {
                        Write-log "Application : $Regitem"
                        $AppInstalledVersion = $AppInfo.DisplayVersion
                        $AppInstalledArchitecture = $AppInfo.Architecture
                        Write-log "Installed version : $AppInstalledVersion"

                        Write-log "Checking for Newer version online..."
                        $AppEverGreenInfo = Get-EvergreenApp -Name $Regitem | Where-Object Architecture -eq $AppInstalledArchitecture
                        Write-log "Latest verion available online: $($AppEverGreenInfo.Version)"

                        If ([version]($AppEverGreenInfo.Version) -gt [version]$AppInstalledVersion)
                            {
                                Set-ItemProperty "$RegTag\$Regitem" -name 'Status' -Value "Obsolete" -force|Out-Null
                                Write-log "$Regitem application status changed to Obsolete !"
                            }
                    }
            }
        }

$FinishTime = [DateTime]::Now
Write-log "***************************************************************************************************"
Write-log "Finished processing time: [$FinishTime]"
Write-log "Operation duration: [$(($FinishTime - $StartupTime).ToString())]"
Write-log "All Operations Finished!! Exit !"
Write-log "***************************************************************************************************"  