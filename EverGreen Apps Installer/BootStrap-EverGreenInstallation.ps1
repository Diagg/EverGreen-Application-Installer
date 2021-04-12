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

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("GoogleChrome", "MicrosoftEdge","Get-LatestAdobeReaderInstaller")]        
        [string]$Application,

        [ValidateSet("x86", "x64")]
        [string]$Architecture = "X64",

        [string]$Log,

        [switch]$DisableUpdate,
        
        [switch]$Uninstall,

        [string]$GithubToken,

        [string]$PreScriptURI,

        [string]$PostScriptURI
     )

##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$Script:CurrentScriptName = $MyInvocation.MyCommand.Name
$Script:CurrentScriptFullName = $MyInvocation.MyCommand.Path
$Script:CurrentScriptPath = split-path $MyInvocation.MyCommand.Path

##== Functions
function Write-log 
    {
         Param(
              [parameter()]
              [String]$Path=$Global:log,

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

Function Get-GistContent
    {
        param(
            [Parameter(Mandatory = $true, ParameterSetName='Prescript')] 
            [Parameter(Mandatory = $true, ParameterSetName='Postscript')]        
            [string]$GithubToken,

            [Parameter(Mandatory = $true,ParameterSetName='Prescript')]
            [string]$PreScriptURI,

            [Parameter(Mandatory = $true, ParameterSetName='Postscript')]
            [string]$PostScriptURI
         )
        
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
        $auth = Invoke-RestMethod -Method Get -Uri $githubURI -Headers $Headers -SessionVariable GITHUB 

        if ($auth) 
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
                                        Write-log "Downloading Gist script $($File.Filename)"
                                        $rawURL = $File.raw_url
                                        $fileraw = Invoke-RestMethod -Method Get -Uri $rawURL -WebSession $GITHUB
                                        Return $fileraw  
                                    } 
                            }
                    }
            }
    }

##== Initializing Environement
If ([string]::IsNullOrWhiteSpace($Log)){$Global:Log = $("$env:Windir\Logs\EvergreenApplication\EverGreen-" + $Application + "_" + $Architecture + "_" + "Intaller.log")}

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
Write-log "System Host Name: $([System.Environment]::MachineName)"
Write-log "System IP Address: $(Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp).IPAddress)"
Write-log "System OS version: $([System.Environment]::OSVersion.VersionString)"
Write-log "System OS Architecture is x64: $([System.Environment]::Is64BitOperatingSystem)"
Write-Log "User Name: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "User is Admin: $((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))" 
Write-Log "User is System: $([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)" 

If ($Uninstall -eq $true){Write-log "Selected Action: Uninstallation"}
else{Write-log "Selected Action: Installation"}

If ($DisableUpdate -eq $true){Write-log "Install Option: Disabling update feature"}
        

## Set Tls to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Add Scripts path to $env:PSModulePath
$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
If ($CurrentValue -notlike "*C:\Program Files\WindowsPowerShell\scripts*") {[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + [System.IO.Path]::PathSeparator + "C:\Program Files\WindowsPowerShell\Scripts", "Machine")}

## install providers
Try 
    {
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

$Application = "Get-LatestAdobeReaderInstaller"
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