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

Invoke-AsCurrentUser function based on work by Kelvin Tegelaar
https://www.cyberdrain.com/automating-with-powershell-impersonating-users-while-running-as-system/

X64 Relaunch based on work by Nathan ZIEHNERT
https://z-nerd.com/blog/2020/03/31-intune-win32-apps-powershell-script-installer/

Set-FTA function based on work by Danyfirex & Dany3j
https://github.com/DanysysTeam/PS-SFTA

Write-EckLog based on work by someone i could not remember (Feel free to reatch me if you recognize your code)

#>

##############
# Product Name: Greenstaller
# Publisher: OSD-Couture.com
# Product Code: 4ec8022d-0366-4909-8240-20c1c89e0d40
# Auto Update: YES
# By Diagg/OSD-Couture.com
# 
# Script Version:  0.37 - 08/06/2021 - 
# Script Version:  0.4 - 19/03/2022 - fully reworked


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
        [switch]$SetAsDefault,

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
        [string]$UpdatePolicyURI
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

##== Set Log path
If ($log = $("$env:Windir\Logs\Greenstaller\Intaller.log")) {$Log = $log.Replace(".log","-$Application.log")}
If (-not(Test-path $(split-path $Log))){New-Item -Path $(split-path $Log) -ItemType Directory -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}

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


##== Do that Omega supreme stuffs and load Includes, environment and dependancies
try 
    {
        $ScriptURI = "https://raw.githubusercontent.com/Diagg/EndPoint-CloudKit-Bootstrap/master/Initialize-ECKPrereq.ps1"
        $Fileraw = (Invoke-WebRequest -URI $ScriptURI -UseBasicParsing -ErrorAction Stop).content
        Invoke-Command $Fileraw -ErrorAction stop
        Initialize-ECKPrereq -Module "Evergreen" -ScriptToImport 'https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/master/SFTA.ps1' -LogPath $log
    }
catch 
    { Write-Error "[ERROR] Unable to load includes, Aborting !" ; Exit 1}


##== Functions

#region Functions 
Function Get-ECKGithubContent
    {
        param(

            [Parameter(Mandatory = $true, Position=0)]
            [string]$URI,
            
            [string]$GithubToken,

            [string]$ScriptName
         )
        
        If([string]::IsNullOrWhiteSpace($GithubToken))
            {
                ## This a public Repo/Gist

                If($URI -like '*/gist.github.com*') ##This is a Gist
                    {
                        $URI = $URI.replace("gist.github.com","gist.githubusercontent.com")
                        If ($URI.Split("/")[$_.count-1] -notlike '*raw*'){$URI = "$URI/raw"}
                    }
                ElseIf($URI -like '*/github.com*') ##This is a Github repo
                    {$URI = $URI -replace "github.com","raw.githubusercontent.com" -replace "blob/",""} 
                Else
                    {
                        If ($URI -notlike "*/raw.githubusercontent.com*" -and $URI -notlike "*//gist.githubusercontent.com*") 
                            {
                                Write-ECKlog -Path $LogPath -Message "[ERROR] Unsupported URI $URI, Aborting !!!"
                                $URI = $false
                            }
                    }
                Return $URI
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

	                                    $files = $myGithubRepos | Where-Object {$_.type -eq "file"}
	                                    $directories = $myGithubRepos | Where-Object {$_.type -eq "dir"}

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
        Write-EckLog "Starting Scheduled scriptblock with name $TaskName as System Account"
        Start-Job -DefinitionName $taskName|Out-Null

        $attempts = 1
        While ((get-job -Name $taskname).State -ne "Completed" -or $attempts -le 15)
            {
                Start-Sleep -Seconds 1
                $attempts += 1
            }

        If ((get-job -Name $taskname).State -eq "Completed")
            {
                Write-EckLog "Scheduled scriptblock with name $TaskName completed successfully !"
                Unregister-ScheduledJob $TaskName -Confirm:$false
                Return $true
            }
        Else
            {
                Write-EckLog "[Error] Scheduled job with name $TaskName, returned with status $((get-job -Name $taskname).State)"
                Unregister-ScheduledJob $TaskName -Confirm:$false
                Return $false                        
            }
    }

Function Invoke-AsCurrentUser
    {
        
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            [Parameter(Mandatory = $false)]
            [String]$ScriptBlockLog = $Script:log,
            [Parameter(Mandatory = $false)]
            [switch]$NoWait,
            [Parameter(Mandatory = $false)]
            [ValidateSet("x86","x64","X86","X64")]
            [String]$Architecture = "x64",
            [Parameter(Mandatory = $false)]
            [switch]$UseWindowsPowerShell = $true,
            [Parameter(Mandatory = $false)]
            [switch]$Visible,
            [Parameter(Mandatory = $false)]
            [switch]$CacheToDisk
        )        
        

        $Source = @"
        using Microsoft.Win32.SafeHandles;
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        namespace RunAsUser
        {
            internal class NativeHelpers
            {
                [StructLayout(LayoutKind.Sequential)]
                public struct PROCESS_INFORMATION
                {
                    public IntPtr hProcess;
                    public IntPtr hThread;
                    public int dwProcessId;
                    public int dwThreadId;
                }
                [StructLayout(LayoutKind.Sequential)]
                public struct STARTUPINFO
                {
                    public int cb;
                    public String lpReserved;
                    public String lpDesktop;
                    public String lpTitle;
                    public uint dwX;
                    public uint dwY;
                    public uint dwXSize;
                    public uint dwYSize;
                    public uint dwXCountChars;
                    public uint dwYCountChars;
                    public uint dwFillAttribute;
                    public uint dwFlags;
                    public short wShowWindow;
                    public short cbReserved2;
                    public IntPtr lpReserved2;
                    public IntPtr hStdInput;
                    public IntPtr hStdOutput;
                    public IntPtr hStdError;
                }
                [StructLayout(LayoutKind.Sequential)]
                public struct WTS_SESSION_INFO
                {
                    public readonly UInt32 SessionID;
                    [MarshalAs(UnmanagedType.LPStr)]
                    public readonly String pWinStationName;
                    public readonly WTS_CONNECTSTATE_CLASS State;
                }
            }
            internal class NativeMethods
            {
                [DllImport("kernel32", SetLastError=true)]
                public static extern int WaitForSingleObject(
                  IntPtr hHandle,
                  int dwMilliseconds);
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern bool CloseHandle(
                    IntPtr hSnapshot);
                [DllImport("userenv.dll", SetLastError = true)]
                public static extern bool CreateEnvironmentBlock(
                    ref IntPtr lpEnvironment,
                    SafeHandle hToken,
                    bool bInherit);
                [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool CreateProcessAsUserW(
                    SafeHandle hToken,
                    String lpApplicationName,
                    StringBuilder lpCommandLine,
                    IntPtr lpProcessAttributes,
                    IntPtr lpThreadAttributes,
                    bool bInheritHandle,
                    uint dwCreationFlags,
                    IntPtr lpEnvironment,
                    String lpCurrentDirectory,
                    ref NativeHelpers.STARTUPINFO lpStartupInfo,
                    out NativeHelpers.PROCESS_INFORMATION lpProcessInformation);
                [DllImport("userenv.dll", SetLastError = true)]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool DestroyEnvironmentBlock(
                    IntPtr lpEnvironment);
                [DllImport("advapi32.dll", SetLastError = true)]
                public static extern bool DuplicateTokenEx(
                    SafeHandle ExistingTokenHandle,
                    uint dwDesiredAccess,
                    IntPtr lpThreadAttributes,
                    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                    TOKEN_TYPE TokenType,
                    out SafeNativeHandle DuplicateTokenHandle);
                [DllImport("advapi32.dll", SetLastError = true)]
                public static extern bool GetTokenInformation(
                    SafeHandle TokenHandle,
                    uint TokenInformationClass,
                    SafeMemoryBuffer TokenInformation,
                    int TokenInformationLength,
                    out int ReturnLength);
                [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                public static extern bool WTSEnumerateSessions(
                    IntPtr hServer,
                    int Reserved,
                    int Version,
                    ref IntPtr ppSessionInfo,
                    ref int pCount);
                [DllImport("wtsapi32.dll")]
                public static extern void WTSFreeMemory(
                    IntPtr pMemory);
                [DllImport("kernel32.dll")]
                public static extern uint WTSGetActiveConsoleSessionId();
                [DllImport("Wtsapi32.dll", SetLastError = true)]
                public static extern bool WTSQueryUserToken(
                    uint SessionId,
                    out SafeNativeHandle phToken);
            }
            internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
            {
                public SafeMemoryBuffer(int cb) : base(true)
                {
                    base.SetHandle(Marshal.AllocHGlobal(cb));
                }
                public SafeMemoryBuffer(IntPtr handle) : base(true)
                {
                    base.SetHandle(handle);
                }
                protected override bool ReleaseHandle()
                {
                    Marshal.FreeHGlobal(handle);
                    return true;
                }
            }
            internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                public SafeNativeHandle() : base(true) { }
                public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }
                protected override bool ReleaseHandle()
                {
                    return NativeMethods.CloseHandle(handle);
                }
            }
            internal enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous = 0,
                SecurityIdentification = 1,
                SecurityImpersonation = 2,
                SecurityDelegation = 3,
            }
            internal enum SW
            {
                SW_HIDE = 0,
                SW_SHOWNORMAL = 1,
                SW_NORMAL = 1,
                SW_SHOWMINIMIZED = 2,
                SW_SHOWMAXIMIZED = 3,
                SW_MAXIMIZE = 3,
                SW_SHOWNOACTIVATE = 4,
                SW_SHOW = 5,
                SW_MINIMIZE = 6,
                SW_SHOWMINNOACTIVE = 7,
                SW_SHOWNA = 8,
                SW_RESTORE = 9,
                SW_SHOWDEFAULT = 10,
                SW_MAX = 10
            }
            internal enum TokenElevationType
            {
                TokenElevationTypeDefault = 1,
                TokenElevationTypeFull,
                TokenElevationTypeLimited,
            }
            internal enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation = 2
            }
            internal enum WTS_CONNECTSTATE_CLASS
            {
                WTSActive,
                WTSConnected,
                WTSConnectQuery,
                WTSShadow,
                WTSDisconnected,
                WTSIdle,
                WTSListen,
                WTSReset,
                WTSDown,
                WTSInit
            }
            public class Win32Exception : System.ComponentModel.Win32Exception
            {
                private string _msg;
                public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
                public Win32Exception(int errorCode, string message) : base(errorCode)
                {
                    _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
                }
                public override string Message { get { return _msg; } }
                public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
            }
            public static class ProcessExtensions
            {
                #region Win32 Constants
                private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                private const int CREATE_NO_WINDOW = 0x08000000;
                private const int CREATE_NEW_CONSOLE = 0x00000010;
                private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
                private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
                #endregion
                // Gets the user token from the currently active session
                private static SafeNativeHandle GetSessionUserToken(bool elevated)
                {
                    var activeSessionId = INVALID_SESSION_ID;
                    var pSessionInfo = IntPtr.Zero;
                    var sessionCount = 0;
                    // Get a handle to the user access token for the current active session.
                    if (NativeMethods.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount))
                    {
                        try
                        {
                            var arrayElementSize = Marshal.SizeOf(typeof(NativeHelpers.WTS_SESSION_INFO));
                            var current = pSessionInfo;
                            for (var i = 0; i < sessionCount; i++)
                            {
                                var si = (NativeHelpers.WTS_SESSION_INFO)Marshal.PtrToStructure(
                                    current, typeof(NativeHelpers.WTS_SESSION_INFO));
                                current = IntPtr.Add(current, arrayElementSize);
                                if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                                {
                                    activeSessionId = si.SessionID;
                                    break;
                                }
                            }
                        }
                        finally
                        {
                            NativeMethods.WTSFreeMemory(pSessionInfo);
                        }
                    }
                    // If enumerating did not work, fall back to the old method
                    if (activeSessionId == INVALID_SESSION_ID)
                    {
                        activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
                    }
                    SafeNativeHandle hImpersonationToken;
                    if (!NativeMethods.WTSQueryUserToken(activeSessionId, out hImpersonationToken))
                    {
                        throw new Win32Exception("WTSQueryUserToken failed to get access token.");
                    }
                    using (hImpersonationToken)
                    {
                        // First see if the token is the full token or not. If it is a limited token we need to get the
                        // linked (full/elevated token) and use that for the CreateProcess task. If it is already the full or
                        // default token then we already have the best token possible.
                        TokenElevationType elevationType = GetTokenElevationType(hImpersonationToken);
                        if (elevationType == TokenElevationType.TokenElevationTypeLimited && elevated == true)
                        {
                            using (var linkedToken = GetTokenLinkedToken(hImpersonationToken))
                                return DuplicateTokenAsPrimary(linkedToken);
                        }
                        else
                        {
                            return DuplicateTokenAsPrimary(hImpersonationToken);
                        }
                    }
                }
                public static int StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true,int wait = -1, bool elevated = true)
                {
                    using (var hUserToken = GetSessionUserToken(elevated))
                    {
                        var startInfo = new NativeHelpers.STARTUPINFO();
                        startInfo.cb = Marshal.SizeOf(startInfo);
                        uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                        startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                        //startInfo.lpDesktop = "winsta0\\default";
                        IntPtr pEnv = IntPtr.Zero;
                        if (!NativeMethods.CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                        {
                            throw new Win32Exception("CreateEnvironmentBlock failed.");
                        }
                        try
                        {
                            StringBuilder commandLine = new StringBuilder(cmdLine);
                            var procInfo = new NativeHelpers.PROCESS_INFORMATION();
                            if (!NativeMethods.CreateProcessAsUserW(hUserToken,
                                appPath, // Application Name
                                commandLine, // Command Line
                                IntPtr.Zero,
                                IntPtr.Zero,
                                false,
                                dwCreationFlags,
                                pEnv,
                                workDir, // Working directory
                                ref startInfo,
                                out procInfo))
                            {
                                throw new Win32Exception("CreateProcessAsUser failed.");
                            }
                            try
                            {
                                NativeMethods.WaitForSingleObject( procInfo.hProcess, wait);
                                return procInfo.dwProcessId;
                            }
                            finally
                            {
                                NativeMethods.CloseHandle(procInfo.hThread);
                                NativeMethods.CloseHandle(procInfo.hProcess);
                            }
                        }
                        finally
                        {
                            NativeMethods.DestroyEnvironmentBlock(pEnv);
                        }
                    }
                }
                private static SafeNativeHandle DuplicateTokenAsPrimary(SafeHandle hToken)
                {
                    SafeNativeHandle pDupToken;
                    if (!NativeMethods.DuplicateTokenEx(hToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        TOKEN_TYPE.TokenPrimary, out pDupToken))
                    {
                        throw new Win32Exception("DuplicateTokenEx failed.");
                    }
                    return pDupToken;
                }
                private static TokenElevationType GetTokenElevationType(SafeHandle hToken)
                {
                    using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 18))
                    {
                        return (TokenElevationType)Marshal.ReadInt32(tokenInfo.DangerousGetHandle());
                    }
                }
                private static SafeNativeHandle GetTokenLinkedToken(SafeHandle hToken)
                {
                    using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 19))
                    {
                        return new SafeNativeHandle(Marshal.ReadIntPtr(tokenInfo.DangerousGetHandle()));
                    }
                }
                private static SafeMemoryBuffer GetTokenInformation(SafeHandle hToken, uint infoClass)
                {
                    int returnLength;
                    bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0,
                        out returnLength);
                    int errCode = Marshal.GetLastWin32Error();
                    if (!res && errCode != 24 && errCode != 122)  // ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
                    {
                        throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length", infoClass));
                    }
                    SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(returnLength);
                    if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, returnLength, out returnLength))
                        throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass));
                    return tokenInfo;
                }
            }
        }
"@

        # Load the custom type
        if (!("RunAsUser.ProcessExtensions" -as [type])) {Add-Type -TypeDefinition $source -Language CSharp}

        Write-EckLog "Preparing Invokation as Current user"
        Write-EckLog "Invokation log is $ScriptBlockLog"

        # Enhance Scriptblock
        $Script_LogPath = "`$Script:LogPath = ""$ScriptBlockLog"" `n"

        $Script_Init = {

function Write-EckLog 
    {
        Param(
                [parameter()]
                [String]$Path=$Script:LogPath,

                [parameter(Position=0)]
                [String]$Message,

                [parameter()]
                [String]$Component="Invoke-AsCurrentUser",

		        #Severity  Type(1 - Information, 2- Warning, 3 - Error)
		        [parameter(Mandatory=$False)]
		        [ValidateRange(1,3)]
		        [Single]$Type = 1
        )


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
        $Content| Out-File $Path -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }


function Write-Errorlog 
    {
        Param([parameter(Position=0)][String]$Message)
        Write-EckLog -Message $Message -type 3
    }


function Write-Warninglog 
    {
        Param([parameter(Position=0)][String]$Message)
        Write-EckLog -Message $Message -type 2
    }

}

        $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_Init.ToString() + $ScriptBlock.ToString().replace("Write-Host", "Write-EckLog").replace("Write-Warning", "Write-Warninglog").replace("Write-Error", "Write-Errorlog").replace("Write-Verbose", "Write-EckLog"))
        $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))

        $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
        if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
        if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) 
            {
                Write-EckLog "The encoded script is longer than the command line parameter limit. The script will be cached to disk"
                $CacheToDisk = $true
            }

        if ($CacheToDisk) 
            {
                $ScriptGuid = new-guid
                $ScriptBlock|Out-File -FilePath "$($ENV:TEMP)\$($ScriptGuid).ps1" -Encoding UTF8 -width 320
                Write-EckLog "Script Block converted to file $($ENV:TEMP)\$($ScriptGuid).ps1"
                $pwshcommand = "-ExecutionPolicy Bypass -Window Normal -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
            }
        else 
            {$pwshcommand = "-ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)"}

        $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
        if ($privs.State -eq "Disabled") 
            {
                Write-EckLog -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token." -Type 3
                return
            }
        else 
            {

                # Use the same PowerShell executable as the one that invoked the function, Unless -UseWindowsPowerShell is defined
           
                If (!$UseWindowsPowerShell -and  $Host.Name -notlike "*ISE*") 
                    { $pwshPath = (Get-Process -Id $pid).Path } 
                Else 
                    { $pwshPath = "$PSHome\powershell.exe"}
                        
                If ($NoWait) { $ProcWaitTime = 1 } else { $ProcWaitTime = -1 }
                If ((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $true -and $([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) -eq $false) { $RunAsAdmin = $true } else { $RunAsAdmin = $false }


                # Add Current user ACL to Log File
                If ((get-acl $ScriptBlockLog).AccessToString -notlike "*$($Script:TsEnv.CurrentLoggedOnUser) Allow  FullControl*")
                    {
                        $Acl = Get-Acl $ScriptBlockLog
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($($Script:TsEnv.CurrentLoggedOnUser),"FullControl","Allow")
                        $acl.SetAccessRule($AccessRule)
                        $acl | Set-Acl $ScriptBlockLog -ErrorAction SilentlyContinue
                    }

                Try 
                    {
                        # Run in user Context
                        Write-EckLog "about to run `"$pwshPath`" $pwshcommand -IsVisible $Visible -Wait $ProcWaitTime -RunAsAdmin $RunAsAdmin"
                        [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser($pwshPath, "`"$pwshPath`" $pwshcommand",(Split-Path $pwshPath -Parent), $Visible, $ProcWaitTime, $RunAsAdmin)|Out-Null
                    }
                Catch 
                    {Write-EckLog "Could not execute as currently logged on user: $($_.Exception.Message)" -Type 3}
                Finally
                    {
                        If ((get-acl $ScriptBlockLog).AccessToString -like "*$($Script:TsEnv.CurrentLoggedOnUser) Allow  FullControl*")
                            {
                                #Remove ACL
                                $acl = Get-Acl $ScriptBlockLog
                                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($($Script:TsEnv.CurrentLoggedOnUser),"FullControl","Allow")
                                $acl.RemoveAccessRule($AccessRule)
                                $acl | Set-Acl $ScriptBlockLog -ErrorAction SilentlyContinue
                            }
                        
                        If ($CacheToDisk) { $null = remove-item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force -ErrorAction SilentlyContinue }
                    }
            }
    }

#endregion 


Try
    {
        ##== Initializing Environement
        $Context = Get-ECKExecutionContext -LogPath $log
        $Script:TsEnv = New-Object PSObject
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentLoggedOnUser' -Value $context.User
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserSID' -Value $context.UserID
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentLoggedOnUserUPN' -Value $context.UserUPN

        If ($Script:TsEnv.CurrentLoggedOnUser -eq "#NotAvailable#"){Write-EckLog "[ERROR] Unable to detect current user, Aborting...." -Path $log -Type 3; Exit}

        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'SystemHostName' -Value ([System.Environment]::MachineName)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'SystemIPAddress' -Value (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp -AddressState Preferred).IPAddress
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'SystemOSversion' -Value ([System.Environment]::OSVersion.VersionString)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'SystemOSArchitectureIsX64' -Value ([System.Environment]::Is64BitOperatingSystem)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserExecutionContext' -Value ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserIsAdmin' -Value (New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserIsSystem' -Value $([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserIsTrustedInstaller' -Value ([System.Security.Principal.WindowsIdentity]::GetCurrent().groups.value -contains "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
        If ($Script:TsEnv.CurrentLoggedOnUser -like "*\*")
            {
                $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserName' -Value ($Script:TsEnv.CurrentLoggedOnUser).split("\")[1]
                $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserDomain' -Value ($Script:TsEnv.CurrentLoggedOnUser).split("\")[0]
            }

        If($Script:TsEnv.CurrentUserSID -eq "#NotAvailable#"){$Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserSID' -Value (New-Object System.Security.Principal.NTAccount($Script:TsEnv.CurrentLoggedOnUser)).Translate([System.Security.Principal.SecurityIdentifier]).value}
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserProfilePath' -Value (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'| Where-Object {$PSItem.pschildname -eq $Script:TsEnv.CurrentUserSID}|Get-ItemPropertyValue -Name ProfileImagePath)
        $Script:TsEnv|Add-Member -MemberType NoteProperty -Name 'CurrentUserRegistryPath' -Value "HKU:\$($Script:TsEnv.CurrentUserSID)" 


        ##== Local Constantes
        $AppDownloadDir = "$env:Public\Downloads\$Application"
        If ([String]::IsNullOrWhiteSpace($InstallSourcePath)){If(-not(Test-path $AppDownloadDir)){New-Item $AppDownloadDir -Force -ItemType Directory -ErrorAction SilentlyContinue|Out-Null}} 

        $StartupTime = [DateTime]::Now
        Write-EckLog "***************************************************************************************************" -LogPath $log
        Write-EckLog "***************************************************************************************************" -LogPath $log
        Write-EckLog "Release $((Select-String -Pattern "Version:" -Path $Script:CurrentScriptFullName -CaseSensitive).Line[0])" -LogPath $log
        Write-EckLog "Started processing time: [$StartupTime]" -LogPath $log
        Write-EckLog "Script Name: $CurrentScriptFullName" -LogPath $log
        Write-EckLog "Selected Application: $Application" -LogPath $log
        If ($Uninstall -ne $true) {Write-EckLog "Selected Application Architecture: $Architecture"}
        Write-EckLog "***************************************************************************************************" -LogPath $log
        Write-EckLog "Powershell Home: $PSHOME" -LogPath $log
        Write-EckLog "Current Session ID: $PID" -LogPath $log
        Write-EckLog "Log Path: $log" -LogPath $log
        Write-EckLog "System Host Name: $($Script:TsEnv.SystemHostName)" -LogPath $log
        Write-EckLog "System IP Address: $($Script:TsEnv.SystemIPAddress)" -LogPath $log
        Write-EckLog "System OS version: $($Script:TsEnv.SystemOSversion)" -LogPath $log
        Write-EckLog "System OS Architecture is x64: $($Script:TsEnv.SystemOSArchitectureIsX64)" -LogPath $log
        Write-EckLog "Logged on user: $($Script:TsEnv.CurrentLoggedOnUser)" -LogPath $log
        If($Script:TsEnv.CurrentLoggedOnUserUPN) {Write-EckLog "Logged on user UPN: $($Script:TsEnv.CurrentLoggedOnUserUPN)" -LogPath $log}
        Write-EckLog "Execution Context is Admin: $($Script:TsEnv.CurrentUserIsAdmin)" -LogPath $log 
        Write-EckLog "Execution Context is System: $($Script:TsEnv.CurrentUserIsSystem)" -LogPath $log
        Write-EckLog "Execution Context is TrustedInstaller: $($Script:TsEnv.CurrentUserIsTrustedInstaller)" -LogPath $log 


        If ($Uninstall -eq $true)
            {Write-EckLog "Selected Action: Uninstallation" -LogPath $log}
        Elseif (-not([String]::IsNullOrWhiteSpace($InstallSourcePath)))
            {
                Write-EckLog "Selected Action: Installation from offline source" -LogPath $log
                Write-EckLog "Install Option: Offline location $InstallSourcePath" -LogPath $log
                $OfflineInstall = $true
            }
        ElseIf ($DisableUpdate -eq $true)
            {Write-EckLog "Install Option: Disabling update feature" -LogPath $log}
        ElseIf (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
            {
                Write-EckLog "Selected Action: Predownloading without installation" -LogPath $log
                Write-EckLog "Install Option: Download location $PreDownloadPath" -LogPath $log
            }           
        Else
            {Write-EckLog "Selected Action: Installation" -LogPath $log}
    

        ##== Download APP Data
        Write-EckLog "Retriving data from Github for Application $Application" -LogPath $log
        $AppDataCode = Get-ECKGithubContent -URI "$GithubRepo/blob/master/EverGreen%20Apps%20Installer/Applications-Data/$Application-Data.ps1"
        Try 
            {
                If ($AppDataCode -ne $False) 
                    {
                        $AppDataScriptPath = "$($env:temp)\Github-$Application-Data.ps1"
                        $AppDataCode|Out-File $AppDataScriptPath
                        ."$AppDataScriptPath"
                        Write-EckLog "Temporary data for Application $Application stored in $AppDataScriptPath" -LogPath $log
                    } 
                Else
                    {Write-EckLog "[Error] Unable to execute $Application data garthering, bad return code, Aborting !!!" -Type 3 -LogPath $log ; Exit} 
            }
        Catch 
            {
                Write-EckLog "[Error] Unable to execute $Application data garthering, logical error occurs, Aborting !!!" -Type 3 -LogPath $log
                Write-EckLog $Error[0].InvocationInfo.PositionMessage.ToString() -type 3 -LogPath $log
                Write-EckLog $Error[0].Exception.Message.ToString() -type 3 -LogPath $log
                Exit
            }


        ##############################
        #### Gather Informations
        ##############################
        $Script:AppInfo = Get-AppInfo -Architecture $Architecture -Language $Language -DisableUpdate $DisableUpdate.IsPresent -EnterpriseMode $EnterpriseMode.IsPresent
        Get-AppInstallStatus

        If ($Script:AppInfo.AppIsInstalled)
            {Write-EckLog "Version $($Script:AppInfo.AppInstalledVersion) of $Application detected!" -LogPath $log}
        Else
            {
                $AppInstallNow = $true
                Write-EckLog "No Installed version of $Application detected!" -LogPath $log
            }


        ##############################
        #### Pre-Script
        ##############################
        If ($PreScriptURI)
            {
                Write-EckLog "Invoking Prescript" -LogPath $log
                If ($GithubToken){$PreScript = Get-ECKGithubContent -URI $PreScriptURI -GithubToken $GithubToken} Else {$PreScript = Get-ECKGithubContent -URI $PreScriptURI}
                Try {Invoke-Command $PreScript}
                Catch {Write-EckLog "[Error] Prescript Failed to execute" -Type 3 -LogPath $log}
            }




        ##############################
        #### Application installation
        ##############################

        If ($Uninstall -ne $true)
            {
                If ($InstallSourcePath){$AppInstallNow = $true}
        
                ##==Check for latest version
                $Script:AppEverGreenInfo = Get-EvergreenApp -Name $Application | Where-Object Architecture -eq $Architecture
                If (-not([string]::IsNullOrWhiteSpace($Script:AppInfo.AppInstallLanguage))){$Script:AppEverGreenInfo = $Script:AppEverGreenInfo|Where-Object Language -eq $Script:AppInfo.AppInstallLanguage}



                ##==Check if we need to update
                $AppUpdateStatus = Get-AppUpdateStatus
                If ($AppUpdateStatus)
                    {
                        $AppInstallNow = $true
                        Write-EckLog "New version of $Application detected! Release version: $($Script:AppEverGreenInfo.Version)" -LogPath $log
                    } 
                Else 
                    {
                        $AppInstallNow = $False
                        Write-EckLog "Version Available online is similar to installed version, Nothing to install !" -LogPath $log
                    } 


                ##==Download
                if (-not([String]::IsNullOrWhiteSpace($PreDownloadPath)))
                    {
                        $PreDownloadPath = "$PreDownloadPath\$Application"
                        If (-not(Test-path $PreDownloadPath))
                            {
                                $Iret = New-Item $PreDownloadPath -ItemType Directory -Force -ErrorAction SilentlyContinue
                                If ([string]::IsNullOrWhiteSpace($Iret)){Write-EckLog "[ERROR] Unable to create download folder at $PreDownloadPath, Aborting !!!" -Type 3 -LogPath $log ; Exit}
                            }
                
                        $AppDownloadDir = $PreDownloadPath
                        $AppInstallNow = $False
                    }

                If (([String]::IsNullOrWhiteSpace($InstallSourcePath) -and $AppInstallNow -eq $True) -or (-not([String]::IsNullOrWhiteSpace($PreDownloadPath))))
                    {
                        Write-EckLog "Found $Application - version: $($Script:AppEverGreenInfo.version) - Architecture: $Architecture - Release Date: $($Script:AppEverGreenInfo.Date) available on Internet" -LogPath $log
                        Write-EckLog "Download Url: $($Script:AppEverGreenInfo.uri)" -LogPath $log
                        Write-EckLog "Downloading installer for $Application - $Architecture"  -LogPath $log
                        $InstallSourcePath = $Script:AppEverGreenInfo|Save-EvergreenApp -Path $AppDownloadDir
                        Write-EckLog "Successfully downloaded $( Split-Path $InstallSourcePath -Leaf) to folder $(Split-Path $InstallSourcePath)" -LogPath $log
                    }

        
                ##== Uninstall before Update if requiered
                If ($Script:AppInfo.AppIsInstalled -eq $True -and [String]::IsNullOrWhiteSpace($PreDownloadPath))
                    {
                        If (($Script:AppInfo.AppMustUninstallBeforeUpdate -eq $true) -or ($Script:AppInfo.AppInstallArchitecture -ne $Script:AppInfo.AppArchitecture -and $Script:AppInfo.AppMustUninstallOnArchChange -eq $true))
                            {
                                ##== Uninstall
                                Write-EckLog "Uninstalling $Application before reinstall/Update !" -LogPath $log
                                $Iret = (Start-Process $Script:AppInfo.AppUninstallCMD -ArgumentList $Script:AppInfo.AppUninstallParameters -Wait -Passthru).ExitCode
                                If ($Script:AppInfo.AppUninstallSuccessReturnCodes -contains $Iret)
                                    {Write-EckLog "Application $Application - version $($Script:AppInfo.AppInstalledVersion) Uninstalled Successfully before reinstall/Update!!!" -LogPath $log}
                                Else
                                    {Write-EckLog "[Warning] Application $Application - version $($Script:AppInfo.AppInstalledVersion) returned code $Iret while trying to uninstall before new update !!!" -Type 2 -LogPath $log}

                                ##== Additionnal removal action
                                Write-EckLog "Uninstalling addintionnal items before reinstall/Update !" -LogPath $log
                                Invoke-AdditionalUninstall
                                Remove-Item "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application" -Recurse -Force -ErrorAction SilentlyContinue
                            }
                    }


                ##==Install
                if ($AppInstallNow -eq $True)
                    {
                        ## Rebuild Parametrers
                        Write-EckLog "Download directory: $InstallSourcePath" -LogPath $log
                        If ((Test-Path $InstallSourcePath) -and (([System.IO.Path]::GetExtension($InstallSourcePath)).ToUpper() -eq $Script:AppInfo.AppExtension.ToUpper()))
                            {
                                $Script:AppInfo.AppInstallParameters = $Script:AppInfo.AppInstallParameters.replace("##APP##",$InstallSourcePath)
                                $Script:AppInfo.AppInstallCMD  = $Script:AppInfo.AppInstallCMD.replace("##APP##",$InstallSourcePath)
                            }
                        Else
                            {Write-EckLog "[ERROR] Unable to find application at $InstallSourcePath or Filename with extension may be missing, Aborting !!!" -Type 3 -LogPath $log ; Exit}


                
                        ## Execute Intall Program
                        Write-EckLog "Installing $Application with command $($Script:AppInfo.AppInstallCMD) and parameters $($Script:AppInfo.AppInstallParameters)" -LogPath $log
                        $Iret = (Start-Process $Script:AppInfo.AppInstallCMD -ArgumentList $Script:AppInfo.AppInstallParameters -Wait -Passthru).ExitCode
                        If ($Script:AppInfo.AppInstallSuccessReturnCodes -contains $Iret)
                            {
                                Write-EckLog "Application $Application - version $($Script:AppEverGreenInfo.version) Installed Successfully !!!" -LogPath $log
                                $Script:AppInfo.AppArchitecture = $Architecture.ToUpper()
                                $Script:AppInfo.AppInstalledVersion = $($Script:AppEverGreenInfo.version)
                            }
                        Else
                            {Write-EckLog "[ERROR] Application $Application - version $($Script:AppEverGreenInfo.version) returned code $Iret while trying to Install !!!" -Type 3 -LogPath $log}


                        ##== Install Additionnal Componants
                        Write-EckLog "Installing additionnal Componants !" -LogPath $log
                        Invoke-AdditionalInstall -SetAsDefault $SetAsDefault.IsPresent -EnterpriseMode $EnterpriseMode.IsPresent


                        ## Clean Download Folder
                        if ([String]::IsNullOrWhiteSpace($PreDownloadPath) -and $OfflineInstall -ne $true )
                            {
                                Write-EckLog "cleaning Download folder" -LogPath $log
                                If (test-path $InstallSourcePath){Remove-Item $InstallSourcePath -recurse -Force -Confirm:$false -ErrorAction SilentlyContinue}
                            }
                    }

 
                ##== Remove Update capabilities
                If ($DisableUpdate -and [String]::IsNullOrWhiteSpace($PreDownloadPath))
                    {
                        Write-EckLog "Disabling $Application update feature !" -LogPath $log
                        Invoke-DisableUpdateCapability
                    }


                ##== Tag in registry
                If ([String]::IsNullOrWhiteSpace($PreDownloadPath))
                    {
                        Write-EckLog "Tagging in the registry !" -LogPath $log
                        $RegTag = "HKLM:\SOFTWARE\OSDC\EverGreenInstaller"
                        If (-not(Test-path $RegTag)){New-item -Path $RegTag -Force|Out-Null}
                        If (-not(Test-path "$RegTag\$Application")){New-item -Path "$RegTag\$Application" -Force|Out-Null}
                        New-ItemProperty -Path "$RegTag\$Application" -Name "InstallDate" -Value $([DateTime]::Now) -Force -ErrorAction SilentlyContinue|Out-Null
                        New-ItemProperty -Path "$RegTag\$Application" -Name "Version" -Value $($Script:AppInfo.AppInstalledVersion) -Force -ErrorAction SilentlyContinue|Out-Null
                        New-ItemProperty -Path "$RegTag\$Application" -Name "Architecture" -Value $($Script:AppInfo.AppArchitecture) -Force -ErrorAction SilentlyContinue|Out-Null
                        New-ItemProperty -Path "$RegTag\$Application" -Name "Status" -Value "UpToDate" -Force -ErrorAction SilentlyContinue|Out-Null
                        If (-not([string]::IsNullOrWhiteSpace($Script:AppInfo.AppInstallLanguage))){New-ItemProperty -Path "$RegTag\$Application" -Name "Language" -Value $($Script:AppInfo.AppInstallLanguage) -Force -ErrorAction SilentlyContinue|Out-Null}
                    
                        ##== Create Scheduled task
                        Write-EckLog "Creating Update Evaluation Scheduled Task !" -LogPath $log
                        $ScriptBlock_UpdateEval = {
                            ##== Functions
                            function Write-EckLog 
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
                                                    Write-EckLog "Latest verion available online: $($AppEverGreenInfo.Version)"

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

                        $TaskName = "EverGreen Update Evaluation"
                        $SchedulerPath = "\Microsoft\Windows\PowerShell\ScheduledJobs"
                        $trigger = New-JobTrigger -Daily -At 12:00
                        $options = New-ScheduledJobOption -StartIfOnBattery  -RunElevated

                        If((Get-LocalUser "service.scheduler" -ErrorAction SilentlyContinue).Enabled -eq $true){Remove-LocalUser "service.scheduler" -Confirm:$False -ErrorAction SilentlyContinue}
                        $password = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
                        $user = New-LocalUser "service.scheduler" -Password $Password -Description "For scheduling in tasks from system account" -ErrorAction SilentlyContinue
                        $credentials = New-Object System.Management.Automation.PSCredential($user.name, $password)

                        $task = Get-ScheduledTask -taskname $taskName -ErrorAction SilentlyContinue
                        if ($null -ne $task){Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false}

                        Register-ScheduledJob -Name $taskName  -Trigger $trigger -ScheduledJobOption $options -ScriptBlock $ScriptBlock_UpdateEval -Credential $credentials -ErrorAction SilentlyContinue|Out-Null
                        $principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highes
                        Set-ScheduledTask -TaskPath $SchedulerPath -TaskName $taskName -Principal $principal|Out-Null
                        Remove-LocalUser "service.scheduler" -Confirm:$False -ErrorAction SilentlyContinue
                        Write-EckLog "Update Evaluation Scheduled task installed successfully under name $Taskname!" -LogPath $log
                                
                    
                    }
            }
        Else
        
        ##############################
        #### Application Uninstallation
        ##############################

            {
                If ($Script:AppInfo.AppIsInstalled -eq $False)
                    {Write-EckLog "Application $Application is not installed, nothing to uninstall ! All operation finished!!" -LogPath $log}
                Else
                    {
                        ##== Uninstall
                        Write-EckLog "About to run $($Script:AppInfo.AppUninstallCMD) $($Script:AppInfo.AppUninstallParameters)" -LogPath $log
                        $Iret = (Start-Process $Script:AppInfo.AppUninstallCMD -ArgumentList $Script:AppInfo.AppUninstallParameters -Wait -Passthru).ExitCode
                        If ($Script:AppInfo.AppUninstallSuccessReturnCodes -contains $Iret)
                            {Write-EckLog "Application $Application - version $($Script:AppInfo.AppInstalledVersion) Uninstalled Successfully !!!" -LogPath $log}
                        Else
                            {Write-EckLog "[Warning] Application $Application - version $($Script:AppInfo.AppInstalledVersion) returned code $Iret while trying to uninstall !!!" -Type 2 -LogPath $log}

                        ##== Additionnal removal action
                        Write-EckLog "Uninstalling additionnal items !" -LogPath $log
                        Invoke-AdditionalUninstall
                        Remove-Item "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application" -Recurse -Force -ErrorAction SilentlyContinue
                    }
            }


        ##############################
        #### Post-Script
        ##############################
        If ($PostScriptURI)
            {
                Write-EckLog "Invoking Postscript" -LogPath $log
                If ($GithubToken){$PostScript = Get-ECKGithubContent -URI $PostScriptURI -GithubToken $GithubToken} Else {$PostScript = Get-ECKGithubContent -URI $PostScriptURI}
                Try {Invoke-Command $PostScript}
                Catch {Write-EckLog "[Error] Postscript Failed to execute" -Type 3 -LogPath $log}
            }

        $FinishTime = [DateTime]::Now
        Write-EckLog "***************************************************************************************************" -LogPath $log
        Write-EckLog "Finished processing time: [$FinishTime]" -LogPath $log
        Write-EckLog "Operation duration: [$(($FinishTime - $StartupTime).ToString())]" -LogPath $log
        Write-EckLog "All Operations for $Application Finished!! Exit !" -LogPath $log
        Write-EckLog "***************************************************************************************************" -LogPath $log 
     }   
Catch
    {
        Write-EckLog "[ERROR] Fatal Error, the program has stopped !!!" -Type 3 -LogPath $log
        Write-EckLog $Error[0].InvocationInfo.PositionMessage.ToString() -type 3 -LogPath $log
        Write-EckLog $Error[0].Exception.Message.ToString() -type 3 -LogPath $log
        Exit 99
    }           