#Requires -Version 5
##Requires -RunAsAdministrator 

[CmdletBinding()]
param(

        [string]$GithubRepo = "https://github.com/Diagg/EverGreen-Application-Installer",

        [string]$Log = "$env:Windir\Logs\EvergreenApplication\EverGreen-UpdateEvaluation.log",

        [string]$GithubToken,

        [string]$UpdatePolicyURI = "https://github.com/Diagg/EverGreen-Application-Installer/blob/master/EverGreen%20Apps%20Installer/Defaul-UpdatePolicy.json"
     )


##== Debug
$ErrorActionPreference = "stop"
#$ErrorActionPreference = "Continue"

##== Global Variables
$Script:CurrentScriptName = $MyInvocation.MyCommand.Name
$Script:CurrentScriptFullName = $MyInvocation.MyCommand.Path
$Script:CurrentScriptPath = split-path $MyInvocation.MyCommand.Path
$Script:Log = $Log

#region Functions
function Write-log 
    {
        #v1.1 - 21/07/2021 - redirect logs to %temp% if unauthorized access rights 

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
        Try
            {$Content|Out-File $Path -Append -ErrorAction SilentlyContinue -Encoding utf8}
        Catch [System.UnauthorizedAccessException]
            {$Content|Out-File "$env:temp\$(Split-Path $Path -Leaf)" -Append -ErrorAction SilentlyContinue -Encoding utf8}
    }


Function Get-GithubContent
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
                        $Fileraw = Invoke-WebRequest -URI $URI -UseBasicParsing
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
#endregion

#region Main
##== Main
#Try
#    {
        $StartupTime = [DateTime]::Now
        Write-log 
        Write-log "***************************************************************************************************"
        Write-log "***************************************************************************************************"
        Write-log "Started processing time: [$StartupTime]"
        Write-log "Script Name: ApplicationUpdateEvaluation"
        Write-log "***************************************************************************************************"

        #Load Application Update Policy.
        Write-log "Retrieving Update ploicy from URI $UpdatePolicyURI"
        If ($GithubToken){$JsonUpdatePolicy = Get-GithubContent -URI $UpdatePolicyURI -GithubToken $GithubToken} Else {$JsonUpdatePolicy = Get-GithubContent -URI $UpdatePolicyURI}
        If ([String]::IsNullOrWhiteSpace($JsonUpdatePolicy)){Write-log "[ERROR] Unable to download Application Update policy, Aborting...." ; Exit}
        $ApplicationUpdatePolicy = $JsonUpdatePolicy|ConvertFrom-Json


        # Check for updates
        $RegTag = "HKLM:\SOFTWARE\OSDC\EverGreenInstaller"
        If (test-path $RegTag)
            {
                $EverGreenApps = (Get-ChildItem $RegTag).PSChildName

                ForEach ($Regitem in $EverGreenApps)
                    {
                        $AppInfo = Get-ItemProperty -Path "$RegTag\$Regitem"
                        If (-not ([string]::IsNullOrWhiteSpace($AppInfo)))
                            {
                                Write-log "Application : $Regitem"
                                If (-not([String]::IsNullOrWhiteSpace($ApplicationUpdatePolicy.$($Regitem))))
                                    {
                                        Write-log "Update Policy : Retrived"
                                        Write-log "Update unabled : $($ApplicationUpdatePolicy.$($Regitem).Update)"
                                        Write-log "Postpone Update days : $($ApplicationUpdatePolicy.$($Regitem).DaysToPostPone)"
                                        Write-log "Postpone Update Hours : $($ApplicationUpdatePolicy.$($Regitem).HoursToPostPone)"
                                    } 
                                Else 
                                    {Write-log "Update Policy : Undefined"}
                                
                                $AppInstalledVersion = $AppInfo.Version
                                $AppInstalledArchitecture = $AppInfo.Architecture
                                $AppInstalledLanguage = $AppInfo.Language
                                Write-log "Installed version : $AppInstalledVersion"
                                Write-log "Installed Architecture : $AppInstalledArchitecture"
                                If (-not([string]::IsNullOrWhiteSpace($AppInstalledLanguage)))
                                    {
                                        Write-log "Installed Language : $AppInstalledLanguage"
                                        $AppEverGreenInfo = Get-EvergreenApp -Name $Regitem | Where-Object {$_.Architecture -eq $AppInstalledArchitecture -and $_.Language -eq $AppInstalledLanguage}
                                    }
                                Else
                                    {$AppEverGreenInfo = Get-EvergreenApp -Name $Regitem | Where-Object $_.Architecture -eq $AppInstalledArchitecture}

                                Write-log "Checking for Newer version online..."
                                Write-log "Latest verion available online: $($AppEverGreenInfo.Version)"

                                If ([version]($AppEverGreenInfo.Version) -gt [version]$AppInstalledVersion)
                                    {
                                        Set-ItemProperty "$RegTag\$Regitem" -name 'Status' -Value "Obsolete" -force -ErrorAction SilentlyContinue|Out-Null
                                        Write-log "$Regitem application status changed to Obsolete !"
                                    }
                        
                                If (Get-ItemProperty -Path "$RegTag\$Regitem" -Name "LatestUpdateScan")
                                    {Set-ItemProperty "$RegTag\$Regitem" -name 'LatestUpdateScan' -Value $([DateTime]::Now) -force -ErrorAction SilentlyContinue|Out-Null}
                                Else
                                    {New-ItemProperty -Path "$RegTag\$Regitem" -Name "LatestUpdateScan" -Value $([DateTime]::Now) -Force -ErrorAction SilentlyContinue|Out-Null}    
                            }
                    }
                }

        $FinishTime = [DateTime]::Now
        Write-log "***************************************************************************************************"
        Write-log "Finished processing time: [$FinishTime]"
        Write-log "Operation duration: [$(($FinishTime - $StartupTime).ToString())]"
        Write-log "All Operations Finished!! Exit !"
        Write-log "***************************************************************************************************"
<#
     }   
Catch
    {
        Write-host $Error[0].Exception.GetType().FullName
        Write-log "[ERROR] Fatal Error, the program has stopped !!!" -Type 3
        Write-log $Error[0].InvocationInfo.PositionMessage.ToString() -type 3
        Write-log $Error[0].Exception.Message.ToString() -type 3
    }  
#>
#endregion  