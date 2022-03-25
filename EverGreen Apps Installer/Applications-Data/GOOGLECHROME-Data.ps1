# Version 0.24 - 25/03/2022

Function Get-AppInfo
    {
        param (
            [Parameter(Mandatory = $false)]
            [string]$Architecture,
            [Parameter(Mandatory = $false)]
            [string]$Language,
            [Parameter(Mandatory = $false)]
            [string]$Channel,            
            [Parameter(Mandatory = $false)]
            [bool]$DisableUpdate,
            [Parameter(Mandatory = $false)]
            [bool]$EnterpriseMode
        )
         
        [PSCustomObject]@{
            AppName = "GoogleChrome"
            AppVendor = "Google"
            AppFiendlyName = "Chrome"
            AppInstallName = "Google Chrome"
            AppPtaName = "ChromeHTML"
            AppExtension = ".msi"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallArchitecture = $($Architecture.ToUpper())
            AppInstallLanguage = $($Language.ToUpper())
            AppInstallChannel = $($Channel.ToUpper())
            AppInstallCMD = "MsiExec"
            AppInstallParameters = "/i ##APP## ALLUSERS=1 /qb"
            AppInstallSuccessReturnCodes = @(0,3010,1641)
            AppUninstallSuccessReturnCodes = @(0,3010,1641)
            AppMustUninstallBeforeUpdate = $false
            AppMustUninstallOnArchChange = $true
        }
    }


Function Get-AppInstallStatus
    {
        ##== Check if Application is Already installed 
        If (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X64)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X64'
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0]
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb")
            }  
        Elseif (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X86)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X86'
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0]
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb")
            }
        Else
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $false
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value $null
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $null
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $null
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $null
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $null
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $null
            }
    } 


Function Get-AppUpdateStatus
    {    
        # Return $True if the application need to updated
        If ([version]($Script:AppEverGreenInfo.Version) -gt [version]$Script:AppInfo.AppInstalledVersion)
            {Return $True}
        ElseIf ($Script:AppInfo.AppInstallArchitecture -ne $Script:AppInfo.AppArchitecture)
            {Return $True}
        Else        
            {Return $False}
    }


Function Invoke-AdditionalInstall
    {
        [Parameter(Mandatory = $false)]
        [bool]$SetAsDefault,
        [Parameter(Mandatory = $false)]
        [bool]$EnterpriseMode,
        [Parameter(Mandatory = $false)]
        [bool]$DisableUpdate

        If ($SetAsDefault)
            {
                $Script_LogPath = "`$ContentPath = ""$($script:ContentPath)"" `n"
                $Script_InstallName = "`$PTAName = ""$($Script:AppInfo.AppPtaName)"" `n"
 
                $Script_Assoc = {
                        ."$ContentPath\SFTA.ps1"
                        Set-PTA $PTAName http
                        Set-PTA $PTAName https
                    }

                $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_InstallName.ToString() + $Script_Assoc.ToString())

                Invoke-ECKScheduledTask -HostScriptPath $CurrentScriptFullName -TaskName 'Set-Assoc' -Context user -LogPath $LogDir -ScriptBlock $Script_Assoc -now -DontAutokilltask

            }

        If ($EnterpriseMode)
            {

            } 

    }


Function Invoke-AdditionalUninstall
    {
        $UninstallFeature_ScriptBlock = { 
                $FolderList = @("C:\Program Files\google","C:\Program Files (x86)\google")
                Foreach ($Folder in $FolderList)
                    {
                        If (Test-Path $Folder){Get-childitem $folder|Remove-Item -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue}
                    }

                $CurrentUser = $(Get-CimInstance -classname Win32_ComputerSystem | Select-Object -expand UserName)
                If ([String]::IsNullOrWhiteSpace($CurrentUser))
                    {
                        # Get user when in Windows Sandbox
                        If ((Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount=True AND Disabled=False AND Status='OK'").Name -eq 'WDAGUtilityAccount')
                            {$CurrentUser = "$($env:COMPUTERNAME)\WDAGUtilityAccount"}
                        # Get Azure AD User
                        Else
                            {
                                If([string]::IsNullOrWhiteSpace($(Get-PSDrive -Name HKU -ErrorAction SilentlyContinue))){New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | out-null}
                                $UserReg = Get-Itemproperty "HKU:\*\Volatile Environment"
                                $CurrentLoggedOnUser = "$($UserReg.USERDOMAIN)\$($UserReg.USERNAME)"
                                $CurrentLoggedOnUserSID = split-path $UserReg.PSParentPath -leaf
                                If(Get-ChildItem HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $CurrentLoggedOnUserSID}){$CurrentUser = $CurrentLoggedOnUser}
                            }
                    }

                If ([String]::IsNullOrWhiteSpace($CurrentUser)){Write-log "[ERROR] Unable to detect current user, Aborting...." ; Return}

                $CurrentUserSID = (New-Object System.Security.Principal.NTAccount($CurrentUser)).Translate([System.Security.Principal.SecurityIdentifier]).value
                $CurrentUserProfilePath = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'| Where-Object {$PSItem.pschildname -eq $CurrentUserSID}|Get-ItemPropertyValue -Name ProfileImagePath)
                
                If (Test-Path ("$CurrentUserProfilePath\Desktop\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\Desktop\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}

                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false -ErrorAction SilentlyContinue
                sc.exe delete "GUpdate"
                sc.exe delete "GUpdatem"
            }

        If ($Script:TsEnv.CurrentUserIsSystem)
            {Invoke-Command -ScriptBlock $UninstallFeature_ScriptBlock}
        Else
            {Invoke-AsSystemNow -ScriptBlock $UninstallFeature_ScriptBlock|Out-Null}

        If (Test-Path ("$($Script:TsEnv.CurrentUserProfilePath)\Desktop\Google Chrome.lnk")){Remove-Item "$($Script:TsEnv.CurrentUserProfilePath)\Desktop\Google Chrome.lnk" -Force|Out-Null}
        If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}

        If (Test-path "C:\Program Files\google"){Remove-Item "C:\Program Files\google" -Force -Confirm:$false}
        If (Test-path "C:\Program Files (x86)\google"){Remove-Item "C:\Program Files (x86)\google" -Force -Confirm:$false}

        If ($Script:AppInfo.AppInstallArchitecture -eq 'X86')
            {
                If (-not(Test-path "C:\Program Files\google"))
                    {Write-log "Successfully uninstalled additional componants  for $($Script:AppInfo.AppInstallName) !"}
                Else
                    {Write-log "[Error] Unable to uninstall additional componants for $($Script:AppInfo.AppInstallName) !" -Type 3} 
            }
        Else
            {
                If (-Not (Test-path "C:\Program Files (x86)\google\*") -and -not(Test-path "C:\Program Files\google"))
                    {Write-log "Successfully uninstalled additional componants  for $($Script:AppInfo.AppInstallName) !"}
                Else
                    {Write-log "[Error] Unable to uninstall additional componants for $($Script:AppInfo.AppInstallName) !" -Type 3} 
            }
    }


Function Invoke-DisableUpdateCapability
    {
        $DisableUpdate_ScriptBlock = { 
                Start-Sleep 5
                Set-Service GoogleChromeElevationService -StartupType Disabled -Status Stopped -ErrorAction SilentlyContinue
                Set-Service Gupdate -StartupType Disabled -Status Stopped -ErrorAction SilentlyContinue
                Set-Service Gupdatem -StartupType Disabled -Status Stopped -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false -ErrorAction SilentlyContinue
                Sc.exe delete "GUpdate"
                Sc.exe delete "GUpdatem"

                $FolderList = @("C:\Program Files\google\Update","C:\Program Files (x86)\google\Update")
                Foreach ($Folder in $FolderList){If (Test-Path $Folder){Rename-Item $Folder -NewName "NOUpdate" -Force -ErrorAction SilentlyContinue}}
            }

       
        If ($Script:TsEnv.CurrentUserIsSystem)
            {Invoke-Command -ScriptBlock $DisableUpdate_ScriptBlock}
        Else
            {Invoke-AsSystemNow -ScriptBlock $DisableUpdate_ScriptBlock}
        
        $FolderList = @("C:\Program Files\google\NOUpdate","C:\Program Files (x86)\google\NOUpdate")
        Foreach ($Folder in $FolderList)
            {
                If (Test-Path $Folder)
                    {
                        Write-log "Update feature disabled successfully for $($Script:AppInfo.AppInstallName) !"
                        $Success = $True
                        Break
                    }
            }

        If ($Success -ne $True){Write-log "[Error] Unable to remove Update feature for $($Script:AppInfo.AppInstallName) !" -Type 3} 
    }
