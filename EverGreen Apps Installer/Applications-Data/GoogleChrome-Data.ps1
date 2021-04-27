# Version 0.18

Function Get-AppInfo
    {
        [PSCustomObject]@{
            AppName = "GoogleChrome"
            AppVendor = "Google"
            AppFiendlyName = "Chrome"
            AppInstallName = "Google Chrome"
            AppExtension = ".msi"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallCMD = "MsiExec"
            AppInstallParameters = "/i ##APP## ALLUSERS=1 /qb"
            AppInstallSuccessReturnCodes = @(0,3010)
            AppUninstallSuccessReturnCodes = @(0,3010)
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
        Else        
            {Return $False}
    }


Function Invoke-AdditionalUninstall
    {
        $UninstallFeature_ScriptBlock = { 
                $FolderList = @("C:\Program Files\google","C:\Program Files (x86)\google")
                Foreach ($Folder in $FolderList)
                    {
                        If (Test-Path $Folder){Get-childitem $folder|Remove-Item -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue}
                    }

                $CurrentUser = (Get-CimInstance –ClassName Win32_ComputerSystem | Select-Object -expand UserName)
                $CurrentUserSID = (New-Object System.Security.Principal.NTAccount($CurrentUser)).Translate([System.Security.Principal.SecurityIdentifier]).value
                $CurrentUserProfilePath = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'| Where-Object {$PSItem.pschildname -eq $CurrentUserSID}|Get-ItemPropertyValue -Name ProfileImagePath)
                
                If (Test-Path ("$CurrentUserProfilePath\Desktop\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\Desktop\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}

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
                set-Service GoogleChromeElevationService -StartupType Disabled -Status Stopped
                set-Service Gupdate -StartupType Disabled -Status Stopped
                set-Service Gupdatem -StartupType Disabled -Status Stopped
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false
                sc.exe delete "GUpdate"
                sc.exe delete "GUpdatem"
            }

        If ($Script:AppInfo.AppInstallArchitecture -eq 'X86')
            {
                $Path1 = "C:\Program Files\Google\Update"
                $Path2 = "C:\Program Files\Google\NOUpdate"
                $AdditionalScriptBlock = {
                        $attempts = 1
                        While (-not(Test-path "C:\Program Files\Google\NOUpdate") -and $attempts -le 15)
                            {
                                Rename-Item "C:\Program Files\Google\Update" -NewName "NOUpdate" -Force -ErrorAction SilentlyContinue
                                Start-Sleep 1
                                $attempts += 1                               
                            }
                    }
            }
        Else
            {
                $Path1 = "C:\Program Files (x86)\Google\Update"
                $Path2 = "C:\Program Files (x86)\Google\NOUpdate"
                $AdditionalScriptBlock = {
                        $attempts = 1
                        While (-not(Test-path "C:\Program Files (x86)\Google\NOUpdate") -and $attempts -le 15)
                            {
                                Rename-Item "C:\Program Files (x86)\Google\Update" -NewName "NOUpdate" -Force -ErrorAction SilentlyContinue
                                Start-Sleep 1
                                $attempts += 1                               
                            }
                    }
            }

        $DisableUpdate_ScriptBlock = [ScriptBlock]::Create($DisableUpdate_ScriptBlock.ToString() + $AdditionalScriptBlock.ToString())
        
        If ($Script:TsEnv.CurrentUserIsSystem)
            {Invoke-Command -ScriptBlock $DisableUpdate_ScriptBlock}
        Else
            {Invoke-AsSystemNow -ScriptBlock $DisableUpdate_ScriptBlock}


        If (-Not (Test-path $Path1) -and (Test-path $Path2))
            {Write-log "Update feature disabled successfully for $($Script:AppInfo.AppInstallName) !"}
        Else
            {Write-log "[Error] Unable to remove Update feature for $($Script:AppInfo.AppInstallName) !" -Type 3} 

    }
