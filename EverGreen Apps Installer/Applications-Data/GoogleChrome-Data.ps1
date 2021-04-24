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
        Param([PsObject]$ObjAppInfo)

        ##== Check if Application is Already installed 
        If (($null -ne ($AppRegUninstall = Get-ItemProperty "$($ObjAppInfo.AppDetection_X64)\*" | Where-Object { $_.DisplayName -like "*$($ObjAppInfo.AppInstallName)" })))
            {
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X64'
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($ObjAppInfo.AppUninstallCommand).Split(" ")[0]
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($ObjAppInfo.AppUninstallCommand).Replace($ObjAppInfo.AppUninstallCMD, "").trim() + " /qb")
            }  
        Elseif (($null -ne ($AppRegUninstall = Get-ItemProperty "$($ObjAppInfo.AppDetection_X86)\*" | Where-Object { $_.DisplayName -like "*$($ObjAppInfo.AppInstallName)" })))
            {
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X86'
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($ObjAppInfo.AppUninstallCommand).Split(" ")[0]
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($ObjAppInfo.AppUninstallCommand).Replace($ObjAppInfo.AppUninstallCMD, "").trim() + " /qb")
            }
        Else
            {
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $false
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value $null
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $null
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $null
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $null
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $null
                $ObjAppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $null
            }

        Return $ObjAppInfo
    } 


Function Get-AppUpdateStatus
    {    
        Param([PsObject]$ObjAppInfo,[PsObject]$GreenAppInfo )

        # Return $True if the application need to updated
        If ([version]($GreenAppInfo.Version) -gt [version]$ObjAppInfo.AppInstalledVersion)
            {Return $True}
        Else        
            {Return $False}
    }


Function Invoke-AdditionalUninstall
    {
        Param([PsObject]$ObjAppInfo)
                
        $FolderList = @("C:\Program Files (x86)\Google", "C:\Program Files\Google")
        Foreach ($Folder in $FolderList)
            {
                 If (Test-Path $Folder)
                    {
                        If ($Script:TsEnv.CurrentUserIsSystem)
                            {Remove-Item $Folder -Force -Recurse|Out-Null}
                        Else
                            {Invoke-AsSystemNow -ScriptBlock {Remove-Item $Folder -Force -Recurse|Out-Null}}
                    }
            }

        If (Test-Path ("$($Script:TsEnv.CurrentUserProfilePath)\Desktop\Google Chrome.lnk")){Remove-Item "$($Script:TsEnv.CurrentUserProfilePath)\Desktop\Google Chrome.lnk" -Force|Out-Null}
        If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}
    }


Function Invoke-DisableUpdateCapability
    {
        Param([PsObject]$ObjAppInfo)
        
        $DisableUpdate_ScriptBlock = { 
                set-Service GoogleChromeElevationService -StartupType Disabled -Status Stopped
                set-Service Gupdate -StartupType Disabled -Status Stopped
                set-Service Gupdatem -StartupType Disabled -Status Stopped
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false
            }

        If ($ObjAppInfo.AppInstallArchitecture -eq 'X64')
            {
                $Path1 = "C:\Program Files\Google\Update"
                $Path2 = "C:\Program Files\Google\NOUpdate"
                $AdditionalScriptBlock = {Rename-Item "C:\Program Files\Google\Update" -NewName "C:\Program Files\Google\NOUpdate" -Force}
            }
        Else
            {
                $Path1 = "C:\Program Files (x86)\Google\Update"
                $Path2 = "C:\Program Files (x86)\Google\NOUpdate"
                $AdditionalScriptBlock = {Rename-Item "C:\Program Files (x86)\Google\Update" -NewName "C:\Program Files (x86)\Google\NOUpdate" -Force}
            }

        $DisableUpdate_ScriptBlock = [ScriptBlock]::Create($DisableUpdate_ScriptBlock.ToString() + $AdditionalScriptBlock.ToString())
        
        If ($UserIsSystem)
            {$Iret = Invoke-Command -ScriptBlock $DisableUpdate_ScriptBlock}
        Else
            {$Iret = Invoke-AsSystemNow -ScriptBlock $DisableUpdate_ScriptBlock}


        If (-Not (Test-path $Path1) -and (Test-path $Path2))
            {Write-log "Update feature disabled successfully for $($ObjAppInfo.AppInstallName) !" ; Return $true}
        Else
            {Write-log "[Error] Unable to remove Update feature for $($ObjAppInfo.AppInstallName) !" -Type 3} 

    }



