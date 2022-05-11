# Version 0.37 - 11/05/2022

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
            [bool]$UpdateWithGreenstaller,
            [Parameter(Mandatory = $false)]
            [bool]$EnterpriseMode,
            [Parameter(Mandatory = $false)]
            [bool]$AppInstallNow,
            [Parameter(Mandatory = $false)]
            [bool]$AppUnInstallNow,
            [Parameter(Mandatory = $false)]
            [bool]$SetAsDefault
        )
         
        [PSCustomObject]@{
            AppName = "GoogleChrome"
            AppVendor = "Google"
            AppFiendlyName = "Chrome"
            AppInstallName = "Google Chrome"
            AppInstallNow = $AppInstallNow
            AppUnInstallNow = $AppUnInstallNow
            AppExtension = ".msi"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallChannel = $($Channel.ToUpper())           
            AppInstallArchitecture = $($Architecture.ToUpper())
            AppInstallLanguage = $($Language.ToUpper())
            AppInstallOptionDefault = $SetAsDefault
            AppInstallOptionEnterprise = $EnterpriseMode
            AppInstallOptionDisableUpdate = $DisableUpdate
            AppInstallOptionGreenUpdate = $UpdateWithGreenstaller
            AppInstallCMD = "MsiExec"
            AppInstallParameters = "/i ##APP## ALLUSERS=1 /qb"
            AppInstallSuccessReturnCodes = @(0,3010,1641)
            AppUninstallSuccessReturnCodes = @(0,3010,1641)
            AppMustUninstallBeforeUpdate = $true
            AppMustUninstallOnArchChange = $true
        }
    }


Function Get-AppInstallStatus
    {
        ##== Check if Application is Already installed 
        If (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X64)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X64' -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0] -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb") -Force
            }  
        Elseif (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X86)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X86' -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0] -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $(($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb") -Force
            }
        Else
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $false -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value $null -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $null -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $null -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $null -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $null -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $null -Force
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
        If ($Script:AppInfo.AppInstallOptionDefault -or $Script:AppInfo.AppInstallOptionEnterprise)
            {
                # Set Default App Association
                $Script_LogPath = "`$ContentPath = ""$($ECK.ContentPath)"" `n"
 
                $Script_Assoc = {
                        ."$ContentPath\SFTA.ps1"
                        Set-PTA -ProgId ChromeHTML -Protocol http
                        Set-PTA -ProgId ChromeHTML -Protocol https
                        Set-PTA -ProgId ChromeHTML -Protocol .htm
                        Set-PTA -ProgId ChromeHTML -Protocol .html
                    }

                Write-ECKlog "Setting file association for $($Script:AppInfo.AppInstallName) !"
                $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_Assoc.ToString())
                Invoke-ECKScheduledTask -TaskName 'Set-Assoc' -Context user -ScriptBlock $ScriptBlock -now -WaitFinished
            }

        If ($Script:AppInfo.AppInstallOptionEnterprise)
            {
                # Remove Desktop Icon
                If (test-path 'C:\Users\Public\desktop\Google Chrome.lnk')
                    {
                        Write-log "Removing desktop Icon for $($Script:AppInfo.AppInstallName) !"
                        Remove-Item 'C:\Users\Public\desktop\Google Chrome.lnk' -Force -ErrorAction SilentlyContinue|Out-Null
                    }


                # Remove Automatic Updates
                Write-log "Removing automatic update for $($Script:AppInfo.AppInstallName) !"
                $Script:AppInfo.AppInstallOptionDisableUpdate = $true
            } 
    }


Function Invoke-AdditionalUninstall
    {
        $UninstallFeature_ScriptBlock = { 
                $FolderList = @("C:\Program Files\google","C:\Program Files (x86)\google")
                Foreach ($Folder in $FolderList){If (Test-Path $Folder){Get-childitem $folder|Remove-Item -Force -Confirm:$false -Recurse -ErrorAction SilentlyContinue}}

                $CurrentUserProfilePath = $ECK.UserProfile
                
                If (Test-Path ("$CurrentUserProfilePath\Desktop\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\Desktop\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk")){Remove-Item "$CurrentUserProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" -Force|Out-Null}
                If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}

                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" -Confirm:$false -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" -Confirm:$false -ErrorAction SilentlyContinue
                sc.exe delete "GUpdate"
                sc.exe delete "GUpdatem"

            }

        If ($ECK.UserIsSystem -eq $true)
            {Invoke-Command -ScriptBlock $UninstallFeature_ScriptBlock}
        Else
            {Invoke-ECKScheduledTask -ScriptBlock $UninstallFeature_ScriptBlock -Context system -now}

        If (Test-Path ("$($ECK.UserProfilePath)\Desktop\Google Chrome.lnk")){Remove-Item "$($ECK.UserProfilePath)\Desktop\Google Chrome.lnk" -Force|Out-Null}
        If (Test-Path ("C:\Users\Public\Desktop\Google Chrome.lnk")){Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force|Out-Null}

        If (Test-path "C:\Program Files\google"){Remove-Item "C:\Program Files\google" -Force -Confirm:$false}
        If (Test-path "C:\Program Files (x86)\google"){Remove-Item "C:\Program Files (x86)\google" -Force -Confirm:$false}

        If ($Script:AppInfo.AppInstallArchitecture -eq 'X86')
            {
                If (-not(Test-path "C:\Program Files\google"))
                    {Write-ECKlog "Successfully uninstalled additional componants  for $($Script:AppInfo.AppInstallName) !"}
                Else
                    {Write-ECKlog "[Error] Unable to uninstall additional componants for $($Script:AppInfo.AppInstallName) !" -Type 3} 
            }
        Else
            {
                If (-Not (Test-path "C:\Program Files (x86)\google\*") -and -not(Test-path "C:\Program Files\google"))
                    {Write-ECKlog "Successfully uninstalled additional componants  for $($Script:AppInfo.AppInstallName) !"}
                Else
                    {Write-ECKlog "[Error] Unable to uninstall additional componants for $($Script:AppInfo.AppInstallName) !" -Type 3} 
            }

        # Restore Default App Association
        $Script_LogPath = "`$ContentPath = ""$($ECK.ContentPath)"" `n"

        $Script_Assoc = {
                ."$ContentPath\SFTA.ps1"
                Set-PTA -ProgId MSEdgeHTM -Protocol http
                Set-PTA -ProgId MSEdgeHTM -Protocol https
                Set-PTA -ProgId MSEdgeHTM -Protocol .htm
                Set-PTA -ProgId MSEdgeHTM -Protocol .html                
            }

        Write-ECKlog "Restoring default file association !"
        $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_Assoc.ToString())
        Invoke-ECKScheduledTask -TaskName 'Set-Assoc' -Context user -ScriptBlock $ScriptBlock -now -WaitFinished




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

       
        If ($ECK.UserIsSystem -eq $true)
            {Invoke-Command -ScriptBlock $DisableUpdate_ScriptBlock}
        Else
            {Invoke-ECKScheduledTask -ScriptBlock $DisableUpdate_ScriptBlock -Context system -now}
        
        $FolderList = @("C:\Program Files\google\NOUpdate","C:\Program Files (x86)\google\NOUpdate")
        Foreach ($Folder in $FolderList)
            {
                If (Test-Path $Folder)
                    {
                        Write-ECKlog "Update feature disabled successfully for $($Script:AppInfo.AppInstallName) !"
                        $Success = $True
                        Break
                    }
            }

        If ($Success -ne $True){Write-ECKlog "[Error] Unable to remove Update feature for $($Script:AppInfo.AppInstallName) !" -Type 3} 
    }