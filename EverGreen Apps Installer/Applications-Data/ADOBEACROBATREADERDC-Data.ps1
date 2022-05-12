# Version 0.30 - 12/05/2022 

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
        
        # Default Settings
        $Architecture = "X86"
        $Channel = $Null
        $InstParam = '-sfx_nu /sPB /rs /msi EULA_ACCEPT=YES ENABLE_CHROMEEXT=0 DISABLE_BROWSER_INTEGRATION=1 ENABLE_OPTIMIZATION=YES ADD_THUMBNAILPREVIEW=0'
        
        If ([String]::IsNullOrWhiteSpace($Language)){$Language = "English"}
        If ($DisableUpdate -or $EnterpriseMode){$InstParam = $InstParam + ' UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1'}
        If ($EnterpriseMode){$InstParam = $InstParam + ' DISABLEDESKTOPSHORTCUT=1'} 
            
              
        
        # Application Object
        [PSCustomObject]@{
            AppName = "AdobeAcrobatReaderDC"
            AppVendor = "Adobe"
            AppFiendlyName = "Acrobat Reader DC"
            AppInstallName = "Adobe Acrobat Reader DC"
            AppInstallNow = $AppInstallNow
            AppUnInstallNow = $AppUnInstallNow
            AppExtension = ".exe"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallChannel = $($Channel.ToUpper())           
            AppInstallArchitecture = $($Architecture.ToUpper())
            AppInstallLanguage = $($Language.ToUpper())
            AppInstallOptionDefault = $SetAsDefault
            AppInstallOptionEnterprise = $EnterpriseMode
            AppInstallOptionDisableUpdate = $DisableUpdate
            AppInstallOptionGreenUpdate = $UpdateWithGreenstaller
            AppInstallCMD = "##APP##"
            AppInstallParameters = $InstParam
            AppInstallSuccessReturnCodes = @(0,3010,1641)
            AppUninstallSuccessReturnCodes = @(0,3010,1641)
            AppMustUninstallBeforeUpdate = $true
            AppMustUninstallOnArchChange = $true
        }
    }


Function Get-AppInstallStatus
    {
        ##== Check if Application is Already installed 
        If (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X64)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)*" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true  -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X64' -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0] -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $((($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb").replace("/I","/x ")) -Force
            }  
        Elseif (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X86)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)*" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X86' -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0] -Force
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $((($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb").replace("/I","/x ")) -Force
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
                        Set-PTA -ProgId AcroExch.Document.DC -Protocol .pdf
                        Set-PTA -ProgId AcroExch.Document.DC -Protocol .pdfxml
                    }

                Write-ECKlog "Setting file association for $($Script:AppInfo.AppInstallName) !"
                $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_Assoc.ToString())
                Invoke-ECKScheduledTask -TaskName 'Set-Assoc' -Context user -ScriptBlock $ScriptBlock -now -WaitFinished
            }

        If ($Script:AppInfo.AppInstallOptionEnterprise)
            {
                # Remove Desktop Icon
                If (test-path "C:\Users\Public\Desktop\Acrobat Reader DC.lnk")
                    {
                        Write-ECKlog "Removing desktop Icon for $($Script:AppInfo.AppInstallName) !"
                        Remove-Item "C:\Users\Public\Desktop\Acrobat Reader DC.lnk" -Force -ErrorAction SilentlyContinue|Out-Null
                    }


                # Remove Automatic Updates
                Write-ECKlog "Removing automatic update for $($Script:AppInfo.AppInstallName) !"
                $Script:AppInfo.AppInstallOptionDisableUpdate = $true

                # Remove Welcome message
                Write-ECKlog "Disabling first tour welcome Popup"
                if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -force -ea SilentlyContinue|Out-Null }
                New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen' -Name 'bShowWelcomeScreen' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue|Out-Null

                # Remove 'Try Adobe Pro DC' button
                Write-ECKlog "Disabling advertising button"
                if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -force -ea SilentlyContinue|Out-Null }
                New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'bAcroSuppressUpsell' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue|Out-Null


                $ScriptBlock_firstTour = {
                        $Reg = "HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\FTEDialog"
                        if((Test-Path -LiteralPath $Reg) -ne $true) {New-Item $Reg -force -ea SilentlyContinue }
                        New-ItemProperty -LiteralPath $Reg -Name 'iFTEVersion' -Value 0x0000000a -PropertyType DWord -Force -ea SilentlyContinue
                        New-ItemProperty -LiteralPath $Reg -Name 'iLastCardShown' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
                    }

                Invoke-ECKScheduledTask -TaskName 'Disable-AdobeFirstTour' -Context user -ScriptBlock $ScriptBlock_firstTour -now -WaitFinished

            } 
    }


Function Invoke-AdditionalUninstall
    {

        # Restore Default App Association
        $Script_LogPath = "`$ContentPath = ""$($ECK.ContentPath)"" `n"

        $Script_Assoc = {
                ."$ContentPath\SFTA.ps1"
                Set-PTA -ProgId MSEdgeHTM -Protocol .pdf                
            }

        Write-ECKlog "Restoring default file association !"
        $ScriptBlock = [ScriptBlock]::Create($Script_LogPath.ToString() + $Script_Assoc.ToString())
        Invoke-ECKScheduledTask -TaskName 'Set-Assoc' -Context user -ScriptBlock $ScriptBlock -now -WaitFinished

        Unregister-ScheduledTask -TaskName "Adobe Acrobat Update Task" -Confirm:$false -ErrorAction SilentlyContinue
        If (Get-service "AdobeARMService" -ErrorAction SilentlyContinue){sc.exe delete "AdobeARMService"}

    }


Function Invoke-DisableUpdateCapability
    {
        Write-ECKlog "Removing Adobe Scheduled task"
        Unregister-ScheduledTask -TaskName "Adobe Acrobat Update Task" -Confirm:$false -ErrorAction SilentlyContinue
        
        If (Get-service "AdobeARMService" -ErrorAction SilentlyContinue)
            {
                Write-ECKlog "Removing Adobe service"
                sc.exe delete "AdobeARMService"
            }
        
        
        Write-ECKlog "Hiding Search for update in menu"
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -force -ea SilentlyContinue|Out-Null }
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'bUpdater' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue|Out-Null
    }
