# Version 0.1

Function Get-AppInfo
    {
        param (
            [Parameter(Mandatory = $false)]
            [string]$Architecture,
            [Parameter(Mandatory = $false)]
            [string]$Language,
            [Parameter(Mandatory = $false)]
            [bool]$DisableUpdate,
            [Parameter(Mandatory = $false)]
            [bool]$EnterpriseMode
        )          
        
        $InstParam = '-sfx_nu /sPB /rs /msi EULA_ACCEPT=YES ENABLE_CHROMEEXT=0 DISABLE_BROWSER_INTEGRATION=1 ENABLE_OPTIMIZATION=YES ADD_THUMBNAILPREVIEW=0'
        If ($DisableUpdate){$InstParam = $InstParam + ' UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1'}
        If ($EnterpriseMode){$InstParam = $InstParam + ' DISABLEDESKTOPSHORTCUT=1'} 
            
        If ([String]::IsNullOrWhiteSpace($Language)){$Language = "English"}       
        
        [PSCustomObject]@{
            AppName = "AdobeAcrobatReaderDC"
            AppVendor = "Adobe"
            AppFiendlyName = "Acrobat Reader DC"
            AppInstallName = "Adobe Acrobat Reader DC"
            AppExtension = ".exe"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallArchitecture = $($Architecture.ToUpper())
            AppInstallLanguage = $($Language.ToUpper())
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
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X64'
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0]
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $((($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb").replace("/I","/x "))
            }  
        Elseif (($null -ne ($AppRegUninstall = Get-ItemProperty "$($Script:AppInfo.AppDetection_X86)\*" | Where-Object { $_.DisplayName -like "*$($Script:AppInfo.AppInstallName)*" })))
            {
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppIsInstalled' -Value $true
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppArchitecture' -Value 'X86'
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppDetection' -Value $AppRegUninstall.PsPath
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCommand' -Value $AppRegUninstall.UninstallString
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppInstalledVersion' -Value $AppRegUninstall.DisplayVersion
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallCMD' -Value $($Script:AppInfo.AppUninstallCommand).Split(" ")[0]
                $Script:AppInfo|Add-Member -MemberType NoteProperty -Name 'AppUninstallParameters' -Value $((($Script:AppInfo.AppUninstallCommand).Replace($Script:AppInfo.AppUninstallCMD, "").trim() + " /qb").replace("/I","/x "))
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
                Write-log "Setting File Association"
                Set-DefaultFileAssociation -AppToDefault "AcroExch.Document.DC" -ProtocolExt ".pdf"
            }

        If ($EnterpriseMode)
            {
                If (test-path "C:\Users\Public\Desktop\Acrobat Reader DC.lnk")
                    {
                        Write-log "Removing desktop Icon"
                        Remove-Item "C:\Users\Public\Desktop\Acrobat Reader DC.lnk" -Force -ErrorAction SilentlyContinue|Out-Null
                    }

                Write-log "Disabling first tour welcome Popup"
                if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -force -ea SilentlyContinue }
                New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen' -Name 'bShowWelcomeScreen' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue

                $ScriptBlock_firstTour = {
                        $Reg = "HKCU:\SOFTWARE\Adobe\Acrobat Reader\DC\FTEDialog"
                        if((Test-Path -LiteralPath $Reg) -ne $true) {New-Item $Reg -force -ea SilentlyContinue }
                        New-ItemProperty -LiteralPath $Reg -Name 'bWelcomeCard_RdrInstall' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
                        New-ItemProperty -LiteralPath $Reg -Name 'iLastCardShown' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
                    }

                Invoke-AsCurrentUser -ScriptBlock $ScriptBlock_firstTour

            } 
    }


Function Invoke-AdditionalUninstall
    {

    }


Function Invoke-DisableUpdateCapability
    {
        Write-log "Removing Adobe Scheduled task"
        Unregister-ScheduledTask -TaskName "Adobe Acrobat Update Task" -Confirm:$false -ErrorAction SilentlyContinue
        
        If (Get-service "AdobeARMService" -ErrorAction SilentlyContinue)
            {
                Write-log "Removing Adobe service"
                sc.exe delete "AdobeARMService"
            }
        
        
        Write-log "Hiding Search for update in menu"
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -force -ea SilentlyContinue }
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' -Name 'bUpdater' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue
    }
