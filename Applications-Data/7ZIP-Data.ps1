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
        If ($ECK.OSArchitectureIsX64 -eq $true)
            {If ([String]::IsNullOrWhiteSpace($Architecture)){$Architecture = "X64"}}
        Else
            {If ([String]::IsNullOrWhiteSpace($Architecture)){$Architecture = "X86"}}    

        
        If ([String]::IsNullOrWhiteSpace($Channel)){$Channel = $null}

       
        # Application Object
        [PSCustomObject]@{
            AppName = "7zip"
            AppVendor = "Igor Pavlov"
            AppFiendlyName = "7zip"
            AppInstallName = "Igor Pavlov 7-zip"
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
                        Set-PTA -ProgId 7-Zip.7z -Protocol .7z
                        Set-PTA -ProgId 7-Zip.arj -Protocol .arj
                        Set-PTA -ProgId 7-Zip.bz2 -Protocol .bz2
                        Set-PTA -ProgId 7-Zip.bzip2 -Protocol .bzip2
                        Set-PTA -ProgId 7-Zip.cab -Protocol .cab
                        Set-PTA -ProgId 7-Zip.cpio -Protocol .cpio
                        Set-PTA -ProgId 7-Zip.deb -Protocol .deb
                        Set-PTA -ProgId 7-Zip.dmg -Protocol .dmg
                        Set-PTA -ProgId 7-Zip.gz -Protocol .gz                                               
                        Set-PTA -ProgId 7-Zip.gzip -Protocol .gzip
                        Set-PTA -ProgId 7-Zip.hfs -Protocol .hfs
                        Set-PTA -ProgId 7-Zip.lha -Protocol .lha
                        Set-PTA -ProgId 7-Zip.lzh -Protocol .lzh
                        Set-PTA -ProgId 7-Zip.lzma -Protocol .lzma
                        Set-PTA -ProgId 7-Zip.rar -Protocol .rar
                        Set-PTA -ProgId 7-Zip.rpm -Protocol .rpm
                        Set-PTA -ProgId 7-Zip.split -Protocol .split
                        Set-PTA -ProgId 7-Zip.swm -Protocol .swm
                        Set-PTA -ProgId 7-Zip.tar -Protocol .tar
                        Set-PTA -ProgId 7-Zip.taz -Protocol .taz
                        Set-PTA -ProgId 7-Zip.tbz -Protocol .tbz
                        Set-PTA -ProgId 7-Zip.tbz2 -Protocol .tbz2
                        Set-PTA -ProgId 7-Zip.tgz -Protocol .tgz
                        Set-PTA -ProgId 7-Zip.tpz -Protocol .tpz
                        Set-PTA -ProgId 7-Zip.wim -Protocol .wim
                        Set-PTA -ProgId 7-Zip.xar -Protocol .xar
                        Set-PTA -ProgId 7-Zip.z -Protocol .z
                        Set-PTA -ProgId 7-Zip.zip -Protocol .zip
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
