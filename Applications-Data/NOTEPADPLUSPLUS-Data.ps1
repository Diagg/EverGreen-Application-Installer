# Version 0.4 - 30/05/2022 

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
        If ([String]::IsNullOrWhiteSpace($Architecture)){$Architecture = "X86"}

     
        
        # Application Object
        [PSCustomObject]@{
            AppAuthority = "EverGreen"
            AppName = "NotepadPlusPlus"
            AppVendor = "Don Ho"
            AppFiendlyName = "Notepad++"
            AppInstallName = "Notepad++"
            AppInstallNow = $AppInstallNow
            AppUnInstallNow = $AppUnInstallNow
            AppExtension = ".exe"
            AppDetection_X86 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
            AppDetection_X64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            AppInstallType = "exe" 
            AppInstallChannel = $null           
            AppInstallArchitecture = $($Architecture.ToUpper())
            AppInstallPlatform = "Windows"
            AppInstallLanguage = $null
            AppInstallOptionDefault = $SetAsDefault
            AppInstallOptionEnterprise = $EnterpriseMode
            AppInstallOptionDisableUpdate = $DisableUpdate
            AppInstallOptionGreenUpdate = $UpdateWithGreenstaller
            AppInstallCMD = "##APP##"
            AppInstallParameters = "/S"
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
        If ($Script:AppInfo.AppInstallOptionEnterprise)
            {
                # Remove Automatic Updates
                Write-ECKlog "Removing automatic update for $($Script:AppInfo.AppInstallName) !"
                $Script:AppInfo.AppInstallOptionDisableUpdate = $true
            } 
    }


Function Invoke-AdditionalUninstall
    {
        Write-ECKlog "Nothing set for Additional Uninstall option !"
    }


Function Invoke-DisableUpdateCapability
    {
        Write-ECKlog "Disabling update capability for $($Script:AppInfo.AppInstallName)"

        $ConfigXML = @"
<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifInHiddenFolder="no" fifProjectPanel1="no" fifProjectPanel2="no" fifProjectPanel3="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="1" transparency="150" dotMatchesNewline="no" isSearch2ButtonsMode="no" regexBackward4PowerUser="no" />
    <History nbMaxFile="10" inSubMenu="no" customLength="-1" />
    <ProjectPanels>
        <ProjectPanel id="0" workSpaceFile="" />
        <ProjectPanel id="1" workSpaceFile="" />
        <ProjectPanel id="2" workSpaceFile="" />
    </ProjectPanels>
    <GUIConfigs>
        <GUIConfig name="ToolBar" visible="yes">standard</GUIConfig>
        <GUIConfig name="StatusBar">show</GUIConfig>
        <GUIConfig name="TabBar" dragAndDrop="yes" drawTopBar="yes" drawInactiveTab="yes" reduce="yes" closeButton="yes" doubleClick2Close="no" vertical="no" multiLine="no" hide="no" quitOnEmpty="no" iconSetNumber="0" />
        <GUIConfig name="ScintillaViewsSplitter">vertical</GUIConfig>
        <GUIConfig name="UserDefineDlg" position="undocked">hide</GUIConfig>
        <GUIConfig name="TabSetting" replaceBySpace="no" size="4" />
        <GUIConfig name="AppPosition" x="256" y="290" width="1100" height="700" isMaximized="no" />
        <GUIConfig name="FindWindowPosition" left="0" top="0" right="0" bottom="0" />
        <GUIConfig name="FinderConfig" wrappedLines="no" purgeBeforeEverySearch="no" />
        <GUIConfig name="noUpdate" intervalDays="15" nextUpdateDate="20220613">yes</GUIConfig>
        <GUIConfig name="Auto-detection">yes</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="TrayIcon">no</GUIConfig>
        <GUIConfig name="MaitainIndent">yes</GUIConfig>
        <GUIConfig name="TagsMatchHighLight" TagAttrHighLight="yes" HighLightNonHtmlZone="no">yes</GUIConfig>
        <GUIConfig name="RememberLastSession">yes</GUIConfig>
        <GUIConfig name="DetectEncoding">yes</GUIConfig>
        <GUIConfig name="SaveAllConfirm">yes</GUIConfig>
        <GUIConfig name="NewDocDefaultSettings" format="0" encoding="4" lang="0" codepage="-1" openAnsiAsUTF8="yes" />
        <GUIConfig name="langsExcluded" gr0="0" gr1="0" gr2="0" gr3="0" gr4="0" gr5="0" gr6="0" gr7="0" gr8="0" gr9="0" gr10="0" gr11="0" gr12="0" langMenuCompact="yes" />
        <GUIConfig name="Print" lineNumber="yes" printOption="3" headerLeft="" headerMiddle="" headerRight="" footerLeft="" footerMiddle="" footerRight="" headerFontName="" headerFontStyle="0" headerFontSize="0" footerFontName="" footerFontStyle="0" footerFontSize="0" margeLeft="0" margeRight="0" margeTop="0" margeBottom="0" />
        <GUIConfig name="Backup" action="0" useCustumDir="no" dir="" isSnapshotMode="yes" snapshotBackupTiming="7000" />
        <GUIConfig name="TaskList">yes</GUIConfig>
        <GUIConfig name="MRU">yes</GUIConfig>
        <GUIConfig name="URL">2</GUIConfig>
        <GUIConfig name="uriCustomizedSchemes">svn:// cvs:// git:// imap:// irc:// irc6:// ircs:// ldap:// ldaps:// news: telnet:// gopher:// ssh:// sftp:// smb:// skype: snmp:// spotify: steam:// sms: slack:// chrome:// bitcoin:</GUIConfig>
        <GUIConfig name="globalOverride" fg="no" bg="no" font="no" fontSize="no" bold="no" italic="no" underline="no" />
        <GUIConfig name="auto-completion" autoCAction="3" triggerFromNbChar="1" autoCIgnoreNumbers="yes" insertSelectedItemUseENTER="yes" insertSelectedItemUseTAB="yes" funcParams="yes" />
        <GUIConfig name="auto-insert" parentheses="no" brackets="no" curlyBrackets="no" quotes="no" doubleQuotes="no" htmlXmlTag="no" />
        <GUIConfig name="sessionExt"></GUIConfig>
        <GUIConfig name="workspaceExt"></GUIConfig>
        <GUIConfig name="MenuBar">show</GUIConfig>
        <GUIConfig name="Caret" width="1" blinkRate="600" />
        <GUIConfig name="ScintillaGlobalSettings" enableMultiSelection="no" />
        <GUIConfig name="openSaveDir" value="0" defaultDirPath="" />
        <GUIConfig name="titleBar" short="no" />
        <GUIConfig name="stylerTheme" path="C:\Users\WDAGUtilityAccount\AppData\Roaming\Notepad++\stylers.xml" />
        <GUIConfig name="insertDateTime" customizedFormat="yyyy-MM-dd HH:mm:ss" reverseDefaultOrder="no" />
        <GUIConfig name="wordCharList" useDefault="yes" charsAdded="" />
        <GUIConfig name="delimiterSelection" leftmostDelimiter="40" rightmostDelimiter="41" delimiterSelectionOnEntireDocument="no" />
        <GUIConfig name="multiInst" setting="0" />
        <GUIConfig name="MISC" fileSwitcherWithoutExtColumn="yes" fileSwitcherExtWidth="50" fileSwitcherWithoutPathColumn="yes" fileSwitcherPathWidth="50" backSlashIsEscapeCharacterForSql="yes" writeTechnologyEngine="0" isFolderDroppedOpenFiles="no" docPeekOnTab="no" docPeekOnMap="no" sortFunctionList="no" saveDlgExtFilterToAllTypes="no" muteSounds="no" />
        <GUIConfig name="Searching" monospacedFontFindDlg="no" stopFillingFindField="no" findDlgAlwaysVisible="no" confirmReplaceInAllOpenDocs="yes" replaceStopsWithoutFindingNext="no" />
        <GUIConfig name="searchEngine" searchEngineChoice="2" searchEngineCustom="" />
        <GUIConfig name="MarkAll" matchCase="no" wholeWordOnly="yes" />
        <GUIConfig name="SmartHighLight" matchCase="no" wholeWordOnly="yes" useFindSettings="no" onAnotherView="no">yes</GUIConfig>
        <GUIConfig name="DarkMode" enable="no" colorTone="0" customColorTop="2105376" customColorMenuHotTrack="4210752" customColorActive="4210752" customColorMain="2105376" customColorError="176" customColorText="14737632" customColorDarkText="12632256" customColorDisabledText="8421504" customColorEdge="6579300" customColorLinkText="65535" />
        <GUIConfig name="ScintillaPrimaryView" lineNumberMargin="show" lineNumberDynamicWidth="yes" bookMarkMargin="show" indentGuideLine="show" folderMarkStyle="box" lineWrapMethod="aligned" currentLineIndicator="1" currentLineFrameWidth="1" virtualSpace="no" scrollBeyondLastLine="yes" rightClickKeepsSelection="no" disableAdvancedScrolling="no" wrapSymbolShow="hide" Wrap="no" borderEdge="yes" isEdgeBgMode="no" edgeMultiColumnPos="" zoom="0" zoom2="0" whiteSpaceShow="hide" eolShow="hide" borderWidth="2" smoothFont="no" paddingLeft="0" paddingRight="0" distractionFreeDivPart="4" />
        <GUIConfig name="DockingManager" leftWidth="200" rightWidth="200" topHeight="200" bottomHeight="200">
            <ActiveTabs cont="0" activeTab="-1" />
            <ActiveTabs cont="1" activeTab="-1" />
            <ActiveTabs cont="2" activeTab="-1" />
            <ActiveTabs cont="3" activeTab="-1" />
        </GUIConfig>
    </GUIConfigs>
</NotepadPlus>
"@

        If ($ECK.OSArchitectureIsX64 -eq $true)
            {
                $uPath = "${env:ProgramFiles(x86)}\Notepad++\config.model.xml"
                $uFolder = "${env:ProgramFiles(x86)}\Notepad++\updater"
            } 
        Else 
            {
                $uPath = "$($env:ProgramFiles)\Notepad++\config.model.xml"
                $uFolder = "$($env:ProgramFiles)\Notepad++\updater"
            }

        $ConfigXML| Out-file -FilePath $uPath -Encoding UTF8 -Append -width 1000 -ErrorAction SilentlyContinue
        If (test-path $uPath)
            {Write-ECKlog "Disable update configuration applied succesfully !"}
        else 
            {Write-ECKlog "[ERROR] unable to apply disable update configuration !" -Type 3}


        If (test-path $ufolder){Remove-Item -Path $uFolder  -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue}
        If (-not (test-path $ufolder))
            {Write-ECKlog "update engine removed succesfully !"}
        else 
            {Write-ECKlog "[ERROR] unable to remove update engine !" -Type 3}

    }
