Start-Transcript -Path "C:\Windows\Logs\Evergreen-DetectionRules.log" -Append -Force -ErrorAction SilentlyContinue
$Application = "GoogleChrome"
Write-host "###########################################################"
Write-host "Executing detection rules for application $Application"
Write-host "###########################################################"
Write-host "Date: $([DateTime]::Now)"
Write-host "Powershell Engine Path: $PSHOME"
$Value = Get-ItemProperty -Path "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Status" -ErrorAction SilentlyContinue
Write-host "Current Application status: $Value"
If ($Value -eq "UpToDate")
    {
        Write-host "Application $Application detected (0)"
        Exit 0
    }
Elseif ([String]::IsNullOrWhiteSpace($Value))
    {
        Write-host "Application $Application Undetected (1)"
        Exit 1
    }
Else
    {
        Write-host "Application $Application needs to be updated (1)"
        Exit 1
    }
End Transcript