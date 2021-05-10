$Application = "GoogleChrome"
$Value = Get-ItemProperty -Path "HKLM:\SOFTWARE\OSDC\EverGreenInstaller\$Application" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Status" -ErrorAction SilentlyContinue
If ($Value -eq "UpToDate")
    {
        Write-host "Application detected"
        #Exit 0
    }
Elseif ([String]::IsNullOrWhiteSpace($Value))
    {
        Write-host "Application Undetected"
        #Exit 1
    }
Else
    {
        Write-host "Application needs to be updated"
        #Exit 1
    }