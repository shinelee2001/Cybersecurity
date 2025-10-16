<#
    .SYNOPSIS
        Removed USB Articat Enumeration
    
    .DESCRIPTION
        Things to check before execution:
            - Get-ExecutionPolicy; if Restricted, then add -ExecutionPolicy Bypass
#>

# Look for portable drive conncetion histroy from the registry
Write-Host "========================================================================"
Write-Host "List portable drive connection history from Registry`n`n"

Write-Host "Reading USBSTOR... `n`n"
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" |
    ForEach-Object {
        Get-ChildItem $_.PSPath
    }

Write-Host "Reading SWD\WPDBUSENUM... `n`n"
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM" |
    ForEach-Object {
        Get-ChildItem $_.PSPath
    }
Write-Host "========================================================================"

$since=(Get-Date).AddDays(-2);

# Look for EventViewer
Write-Host "========================================================================"
Write-Host "List portable drive connection history from EventViewer`n`n"

Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} | Where-Object{$_.ProviderName -match "Pnp"}

Write-Host "========================================================================"
