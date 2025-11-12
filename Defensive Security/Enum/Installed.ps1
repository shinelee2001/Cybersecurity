$registryPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($path in $registryPaths) {
  Get-ItemProperty -Path "$path\*" -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
      Name = $_.DisplayName
      Version = $_.DisplayVersion
      InstallLocation = $_.InstallLocation
    }
  } | Where-Object { $_.Name -ne $null } | Format-Table -AutoSize
}
