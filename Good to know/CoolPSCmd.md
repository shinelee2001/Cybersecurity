## Cool PowerShell Commands

### 1) Run Base64-encoded Commands
```powershell
Invoke-Expression (
    [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String("bHM=")
    )
)
```

### 2) Write Raw Bytes to File
```powershell
$bytes = ("48 69 0D 0A 52 65 7A 65").Split(" ") |
    ForEach-Object { [Convert]::ToByte($_, 16) }

[IO.File]::WriteAllBytes("hiReze.txt", $bytes)
```

### 3) Extract Printable Strings From Binary Files
*(similar to strings in Linux)*
```powershell
Select-String -Path "C:\path\to\file" -Pattern "[ -~]{4,}" -AllMatches |
    Select-Object -ExpandProperty Matches |
    Select-Object -ExpandProperty Value
```
