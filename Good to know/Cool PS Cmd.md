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

### 4) Read files in bytes -> convert to base64 and save to txt -> then original file
*(Useful to bypass DLP solution)*
```powershell
# To base64
$bytes = [io.file]::Readallbytes("C:\Intel® Wi-Fi 6E AX211 160MHz Ver 23.20.0.4.zip")
$base64=[convert]::tobase64string($bytes)
set-content -path "c:\bytes.b64.txt" -value $base64 -encoding ASCII

$base64 = get-content "c:\bytes.b64.txt" -raw
$bytes = [convert]::frombase64string($base64)
[io.file]::writeallbytes("c:\driver.zip", $bytes)
```

### 5) Ping sweeper
```powershell
1..64 | % { $ip="10.92.147.$_"; "IP $ip - Alive: $(Test-Connection $ip -Count 1 -Quiet -ErrorAction SilentlyContinue)" }
```
