# AES-256-CBC + HMAC

param(
  [Parameter(Mandatory=$true)][string] $PlainFile,
  [string] $OutEncFile = ""
)


if (-not (Test-Path $PlainFile)) { Write-Error "PlainFile not found: $PlainFile"; exit 1 }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Write-Error "openssl not found in PATH"; exit 2 }

if ($OutEncFile -eq "") { $OutEncFile = "$PlainFile.enc" }


# Master key (32 bytes random, base64)
$bytes = New-Object 'Byte[]' 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$masterB64 = [Convert]::ToBase64String($bytes)

# Save the master key
$keyFile = Join-Path $env:TEMP ("enc_key_{0}.txt" -f ([guid]::NewGuid()))
[System.IO.File]::WriteAllText($keyFile, $masterB64)

# Derive EncKey, MacKey from MasterKey
function Get-BytesFromB64($b64){[Convert]::FromBase64String($b64)}
function Sha256($bytes){$h = [System.Security.Cryptography.SHA256]::Create(); return $h.ComputeHash($bytes)}

$masterBytes = Get-BytesFromB64 $masterB64
$encKey = Sha256($masterBytes + [Text.Encoding]::ASCII.GetBytes("ENC")) # 32 bytes
$macKey = Sha256($masterBytes +[Text.Encoding]::ASCII.GetBytes("MAC") )

# AES-256-CBC encryption with IV (no salt, no pbkdf2)
$iv = New-Object 'Byte[]' 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

function ToHex($bytes){ ($bytes|ForEach-Object{$_.ToString("x2")}) -join "" }

$encKeyHex = ToHex $encKey
$ivHex = ToHex $iv

$opensslArgs = @(
  "enc","-aes-256-cbc",
  "-K", $encKeyHex,
  "-iv", $ivHex,
  "-in", $PlainFile,
  "-out", $OutEncFile
)

Write-Host "Running: openssl $($opensslArgs -join ' ')"
& openssl @opensslArgs
if ($LASTEXITCODE -ne 0) { Write-Error "OpenSSL encryption failed."; exit 3 }

# Compute HMAC-SHA256 over (IV || ciphertext)
$ct = [System.IO.File]::ReadAllBytes($OutEncFile)
$dataToMac = New-Object byte[] ($iv.Length + $ct.Length)
[Array]::Copy($iv, 0, $dataToMac, 0, $iv.Length)
[Array]::Copy($ct, 0, $dataToMac, $iv.Length, $ct.Length)

$hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
$tag  = $hmac.ComputeHash($dataToMac)

$ivFile   = "$OutEncFile.iv"
$hmacFile = "$OutEncFile.hmac"
[System.IO.File]::WriteAllBytes($ivFile, $iv)
[System.IO.File]::WriteAllBytes($hmacFile, $tag)
Write-Host "Created:"
Write-Host "  Ciphertext : $OutEncFile"
Write-Host "  IV         : $ivFile"
Write-Host "  HMAC       : $hmacFile"


Write-Host "Encryption complete. Encrypted file: $OutEncFile"
