# AES-256-CBC + HMAC

param(
  [Parameter(Mandatory=$true)][string] $PlainFile,
  [string] $OutPakFile = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PlainFile)) { Write-Error "PlainFile not found: $PlainFile" }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Write-Error "openssl not found in PATH" }

if ($OutPakFile -eq "") { $OutPakFile = "$PlainFile.pak" }
if ([IO.Path]::GetExtension($OutPakFile) -ieq ".enc") { $OutPakFile = [IO.Path]::ChangeExtension($OutPakFile, ".pak") }

# --- util
function New-RandBytes([int]$len){$b = New-Object byte[] $len; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); return $b}
function ToHex([byte[]]$bytes){ ($bytes | ForEach-Object { $_.ToString("x2") }) -join "" }
function Sha256([byte[]]$bytes){ $h=[Security.Cryptography.SHA256]::Create(); $h.ComputeHash($bytes) }

# MasterKey gen
$master = New-RandBytes 32
$masterB64 = [Convert]::ToBase64String($master)

$KeyOutB64File = Join-Path $env:TEMP ("enc_key_{0}.txt" -f ([guid]::NewGuid()))
[IO.File]::WriteAllText($KeyOutB64File, $masterB64)
Write-Host "Master key (base64) written to: $KeyOutB64File"

# EncKye and MacKey gen
$encKey = Sha256($master + [Text.Encoding]::ASCII.GetBytes("ENC"))
$macKey = Sha256($master + [Text.Encoding]::ASCII.GetBytes("MAC"))
$iv     = New-RandBytes 16

# Encrypt in CBC mdoe
$ctTemp = [IO.Path]::GetTempFileName()
Remove-Item $ctTemp -Force
$ctTemp = "$ctTemp.bin"

$encKeyHex = ToHex $encKey
$ivHex     = ToHex $iv

$opensslArgs = @("enc","-aes-256-cbc","-K",$encKeyHex,"-iv",$ivHex,"-in",$PlainFile,"-out",$ctTemp)
Write-Host "Running: openssl $($opensslArgs -join ' ')"
& openssl @opensslArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "OpenSSL encryption failed." }

# --- 4) HMAC(IV||CT)
$ct = [IO.File]::ReadAllBytes($ctTemp)
$dataToMac = New-Object byte[] ($iv.Length + $ct.Length)
[Array]::Copy($iv,0,$dataToMac,0,$iv.Length)
[Array]::Copy($ct,0,$dataToMac,$iv.Length,$ct.Length)

$hmac = [Security.Cryptography.HMACSHA256]::new($macKey)  # ← 중요: 단일 인자
$tag  = $hmac.ComputeHash($dataToMac)

# Configure .pak file: "PAK1"(4) | 0x01(1) | IV(16) | HMAC(32) | CT(rest)
$fs = [IO.File]::Open($OutPakFile,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
  $bw = New-Object IO.BinaryWriter($fs)
  $bw.Write([Text.Encoding]::ASCII.GetBytes("PAK1"))
  $bw.Write([byte]1)
  $bw.Write($iv)
  $bw.Write($tag)
  $bw.Write($ct)
  $bw.Flush()
}
finally { $fs.Dispose() }

Remove-Item $ctTemp -Force

Write-Host "Encryption Completed.`nCreated PAK: $OutPakFile"
Write-Host "Share the base64 key via a separate secure channel: $KeyOutB64File"
