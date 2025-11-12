param(
	[Parameter(Mandatory=$true)][string] $PakFile,
	[Parameter(Mandatory=$true)][string] $KeyB64File,
	[string] $OutPlainFile = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PakFile)) { Write-Error "PakFile not found: $PakFile" }
if (-not (Test-Path $KeyB64File)) { Write-Error "KeyB64File not found: $KeyB64File" }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Write-Error "openssl not found in PATH" }

# --- util
function Sha256([byte[]]$bytes){ $h=[Security.Cryptography.SHA256]::Create(); $h.ComputeHash($bytes) }
function ToHex([byte[]]$bytes){ ($bytes | ForEach-Object { $_.ToString("x2") }) -join "" }
function CtEq([byte[]]$a,[byte[]]$b){
  if ($a.Length -ne $b.Length) { return $false }
  $diff = 0
  for ($i=0; $i -lt $a.Length; $i++){ $diff = $diff -bor ($a[$i] -bxor $b[$i]) }
  return ($diff -eq 0)
}


# Key load
$masterB64 = Get-Content -LiteralPath $KeyB64File -Raw
$master = [Convert]::FromBase64String($masterB64)
$encKey = Sha256($master + [Text.Encoding]::ASCII.GetBytes("ENC"))
$macKey = Sha256($master + [Text.Encoding]::ASCII.GetBytes("MAC"))

# Parse PAK: Magic(4) | Ver(1) | IV(16) | HMAC(32) | CT
$all = [IO.File]::ReadAllBytes($PakFile)
if ($all.Length -lt 53) {throw "PAK too small."}

$magic = [Text.Encoding]::ASCII.GetString($all,0,4)
if ($magic -ne "PAK1") {throw "Invalid magic: $magic"}
$ver = $all[4]
if ($ver -ne 1){throw "Unsupported version: $ver"}

$iv = New-Object byte[] 16; [Array]::Copy($all,5,$iv,0,16)
$tag = New-Object byte[] 32; [Array]::Copy($all,21,$tag,0,32)

$ctLen = $all.Length - 53
if ($ctLen -le 0){throw "Empty ciphertext"}
$ct = New-Object byte[] $ctLen; [Array]::Copy($all,53,$ct,0,$ctLen)

# Verify HMAC
$dataToMac = New-Object byte[] ($iv.Length + $ct.Length)
[Array]::Copy($iv,0,$dataToMac,0,$iv.Length)
[Array]::Copy($ct,0,$dataToMac,$iv.Length,$ct.Length)

$hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
$calc = $hmac.ComputeHash($dataToMac)

if (-not (CtEq $tag $calc)){throw "HMAC verification FAILED. Aborting."}

# Decrypt ct
$encKeyHex = ToHex $encKey
$ivHex = ToHex $iv

$ctTmp = [IO.Path]::GetTempFileName()
Remove-Item $ctTmp -Force
$ctTmp = "$ctTmp.bin"
[IO.File]::WriteAllBytes($ctTmp,$ct)

$opensslArgs = @("enc","-d","aes-256-cbc","-K",$encKeyHex,"-iv",$ivHex,"-in",$ctTmp,"-out",$OutPlainFile)
Write-Host "Running: openssl $($opensslArgs -join " ")"
& openssl $opensslArgs | Out-Null
if ($LASTEXITCODE -ne 0){Remove-Item $ctTmp -Force; throw "OpenSSL decryption FAILED."}

Remove-Item $ctTmp -Force
Write-Host "Decryption Complete: $OutPlainFile"
