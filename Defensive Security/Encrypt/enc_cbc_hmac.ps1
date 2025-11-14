# EtM (AES-256-CBC + HMAC)

param(
  [Parameter(Mandatory = $true)][string] $PlainFile,
  [string] $OutPakFile = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PlainFile)) { Write-Error "PlainFile not found: $PlainFile"; exit 1 }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Write-Error "openssl not found in PATH"; exit 2 }

if ($OutPakFile -eq "") { $OutPakFile = "$PlainFile.pak" }
if ([IO.Path]::GetExtension($OutPakFile) -ieq ".enc") {$OutPakFile = [IO.Path]::ChangeExtension($OutPakFile, ".pak")}

# Util
function New-RandomBytes([int] $len) {$b = New-Object byte[] $len;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);return $b}
function To-Hex([byte[]] $bytes) {($bytes | ForEach-Object { $_.ToString("x2") }) -join ""}
function Derive-KeysFromMasterBytes([byte[]] $master) {
    $sha = [Security.Cryptography.SHA512]::Create()
    $h = $sha.ComputeHash($master)
    $encKey = $h[0..31]
    $macKey = $h[32..63]
    return @{
        EncKey = $encKey
        MacKey = $macKey
    }
}

# MasterKey gen
$master = New-RandomBytes 32
$masterB64 = [Convert]::ToBase64String($master)

$keyFile = Join-Path $env:TEMP ("enc_key_{0}.txt" -f ([guid]::NewGuid()))
[IO.File]::WriteAllText($keyFile, $masterB64)
Write-Host "Master key (base64) written to: $keyFile"

# EncKey and MacKey gen
$keys = Derive-KeysFromMasterBytes -master $master
[byte[]] $encKey = $keys.EncKey
[byte[]] $macKey = $keys.MacKey

# Write-Host "macKey   : $([Convert]::ToBase64String($macKey))"

[byte[]] $iv = New-RandomBytes 16
$ivHex = To-Hex $iv # Prepare IV (16 bytes)
$encKeyHex = To-Hex $encKey


# Encrypt in CBC mode
$ctTemp = [IO.Path]::GetTempFileName()
Remove-Item $ctTemp -Force
$ctTemp = "$ctTemp.bin"

$opensslArgs = @("enc", "-aes-256-cbc","-K", $encKeyHex,"-iv", $ivHex,"-in", $PlainFile,"-out", $ctTemp)
Write-Host "Running: openssl $($opensslArgs -join ' ')"
& openssl $opensslArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
    Remove-Item $ctTemp -Force
    throw "OpenSSL encryption FAILED."
}

[byte[]] $ct = [IO.File]::ReadAllBytes($ctTemp)

# HMAC(iv || ct)
$hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,[byte[]]$macKey)
[byte[]] $tag = $hmac.ComputeHash($iv + $ct)
Write-Host "tag(enc) : $([Convert]::ToBase64String($tag))"

# Create PAK
[byte[]] $magic = [Text.Encoding]::ASCII.GetBytes("PAK1")
[byte] $version = 1
[byte] $ivLen = [byte]$iv.Length
[byte] $tagLen = [byte]$tag.Length

[byte[]] $ctLenBytes = [BitConverter]::GetBytes([uint32]$ct.Length)
if ([BitConverter]::IsLittleEndian) {
    [Array]::Reverse($ctLenBytes)
}

# header: 4 + 1 + 1 + 1 + 4 = 11
[byte[]] $header = New-Object byte[] 11
$offset = 0
[Array]::Copy($magic, 0, $header, $offset, 4); $offset += 4
$header[$offset] = $version; $offset += 1
$header[$offset] = $ivLen;   $offset += 1
$header[$offset] = $tagLen;  $offset += 1
[Array]::Copy($ctLenBytes, 0, $header, $offset, 4); $offset += 4

# Total array (header || IV || CT || Tag)
$totalLen = $header.Length + $iv.Length + $ct.Length + $tag.Length
[byte[]] $pak = New-Object byte[] $totalLen

$pos = 0
[Array]::Copy($header, 0, $pak, $pos, $header.Length); $pos += $header.Length
[Array]::Copy($iv,     0, $pak, $pos, $iv.Length);     $pos += $iv.Length
[Array]::Copy($ct,     0, $pak, $pos, $ct.Length);     $pos += $ct.Length
[Array]::Copy($tag,    0, $pak, $pos, $tag.Length);    $pos += $tag.Length

[IO.File]::WriteAllBytes($OutPakFile, $pak)

Remove-Item $ctTemp -Force

Write-Host "Encryption Completed."
Write-Host "Created PAK: $OutPakFile"
Write-Host "Share the base64 key via a separate secure channel: $keyFile"

# [byte[]] $all = [IO.File]::ReadAllBytes($OutPakFile)
# Write-Host "Length = $($all.Length)"
# Write-Host "First 80 bytes:"
# ($all[0..([Math]::Min(79, $all.Length - 1))] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '