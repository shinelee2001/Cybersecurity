param(
    [Parameter(Mandatory = $true)][string] $PakFile,
    [Parameter(Mandatory = $true)][string] $KeyB64File,
    [string] $OutPlainFile = ""
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $PakFile)) { Write-Error "PakFile not found: $PakFile"; exit 1 }
if (-not (Test-Path $KeyB64File)) { Write-Error "KeyB64File not found: $KeyB64File"; exit 2 }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Write-Error "openssl not found in PATH"; exit 3 }

if ($OutPlainFile -eq "") {
    $base = [IO.Path]::GetFileNameWithoutExtension($PakFile)
    $dir  = [IO.Path]::GetDirectoryName($PakFile)
    if ([string]::IsNullOrEmpty($dir)) { $dir = "." }
    $OutPlainFile = [IO.Path]::Combine($dir, $base)
}


# --- util
function To-Hex([byte[]] $bytes) {($bytes | ForEach-Object { $_.ToString("x2") }) -join ""}
function CtEq([byte[]] $a, [byte[]] $b) {
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        $diff = $diff -bor ($a[$i] -bxor $b[$i])
    }
    return ($diff -eq 0)
}
function Derive-KeysFromMasterB64([string] $b64) {
    [byte[]] $master = [Convert]::FromBase64String($b64)
    $sha = [Security.Cryptography.SHA512]::Create()
    $h = $sha.ComputeHash($master)
    $encKey = $h[0..31]
    $macKey = $h[32..63]
    return @{
        EncKey = $encKey
        MacKey = $macKey
    }
}



# Retrieve Keys
$masterB64 = (Get-Content $KeyB64File -Raw).Trim()
$keys = Derive-KeysFromMasterB64 -b64 $masterB64
[byte[]] $encKey = $keys.EncKey
[byte[]] $macKey = $keys.MacKey

# Write-Host "macKey   : $([Convert]::ToBase64String($macKey))"

# Parse PAK file
[byte[]] $all = [IO.File]::ReadAllBytes($PakFile)
if ($all.Length -lt 11) { throw "PAK file too short" } # read header len check

$pos = 0
[byte[]] $magic = New-Object byte[] 4
[Array]::Copy($all, $pos, $magic, 0, 4); $pos += 4
$magicStr = [Text.Encoding]::ASCII.GetString($magic)
if ($magicStr -ne "PAK1") {throw "Invalid PAK magic: $magicStr"} #magic check

$version = $all[$pos]; $pos += 1
if ($version -ne 1) { throw "Unsupported PAK version: $version" } #version check

$ivLen  = $all[$pos]; $pos += 1
$tagLen = $all[$pos]; $pos += 1

[byte[]] $ctLenBytes = New-Object byte[] 4
[Array]::Copy($all, $pos, $ctLenBytes, 0, 4); $pos += 4
if ([BitConverter]::IsLittleEndian) {[Array]::Reverse($ctLenBytes)}
$ctLen = [BitConverter]::ToUInt32($ctLenBytes, 0)

if ($all.Length -lt $pos + $ivLen + $ctLen + $tagLen) {throw "PAK file truncated or corrupted"}

[byte[]] $iv = New-Object byte[] $ivLen
[Array]::Copy($all, $pos, $iv, 0, $ivLen); $pos += $ivLen

[byte[]] $ct = New-Object byte[] $ctLen
[Array]::Copy($all, $pos, $ct, 0, $ctLen); $pos += $ctLen

[byte[]] $tagFile = New-Object byte[] $tagLen
[Array]::Copy($all, $pos, $tagFile, 0, $tagLen); $pos += $tagLen

# Write-Host "tag(file): $([Convert]::ToBase64String($tagFile))"


# Verify HMAC(iv || ct)
$hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,[byte[]]$macKey)
[byte[]] $tagCalc = $hmac.ComputeHash($iv + $ct)
Write-Host "tag(calc): $([Convert]::ToBase64String($tagCalc))"
if (-not (CtEq $tagFile $tagCalc)) {throw "HMAC verification FAILED. Aborting."}


$encKeyHex = To-Hex $encKey
$ivHex     = To-Hex $iv

# Decrypt
$ctTmp = [IO.Path]::GetTempFileName()
Remove-Item $ctTmp -Force
$ctTmp = "$ctTmp.bin"
[IO.File]::WriteAllBytes($ctTmp, $ct)

$opensslArgs = @("enc", "-d", "-aes-256-cbc","-K", $encKeyHex,"-iv", $ivHex,"-in", $ctTmp,"-out", $OutPlainFile)

Write-Host "Running: openssl $($opensslArgs -join ' ')"
& openssl $opensslArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
    Remove-Item $ctTmp -Force
    throw "OpenSSL decryption FAILED."
}

Remove-Item $ctTmp -Force
Write-Host "Decryption Complete: $OutPlainFile"
