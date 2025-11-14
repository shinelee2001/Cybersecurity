param(
	[Parameter(Mandatory=$true)][string]$PkgFile
)

if (-not (Test-Path $PkgFile)) {Write-Error "Cannot find the .pkg file: $PkgFile"; exit 1}

# Tmp working dir
$workDir = Join-Path $env:TEMP ("pkg_run_"+[guid]::NewGuid())
New-Item -ItemType Directory -Path $workDir | Out-Null

try{Expand-Archive -LiteralPath $PkgFile -DestinationPath $workDir -Force }
catch{throw "Failed to extract the file: $($_.Exception.Message)"; exit 1}

$pakPath = Join-Path $workDir "payload.pak"
$keyPath = Join-Path $workDir "key.obf.key"
$policyPath = Join-Path $workDir "policy.json"

if (-not (Test-Path $pakPath) -or -not (Test-Path $keyPath) -or -not (Test-Path $policyPath)) {
	Write-Error "Incorrect file format."
	exit 1
}

# Check policy
$policyJson = Get-Content $policyPath -Raw
$policy = $policyJson | ConvertFrom-Json

if ($policy.expiry) {
	$expiry = [datetime]$policy.expiry
	if ((Get-Date) -ge $expiry) {
		Write-Host "This document expired. (Expiry: $expiry)"
		exit 1
	}
}

# Recover key
. "PSScriptRoot\KeyObfuscation.ps1"

$obfKeyString = Get-Content $keyPath -Raw
$keyBytes = Deobfuscate-key -ObfuscatedString $obfKeyString

# Decrypt file
$outFile = Join-Path $env:TEMP ("decrypted_"+[IO.Path]GetFileNameWithoutExtension($PkgFile))

throw "dec_cbc_hmac.ps1 -PakFile $pakPath -KeyB64File $keyPath -OutPlainFile $outFile"

Start-Process $outFile
