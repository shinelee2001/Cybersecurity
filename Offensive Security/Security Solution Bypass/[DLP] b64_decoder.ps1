param(
	[string]$SrcFile,
	[string]$DstFile
)

Write-Host "`n[+] Starting script...!"
Write-Host "     It is important that the DstFile extension is the same as the original file extension."

Start-Sleep -Milliseconds 1000
if (-not (Test-Path $SrcFile)) {
	Write-Host "`n[-] Source File not found: $SrcFile. Closing the script"
	exit 1
}

if (Test-Path $DstFile) {
	Start-Sleep -Milliseconds 1000
	Write-Host "`n[-] The file already exists: $DstFile. Closing the script."
	exit 1
}

Start-Sleep -Milliseconds 1000
Write-Host "`n[+] Reading source file..."
try {
	$base64 = Get-Content $SrcFile -Raw
	Write-Host "     Total length of the file in Base64 encoded format: $($base64.Length) chars"
}
catch {
	Start-Sleep -Milliseconds 1000
	Write-Host "[-] Somthing went wrong during file read."
	Write-Host "Error: $($_.Exception.Message)"
	Write-Host "Closing the script."
	exit 1
}

Start-Sleep -Milliseconds 1000
Write-Host "`n[+] Writing source file..."
$bytes = [convert]::FromBase64String($base64)
[io.file]::WriteAllBytes($DstFile, $bytes)


Write-Host "`n[+] Done. All chunks pasted and saved."
