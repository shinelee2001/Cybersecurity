param(
	[string]$SrcFile,
	[string]$DstFile,
	[int]$ChunkSize = 1000,
	[int]$DelayAfterPasteMs = 500,
	[int]$DelayAfterSaveMs = 1000
)

Write-Host "===================================================================================="
Write-Host "=          _         _              _____                      _                   ="        
Write-Host "=         / \  _   _| |_ ___       | ____| _ __   ___  ___  __| | ___ _  ___       ="
Write-Host "=        / _ \| | | | __/ _ \      | |__  | '_ \ / __|/ _ \/ _  |/ _ \ |/ _ \      ="
Write-Host "=       / ___ \ |_| | || (_) |     | |___|| | | | (__| (_)| (_| |  __/ |__  /      ="
Write-Host "=      /_/   \_\__,_|\__\___/      |_____||_| |_|\___|\___/\__|_|\___|_|  \_\      ="
Write-Host "=                                                                                  ="
Write-Host "===================================================================================="

Write-Host "`n[+] Starting script...!"

if (-not (Test-Path $SrcFile)) {
	Write-Host "`n[-] Source File not found: $SrcFile. Closing the script"
	exit 1
}

if (-not (Test-Path $DstFile)) {
	Write-Host "`n[-] Destination File not found: $DstFile. Closing the script."
	exit 1
	# New-Item -ItemType File -Path $DstFile -Force | Out-Null
}

Write-Host "`n[+] Reading source file..."
$bytes = [io.file]::ReadAllBytes($SrcFile)
$base64 = [convert]::ToBase64String($bytes)
Write-Host "   Total length of the file in Base64 encoded format: $($base64.Length) chars"




Write-Host "`n[+] Loading user32.dll assembly file..."

Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods{
	[DllImport("user32.dll")]
	public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@


$script:editor = ""

function Get-Editor {
	Write-Host "`n[+] Searching text editor to write files..."
	
	Write-Host "   Searching notepad.exe..."	
	$notepad = Get-Item "C:\Windows\notepad.exe" -ErrorAction SilentlyContinue
	if ($notepad) {
		$script:editor = "notepad"
		Write-Host "   $($script:editor) found!"
		return 
	}
	
	Write-Host "   Searching notepad++.exe..."
	$notepadPP = Get-ChildItem -Path C:\ -Filter "notepad++.exe" -File -Recurse -ErrorAction SilentlyContinue
	if ($notepadPP) {
		$script:editor = "notepad++"
		Write-Host "   $($script:editor) found!"
		return 
	}
	
	
	Write-Warning "`n[-] No text editor found. Closing the script."
	exit 1
}

Get-Editor


$script:proc
try {
	$script:proc = Start-Process $script:editor -ArgumentList $DstFile -ErrorAction Stop -PassThru | Select-Object -First 1
}
catch {
	Write-Error "`n[-] An error occurred during process launch..."
	Write-Error "Message: $($_.Exception.Message)"
	Write-Error "`nClosing the script."
	exit 1
}
[NativeMethods]::SetForegroundWindow($script:proc.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 1000

Write-Host "`n[+] Start writing file..."
for ($i=0; $i -lt $base64.Length; $i+=$ChunkSize) {
	$remaining = $base64.Length - $i
	$len = [Math]::Min($ChunkSize, $remaining)
	$chunk = $base64.Substring($i, $len)
	
	Write-Host "   Chunk starting at index $i (length $len) -- paste + save..."
	Set-Clipboard -Value $chunk
	
	[System.Windows.Forms.SendKeys]::SendWait("^v")
	Start-Sleep -Milliseconds $DelayAfterPasteMs
	
	[System.Windows.Forms.SendKeys]::SendWait("^s")
	Start-Sleep -Milliseconds $DelayAfterSaveMs
}

Write-Host "`n[+] Done. All chunks pasted and saved."
