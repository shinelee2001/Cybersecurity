param(
	[string]$SrcFile,
	[string]$DstFile,
	[int]$ChunkSize = 50000,
	[int]$DelayAfterPasteMs = 500,
	[int]$DelayAfterSaveMs = 1000
)

if (-not (Test-Path $SrcFile)) {
	Write-Error "Source File not found: $SrcFile"
	exit 1
}

if (-not (Test-Path $DstFile)) {
	# Write-Error "Destination File not found: $DstFile"
	# exit 1
	New-Item -ItemType File -Path $DstFile -Force | Out-Null
}

Write-Host "`n[+] Reading source file..."

$content = Get-Content $SrcFile -Raw
Write-Host "   Total Length: $($content.Length) chars"



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
	Write-Host "`n     2. Searching notepad++.exe..."
	$notepadPP = Get-ChildItem -Path C:\ -Filter "notepad++.exe" -File -Recurse -ErrorAction SilentlyContinue
	if ($notepadPP) {
		$script:editor = "notepad++"
		Write-Host "   $($script:editor) found!"
		return 
	}
	
	Write-Error "`n[-] No text editor found. Closing the script."
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
Start-Sleep -Milliseconds 200

Write-Host "`n[+] Start writing file..."
for ($i=0; $i -lt $content.Length; $i+=$ChunkSize) {
	$remaining = $content.Length - $i
	$len = [Math]::Min($ChunkSize, $remaining)
	$chunk = $content.Substring($i, $len)
	
	Write-Host "   Chunk starting at index $i (length $len) -- paste + save..."
	
	Set-Clipboard -Value $chunk
	Focus-Editor
	[System.Windows.Forms.SendKeys]::SendWait("^v")
	Start-Sleep -Milliseconds $DelayAfterPasteMs
	
	[System.Windows.Forms.SendKeys]::SendWait("^s")
	Start-Sleep -Milliseconds $DelayAfterSaveMs
}

Write-Host "`n[+] Done. All chunks pasted and saved."
