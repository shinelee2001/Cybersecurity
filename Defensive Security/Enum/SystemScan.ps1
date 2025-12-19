<#
.SYNOPSIS
NSE Security System Scan — Finds user data files created or modified within the last N days (default 56) and can optionally scan file contents for keywords (including OCR).

.DESCRIPTION
This script helps identify potential data exfiltration indicators by listing “data-like” files that were created or modified within a selected time window.

Default scan scope:
- User profiles under C:\Users\ (recursive)
- Recycle Bin
- Non-C: partitions and external/removable drives (when readable)

Default exclusions / protections:
- Skips common system locations (AppData, Windows, Program Files, Program Files (x86))
- Skips ReparsePoint items (symbolic links, etc.)
- Skips zero-byte files (commonly cloud-only placeholders)

Optional features:
- -ContentScan: scans file contents for keywords
  * TXT/CSV via Select-String
  * DOCX/PPTX/XLSX by extracting OOXML XML content
  * Images via Windows built-in OCR
  * PDFs via page-render + Windows OCR
- External storage activity signals:
  * UMDF Operational event log entries (if enabled)
  * USBSTOR install blocks parsed from setupapi.dev.log (plus FriendlyName lookup)

Output:
- Console output plus a transcript log file
- A log is created under %TEMP% and then copied to the script folder ($PSScriptRoot)

Important notes:
- Content scanning (especially OCR and large drives) can take significant time.
- OCR requires Windows 10+ and Windows PowerShell (Desktop edition, typically 5.1).

.PARAMETER days
Number of days to look back. Files are included if CreationTime OR LastWriteTime is within the last N days.
Default: 56

.PARAMETER contentScan
If specified, scans file contents for keywords (including OCR for images and PDFs).

.PARAMETER keyWords
Additional keywords (string array) to search for. These are added to the default keyword list.
Example: -keyWords "project x","prototype","do not distribute"

.EXAMPLE
.\SystemScan10.ps1
Runs the default scan (56 days) and prints matching file paths/timestamps.

.EXAMPLE
.\SystemScan10.ps1 -days 14
Scans for files created/modified within the last 14 days.

.EXAMPLE
.\SystemScan10.ps1 -contentScan
Runs file discovery + content scanning using the default keywords (includes OCR).

.EXAMPLE
.\SystemScan10.ps1 -days 30 -contentScan -keyWords "battery","supplier","drawing"
Scans the last 30 days, enables content scanning, and adds extra keywords.

.OUTPUTS
Console output + transcript log file (LOG).

.NOTES
Author / Changelog:
- Ian Douglas 2025-04-14
- Owen Tan    2025-07-16  Release 9
- Dongchan Lee 2025-10-23 Minor fixes (skip cloud-only/zero-byte)
- Dongchan Lee 2025-10-31 Release 10.1 (content scanning)
- Dongchan Lee 2025-11-05 Release 10.2 (stability fixes)
- Dongchan Lee 2025-11-24 Release 10.3 (removable drive scan + OCR integration)

Tip:
Get-Help .\SystemScan10.ps1 -Examples
Get-Help .\SystemScan10.ps1 -Detailed
#>


# SystemScan10.ps1
# 
# NSE Security System Scan Report PowerShell Script
# 
# intended to scan laptops for potential exfiltration of data based on changes done in the past xxx days
# xxx is the number of days, default 56 days (8 weeks)

#
# Check out the SystemScan.README.txt(.ps1) for command line run instructions.

#
# Captures System Details: Logs the computer name, Windows version, and current username.
#
# Scans User Data Folders: Checks Documents, Desktop, Downloads, Pictures, and Videos for changes.
#
# Excludes System Folders: It skips AppData, Windows, and Program Files.
#
# Logs Everything: The script logs the scan start, files found, and scan duration in a log file.

# 
# Ian Douglas 2025-04-14
# Owen Tan    2025-07-16	Release 9
# Dongchan Lee 2025-10-23	Minor fixes and improvements e.g. skipping cloud-only entities
# Dongchan Lee 2025-10-31	Release 10.1 (Introducing content scanning)
# Dongchan Lee 2025-11-05	Release 10.2 (Minor fixes and improvements e.g. filename scanning error handling) 
# Dongchan Lee 2025-11-24	Release 10.3 (Scanning removable disks except NSE Security Scanning drive + Windows built-in OCR engine integration for content scan + minor fixes on content scanning)
 
# Get system details

# Define default number of days if not provided
param (
    [int]$days = 56,
	[switch]$contentScan,
	[string[]]$keyWords
)

# Generate log filename with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$logFile = "$env:TEMP\NSE_SYSTEM_SCAN_$timestamp.LOG"

# Start logging
Start-Transcript -Path $logFile -Append

# Capture system details
$systemName = $env:COMPUTERNAME
$windowsVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$username = $env:USERNAME

Write-Host  "`n************************************************************`n***"
Write-Host  "***   Starting NSE system scan...      "
Write-Host  "***`n************************************************************"
Write-Host  "***"
Write-Host  "***   System Name    : $systemName  "
Write-Host  "***   Serial Number  : $SerialNumber"
Write-Host  "***   Windows Version: $windowsVersion"
Write-Host  "***   Username       : $username    "
Write-Host  "***`n************************************************************`n***"
Write-Host "***   Scanning for files and directories containing data, modified or created in the last $days days..." -ForegroundColor Yellow
Write-Host  "***`n************************************************************"

# Record start time
$startTime = Get-Date

# Define the date threshold for filtering files
$dateThreshold = (Get-Date).AddDays(-$days)

# Define excluded directories
$excludedDirs = @("AppData", "Windows", "Program Files", "Program Files (x86)")

# Define data file extensions of interest
$dataFileExtensions = @(".jpg", "jpeg", "tif", "tiff",".png", ".mp4", ".mov", ".docx", ".xlsx", ".pptx", ".txt", ".pdf", ".csv", ".zip")

# Initialize storage for found files
$foundFiles = @{}

# File counter # 2025-07-16
[int]$totalFiles = 0


### Scan C:\Users\ ###
$userDirs = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -notin $excludedDirs }

foreach ($user in $userDirs) {
    Write-Host "***   Scanning: $($user.FullName)"

    # Get all relevant files modified or created in the time frame
	# (2025-10-23) Added a condition "-and ($_.Length -gt 0)" to ignore file with size 0
	#	- In this way, we can also ignore cloud-only files existing in the endpoint.
	# 	- The local keeps the inks of cloud-only files, which are of size 0 on disk.
	# (2025-11-05) Minor fixes
	#	- Skipping symbolic links (ReparsePoint in Windows) while scanning by adding "-Attributes !ReparsePoint"
    $files = Get-ChildItem -Path $user.FullName -Recurse -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue | 
             Where-Object { ($_.LastWriteTime -ge $dateThreshold -or $_.CreationTime -ge $dateThreshold) -and ($_.Extension -in $dataFileExtensions) -and ($_.Length -gt 0)} |
             Where-Object { ($_.FullName -notmatch '\\AppData\\') -and ($_.FullName -notmatch '\\Windows\\') } |
             Select-Object FullName, LastWriteTime, CreationTime

    # Add one to the file counter
    $totalFiles += $files.Count # 2025-07-16

    # Store found files under their parent directories
    foreach ($file in $files) {
        $parentDir = Split-Path -Parent $file.FullName
        if (-not $foundFiles.ContainsKey($parentDir)) {
            $foundFiles[$parentDir] = @()
        }
        $foundFiles[$parentDir] += $file
    }
}

### Scan Recycle Bin ###
$recycleBinPath = "C:\$Recycle.Bin"

if (Test-Path $recycleBinPath) {
Write-Host  "***`n************************************************************"    
Write-Host  "`n***   Scanning Recycle Bin..."
    
    # Go through each user's Recycle Bin folder
	# (2025-10-23) Added a condition "-and ($_.Length -gt 0)" to ignore file with size 0
	#	- In this way, we can also ignore cloud-only files existing in the endpoint.
	# 	- The local keeps the inks of cloud-only files, which are of size 0 on disk
	# (2025-11-05) Minor fixes
	#	- Skipping symbolic links (ReparsePoint in Windows) while scanning by adding "-Attributes !ReparsePoint".
    $recycleBinUsers = Get-ChildItem -Path $recycleBinPath -Directory -ErrorAction SilentlyContinue
    $totalFiles += $recycleBinFiles.Count # 2025-07-16
    foreach ($binUser in $recycleBinUsers) {
        $recycleBinFiles = Get-ChildItem -Path $binUser.FullName -Recurse -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue | 
                           Where-Object { ($_.LastWriteTime -ge $dateThreshold -or $_.CreationTime -ge $dateThreshold) -and ($_.Extension -in $dataFileExtensions) -and ($_.Length -gt 0)} |
                           Select-Object FullName, LastWriteTime, CreationTime

        if ($recycleBinFiles.Count -gt 0) {
            if (-not $foundFiles.ContainsKey("Recycle Bin")) {
                $foundFiles["Recycle Bin"] = @()
            }
            $foundFiles["Recycle Bin"] += $recycleBinFiles
        }
    }
}

### Scan Additional Partitions & USB Drives ###
# Get all non-C: drives
# (2025-11-24) Scanning all removable drives
#	- Removed '-and $_.DriveType -ne 2' condition
# 	- NSE Security Scanning drive will not be scanned by Test-DriveReadable function
$nonUSBDrives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -ne 'C:'}

# Get corresponding PowerShell drives (PSDrive) for safe access
$extraDrives = @()
foreach ($drive in $nonUSBDrives) {
    $psDrive = Get-PSDrive -Name ($drive.DeviceID.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($psDrive) {
        $extraDrives += $psDrive
    }
}

# (2025-11-05) Helper to verify drive readability
function Test-DriveReadable {
	param(
		[string]$driveRoot
	)
	
	if (-not (Test-Path -LiteralPath $driveRoot)) {return [PSCustomObject]@{Readable=$false; Reason='NotFound'}}
	try {
		# Skip if drive is not readable
		&{Get-ChildItem -LiteralPath $driveRoot -Force -Depth 0 -ErrorAction Stop | Out-Null} 2>$null

		# Skip if drive has 'NSE_Scripts' Directory (2025-11-24)
		$dir = Join-Path $driveRoot 'NSE_Scripts'
		if (Test-Path -LiteralPath $dir) {
			return [PSCustomObject]@{Readable=$false; Reason='NSE Security Team Inspection Drive... Skipping Scanning.'}
		}
		
		
		return [PSCustomObject]@{Readable=$true; Reason=$null}
	}
	catch [System.UnauthorizedAccessException] {return [PSCustomObject]@{Readable=$false; Reason='AccessDenied'}}
	catch [System.IO.IOException] {return [PSCustomObject]@{Readable=$false; Reason='IOError'}}
	catch {return [PSCustomObject]@{Readable=$false; Reason=$_.Exception.Message}}
}

# (2025-11-05) Define FriendlyName of DriveType
$driveTypeNames = @{
    0 = 'Unknown'
    1 = 'No Root Directory'
    2 = 'Removable'
    3 = 'Local Disk'
    4 = 'Network'
    5 = 'CD-ROM'
    6 = 'RAM Disk'
}


if ($extraDrives) {
    Write-Host  "`***`n************************************************************"
    Write-Host  "***`n***   Scanning additional partitions and external drives..."

    foreach ($drive in $extraDrives) {
		
		# Handle a case when we cannot read the drive (2025-10-23)
		# Enveloped the preexisting codes with try-catch.
		#	- In general, the error occurs when the drive is too large and the scanning process runs out of memory.
		$driveLetter = $drive.Root
		Write-Host "***   Scanning drive: $driveLetter"
		
		$probe = Test-DriveReadable -driveRoot $driveLetter
		
		# (2025-11-05) Minor fixes
		# 	- Improving error handling cases
		if (-not $probe.Readable) {
			$deviceID = $driveLetter.Trim('\')
			try {$disk = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $deviceID}}
			catch {$disk = $null}
			if ($disk -ne $null) {write-host "***   DriveType: $($driveTypeNames[[int]$disk.DriveType])"} else {write-host "***   DriveType: Unknown"}
			Write-Host ("***   Skipped while scanning. Reason: {0}" -f $probe.Reason)
			continue
		}
		
		
		try {
			# (2025-10-23) Added a condition "-and ($_.Length -gt 0)" to ignore file with size 0
			#	- In this way, we can also ignore cloud-only files existing in the endpoint.
			# 	- The local keeps the inks of cloud-only files, which are of size 0 on disk.
			# (2025-11-05) Minor fixes
			#	- Skipping symbolic links (ReparsePoint in Windows) while scanning by adding "-Attributes !ReparsePoint"
			#   - Improving error handling cases
			$files = & {
				Get-ChildItem -Path $driveLetter -Recurse -File -Attributes !ReparsePoint -ErrorAction Stop | 
				Where-Object { ($_.LastWriteTime -ge $dateThreshold -or $_.CreationTime -ge $dateThreshold) -and ($_.Extension -in $dataFileExtensions) -and ($_.Length -gt 0)} | 
				Select-Object FullName, LastWriteTime, CreationTime
			} 2>$null
			
			$totalFiles += $files.Count # 2025-07-16

			if ($files.Count -gt 0) {
				$foundFiles[$driveLetter] = $files
			}
		} catch {
			Write-Host "***   An error occurred while scanning drive $driveLetter."
			Write-Host "***   Error Message: $($_.Exception.Message)"
		}        
    }
}


# Print results
if ($foundFiles.Count -gt 0) {
	Write-Host  "`***`n************************************************************"
    Write-Host "***`n***   Total files found: $totalFiles" # 2025-07-16
    Write-Host "***`n***   Directories Containing Data Files:"
    foreach ($dir in $foundFiles.Keys) {
        Write-Host "***`n***   [DIR] $dir"
        foreach ($file in $foundFiles[$dir]) {
            # Fixing PowerShell 5 compatibility (Replacing ??)
            $creationDate = $file.CreationTime         # 2025-07-16
            $lastModDate  = $file.LastWriteTime        # 2025-07-16
            Write-Host "***     [FILE] $($file.FullName) - Created: $creationDate - Modified: $lastModDate" # 2025-07-16

        }
    }
} else {
    Write-Host "***`n************************************************************"
    Write-Host "***`n***   No relevant files found in user directories, Recycle Bin, or other partitions."
}


#############################
### File Content Scanning ###
#############################
#
#	Initially added date: 2025-10-31
#   The compatibility test was only carried out under Powershell v5.1.26100 and .Net Framework 4.8
#
#	(2025-11-24) Try-catch error handling for tag mismatching error found during xml file read.
# 		- This error was occasionally found when documents contain Koreans or Chinese. (e.g., <w:t>涓€鑷存€ч噸澶嶆€?/w:t>)
#		- I don't know if byte reading first then UTF-8 encoding would help the case. (If you think it is reasonable, then change it please with justification)
#

# Define keywords to look up in documents
$defaultKeywords = @('confidential', 'secret', 'nextstar energy', 'nse', 'esst', 'nextstar')
if ($keywords) { $defaultKeywords += $keywords }


# Convert the keyword into regex form
$keywordPtn = ($defaultKeywords | ForEach-Object { $_ } ) -join '|'
$keywordPtn = "(?i:$keywordPtn)"


# $maxSizeBytes = 5MB  # This threshold is not in use.

$keywordFoundFiles = New-Object 'System.Collections.Generic.List[object]'


# Helper to extract texts from DOCX.
function Get-DocxText {
    param([string]$Path)
	
	# Temp file and folder to unzip the document.
	$tmpZip = [System.IO.Path]::ChangeExtension($Path, ".zip")
	$tmpFolder = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) "tmp_docx"
	
	# Check if the temp file or folder exists and remove them before unzip the current document.
	if (Test-Path -LiteralPath $tmpFolder) { Remove-Item -Recurse -Force $tmpFolder }
    if (Test-Path -LiteralPath $tmpZip) { Remove-Item -Force $tmpZip }
	
	# Unzip the document in temp folder
	Copy-Item -LiteralPath $Path $tmpZip
	Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpFolder -Force
	
	
	# (2025-11-05) Scanning logic fix for docx
	# 	- Now it scans through headers and footers as well.
	$fileNames = @(Join-Path $tmpFolder 'word\document.xml') + 
		(Get-ChildItem -LiteralPath (Join-Path $tmpFolder 'word') -Filter 'header*.xml' -ErrorAction SilentlyContinue |
			ForEach-Object { $_.FullName }) +
		(Get-ChildItem -LiteralPath (Join-Path $tmpFolder 'word') -Filter 'footer*.xml' -ErrorAction SilentlyContinue |
			ForEach-Object { $_.FullName })
	$docxTexts = @{}
	
	foreach($docxFile in $fileNames){
		try {
			[xml]$xml = Get-Content -LiteralPath $docxFile -Raw -Encoding UTF8
		}
		catch {
			$docxTexts[($docxFile -split '\\')[-1]] = "[XML Parse failed] $($_.Exception.Message)"
			continue
		}
		
		$textNodes = $xml.SelectNodes('//*[local-name()="t"]')
        $text = ($textNodes | ForEach-Object { $_.InnerText }) -join ' '
        $lines = $text -split '\. '


        $matched = $lines | Where-Object { $_ -and ($_ -match $keywordPtn) }
		if ($matched) {$docxTexts[($docxFile -split '\\')[-1]] = ($matched -join "`n")}
	}
	
	# Remove temp file and folder
	Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip

    return $docxTexts
}


# Helper to extract texts from PPTX.
function Get-PptxSlidesText {
    param([string]$Path)

	# Temp file and folder to unzip the document.
    $tmpZip    = [System.IO.Path]::ChangeExtension($Path, ".zip")
    $tmpFolder = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) "temp_pptx"

	# Check if the temp file or folder exists and remove them before unzip the current document.
    if (Test-Path -LiteralPath $tmpFolder) { Remove-Item -Recurse -Force $tmpFolder }
    if (Test-Path -LiteralPath $tmpZip)    { Remove-Item -Force $tmpZip }

	# Unzip the document in temp folder
	Copy-Item -LiteralPath $Path $tmpZip -Force
	Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpFolder -Force
	
	$slidesDir = Join-Path $tmpFolder "ppt\slides"
	if (-not (Test-Path -LiteralPath $slidesDir)) {return}
	$slideFiles = Get-ChildItem -LiteralPath $slidesDir -Filter "slide*.xml" -File
	
	$slideTexts = @{}
	
	
	foreach($sf in $slideFiles) {
		try {
			[xml]$xml = Get-Content $sf.FullName -Raw -Encoding UTF8
		}
		catch {
			$slideTexts[$sf.Name] = "[XML Parse failed] $($_.Exception.Message)"
			continue
		}
		
		$tNodes = $xml.SelectNodes('//*[local-name()="t"]')
		
		$text = ($tNodes | ForEach-Object { $_.InnerText }) -join ' '
		$lines = $text -split '\. '
		
		# Look up for the keywords in the document
		$matched = $lines | Where-Object { $_ -match $keywordPtn }
		if ($matched) {$slideTexts[$sf.Name] = ($matched -join "`n")}
		
	}
	
	# Remove temp file and folder.
	Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip
	
	return $slideTexts
}

# Helper to extract texts from Excel.
function Get-ExcelText {
    param([string]$Path)

	# Temp file and folder to unzip the document.
    $tmpZip    = [System.IO.Path]::ChangeExtension($Path, ".zip")
    $tmpFolder = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) "temp_xlsx"

	# Check if the temp file or folder exists and remove them before unzip the current document.
    if (Test-Path -LiteralPath $tmpFolder) { Remove-Item -Recurse -Force $tmpFolder }
    if (Test-Path -LiteralPath $tmpZip)    { Remove-Item -Force $tmpZip }

	# Unzip the document in temp folder
	Copy-Item -LiteralPath $Path $tmpZip -Force
	Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpFolder -Force
	
	
	$excelTexts = @{}
	
	# 1) sharedStrings.xml
	$sharedStrings = Join-Path $tmpFolder "xl\sharedStrings.xml"
	if (-not (Test-Path -LiteralPath $sharedStrings)) {
		# Write-Warning "xl\sharedStrings.xml not found in $Path"
		return
	}
	try {
		[xml]$ssXml = Get-Content -LiteralPath $sharedStrings -Raw -Encoding UTF8
	}
	catch {
		$excelTexts["sharedStrings.xml"] = "[XML Parse failed] $($_.Exception.Message)"
	}
	$ssTNodes = $ssXml.SelectNodes('//*[local-name()="t"]')
	$ssText = ($ssTNodes | ForEach-Object { $_.InnerText }) -join ' '
	$ssLines = $ssText -split '\. '
	
	# Look up for the keywords in the document
	$ssMatched = $ssLines | Where-Object { $_ -match $keywordPtn}
	if ($ssMatched) {$excelTexts["sharedStrings.xml"] = ($ssMatched -join "`n") }
	
	
	
	# 2) drawing*.xml
	$drawingDir = Join-Path $tmpFolder "xl\drawings"
	if (-not (Test-Path -LiteralPath $drawingDir)) {return}
	$drawingFiles = Get-ChildItem -LiteralPath $drawingDir -Filter "drawing*.xml" -File
	
	foreach($df in $drawingFiles) {
		try {
			[xml]$xml = Get-Content $df.FullName -Raw -Encoding UTF8
		}
		catch {
			$excelTexts[$df.Name] = "[XML Parse failed] $($_.Exception.Message)"
			continue
		}
		$tNodes = $xml.SelectNodes('//*[local-name()="t"]')
		
		$text = ($tNodes | ForEach-Object { $_.InnerText }) -join ' '
		$lines = $text -split '\. '
		
		# Look up for the keywords in the document
		$matched = $lines | Where-Object { $_ -match $keywordPtn }
		if ($matched) {$excelTexts[$df.Name] = ($matched -join "`n")}
	}
	
	# 3) chartEx*.xml
	$chartDir = Join-Path $tmpFolder "xl\charts"
	if (-not (Test-Path -LiteralPath $chartDir)) {return}
	
	$chartFiles = Get-ChildItem -LiteralPath $chartDir -Filter "chart*.xml" -File
	foreach($cf in $chartFiles) {
		try {
			[xml]$xml = Get-Content $cf.FullName -Raw -Encoding UTF8	
		}
		catch {
			excelTexts[$cf.Name] = "[XML Parse failed] $($_.Exception.Message)"
			continue
		}
		
		$paths = @('//*[local-name()="t"]', '//*[local-name()="v"]')
		foreach ($path in $paths) {
			$nodes = $xml.SelectNodes($path)
			if ($nodes) {
				foreach($n in $nodes) {
					$chartText = $($n.InnerText) -join ' '
					$chartLines = $chartText -split '\. '
					
					# Look up for the keywords in the document
					$chartMatched = $chartLines | Where-Object {$_ -match $keywordPtn}
					if ($chartMatched) {$excelTexts[$cf.Name] = ($chartMatched -join "`n")}
				}
			}
		}
	}
	
	# Remove temp file and folder.
	Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip
	
	return $excelTexts
}

# (2025-11-24) OCR Scan
#
# Compatible PSEditions: Desktop
# Powershell version: 5
# OS Version: Windows 10 or above (It uses Windows built-in OCR engine)
# Reference: https://github.com/TobiasPSP/PsOcr
#

$script:OcrInitialized = $false
$script:OcrAwaiter        = $null   # For IAsyncOperation<T>
$script:OcrActionAwaiter  = $null   # For IAsyncAction

# Load OCR in WinRT
function Initialize-OcrWinRT{
    if ($script:OcrInitialized) { return }

    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime

        # Load WinRT types as required
        $null = [Windows.Storage.StorageFile,                Windows.Storage,         ContentType = WindowsRuntime]
        $null = [Windows.Media.Ocr.OcrEngine,                Windows.Foundation,      ContentType = WindowsRuntime]
        $null = [Windows.Foundation.IAsyncOperation`1,       Windows.Foundation,      ContentType = WindowsRuntime]
        $null = [Windows.Foundation.IAsyncAction,            Windows.Foundation,      ContentType = WindowsRuntime]
        $null = [Windows.Graphics.Imaging.SoftwareBitmap,    Windows.Foundation,      ContentType = WindowsRuntime]
        $null = [Windows.Storage.Streams.RandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
        $null = [Windows.Data.Pdf.PdfDocument,               Windows.Data.Pdf,        ContentType = WindowsRuntime]
        $null = [WindowsRuntimeSystemExtensions]
        $null = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages

        # 1) IAsyncOperation<T> awaiter
        $script:OcrAwaiter = [WindowsRuntimeSystemExtensions].GetMember(
            'GetAwaiter', 'Method', 'Public,Static'
        ) | Where-Object {
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        } | Select-Object -First 1

        # 2) IAsyncAction awaiter
        $script:OcrActionAwaiter = [WindowsRuntimeSystemExtensions].GetMember(
            'GetAwaiter', 'Method', 'Public,Static'
        ) | Where-Object {
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
        } | Select-Object -First 1

        if (-not $script:OcrAwaiter -or -not $script:OcrActionAwaiter) {
            throw "Failed to locate WinRT awaiter methods."
        }

        # IAsyncOperation<T>
        if (-not (Get-Command Invoke-WinRtAsync -ErrorAction SilentlyContinue)) {
            function Script:Invoke-WinRtAsync {
                param(
                    [Parameter(Mandatory)][object]$AsyncTask,
                    [Parameter(Mandatory)][Type]$As
                )

                return $script:OcrAwaiter.
                    MakeGenericMethod($As).
                    Invoke($null, @($AsyncTask)).
                    GetResult()
            }
        }

        # IAsyncAction
        if (-not (Get-Command Invoke-WinRtAction -ErrorAction SilentlyContinue)) {
            function Script:Invoke-WinRtAction {
                param(
                    [Parameter(Mandatory)][object]$AsyncTask
                )

                # GetResult() would be void, but we only just have to wait
                return $script:OcrActionAwaiter.
                    Invoke($null, @($AsyncTask)).
                    GetResult()
            }
        }

        $script:OcrInitialized = $true
    }
    catch {
        throw '***   OCR requires Windows 10 or above and PowerShell .'
    }
}


# Read images and find keywords
function Get-ImageOcrMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$KeywordPattern,
        [string]$LanguageTag = 'en-US' # Currently I fixed 'en-US' since $KeywordPattern has English words only.
    )

    Initialize-OcrWinRT

    try {
        if ($LanguageTag) {
            $lang      = New-Object Windows.Globalization.Language $LanguageTag
            $ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
        } else {
            $ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
        }
        if (-not $ocrEngine) { return $null }

        $fileTask    = [Windows.Storage.StorageFile]::GetFileFromPathAsync($Path)
        $storageFile = Invoke-WinRtAsync $fileTask ([Windows.Storage.StorageFile])

        $contentTask = $storageFile.OpenAsync([Windows.Storage.FileAccessMode]::Read)
        $fileStream  = Invoke-WinRtAsync $contentTask ([Windows.Storage.Streams.IRandomAccessStream])

        $decoderTask   = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($fileStream)
        $bitmapDecoder = Invoke-WinRtAsync $decoderTask ([Windows.Graphics.Imaging.BitmapDecoder])

        $bmpTask        = $bitmapDecoder.GetSoftwareBitmapAsync()
        $softwareBitmap = Invoke-WinRtAsync $bmpTask ([Windows.Graphics.Imaging.SoftwareBitmap])

        $ocrTask   = $ocrEngine.RecognizeAsync($softwareBitmap)
        $ocrResult = Invoke-WinRtAsync $ocrTask ([Windows.Media.Ocr.OcrResult])

        $lines = @()
        foreach ($line in $ocrResult.Lines) {
            $lineText = ($line.Words | ForEach-Object { $_.Text }) -join ' '
            if ($lineText) { $lines += $lineText }
        }

        $matched = $lines | Where-Object { $_ -match $KeywordPattern }
        if ($matched) {
            return @{ 'OCR' = ($matched -join "`n") }
        }

        return $null
    }
    catch {
        Write-Host "Image OCR failed for '$Path': $($_.Exception.Message)"
        return $null
    }
}

# Read pdf and find keywords
function Get-PdfOcrMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$KeywordPattern,
        [string]$LanguageTag = 'en-US' # Currently I have fixed 'en-US' now since KeywordPattern has English words only.
    )

    Initialize-OcrWinRT

    try {
        if ($LanguageTag) {
            $lang      = New-Object Windows.Globalization.Language $LanguageTag
            $ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
        } else {
            $ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
        }
        if (-not $ocrEngine) { return $null }

        $fileTask    = [Windows.Storage.StorageFile]::GetFileFromPathAsync($Path)
        $storageFile = Invoke-WinRtAsync $fileTask ([Windows.Storage.StorageFile])

        $pdfTask = [Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($storageFile)
        $pdfDoc  = Invoke-WinRtAsync $pdfTask ([Windows.Data.Pdf.PdfDocument])
        if (-not $pdfDoc) { return $null }

        $pageMatches = @{}
        $pageCount   = $pdfDoc.PageCount

        for ($i = 0; $i -lt $pageCount; $i++) {
            $page = $pdfDoc.GetPage($i)
            if (-not $page) { continue }

            $stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream

            # IAsyncAction --> Invoke-WinRtAction
            $renderAction = $page.RenderToStreamAsync($stream)
            $null = Invoke-WinRtAction $renderAction

            $decoderTask = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)
            $decoder     = Invoke-WinRtAsync $decoderTask ([Windows.Graphics.Imaging.BitmapDecoder])

            $bmpTask        = $decoder.GetSoftwareBitmapAsync()
            $softwareBitmap = Invoke-WinRtAsync $bmpTask ([Windows.Graphics.Imaging.SoftwareBitmap])

            $ocrTask   = $ocrEngine.RecognizeAsync($softwareBitmap)
            $ocrResult = Invoke-WinRtAsync $ocrTask ([Windows.Media.Ocr.OcrResult])

            $lines = @()
            foreach ($line in $ocrResult.Lines) {
                $lineText = ($line.Words | ForEach-Object { $_.Text }) -join ' '
                if ($lineText) { $lines += $lineText }
            }

            $matched = $lines | Where-Object { $_ -match $KeywordPattern }
            if ($matched) {
                $pageKey = "Page $($i + 1)"
                $pageMatches[$pageKey] = ($matched -join "`n")
            }

            $page.Dispose()
            $stream.Dispose()
        }

        if ($pageMatches.Count -gt 0) { return $pageMatches }
        return $null
    }
    catch {
        Write-Host "PDF OCR failed for '$Path': $($_.Exception.Message)"
        return $null
    }
}





# Content scanning runs only if the script runs with -contentScan argument
if ($contentScan) {
	
	Write-Host "***`n************************************************************`n***"
	Write-Host "***   Scanning file contents..." -ForegroundColor Yellow
	Write-Host "***`n***   Keywords are: $(($defaultKeywords | ForEach-Object { $_ } ) -join ',')"
	Write-Host "***`n************************************************************"
	Write-Host "***"
	
	foreach ($dir in $foundFiles.Keys) {
		foreach ($file in $foundFiles[$dir]) {
			$fileFullName = $file.FullName
			$ext = $fileFullName.Split('.')[-1]
			
			# scan txt files
			if ($ext -in @('txt', 'csv')) {
				$fileFullName
				$keywordFound = Select-String -Path $fileFullName -Pattern $keywordPtn -ErrorAction SilentlyContinue
				
				if ($keywordFound) {
					$matches = Select-String -Path $fileFullName -Pattern $keywordPtn -ErrorAction SilentlyContinue
					$matchedLines = @()
					
					foreach ($m in $matches) {
						$matchedLines += ("[Line $($m.LineNumber)] $($m.Line)")
					}
					
					$obj = New-Object PSObject -Property @{
						Name = $fileFullName
						MatchedLines = $matchedLines -join "`n***      "
					}
					
					$keywordFoundFiles.Add($obj)
				}		
			}
			
			# scan docx files
			if ($ext -eq 'docx') {
				$keywordFound = Get-DocxText $fileFullName
				if ($keywordFound.Count -gt 0) {
					$obj = New-Object PSObject -Property @{
						Name = $fileFullName
						MatchedLines = $keywordFound
					}
					$keywordFoundFiles.Add($obj)
				}
			}
			
			# scan pptx files
			if ($ext -eq 'pptx') {
				$keywordFound = Get-PptxSlidesText $fileFullName
				if ($keywordFound.Count -gt 0) {
					$obj = New-Object PSObject -Property @{
						Name = $fileFullName
						MatchedLines = $keywordFound
					}
					$keywordFoundFiles.Add($obj)
				}
			}
			
			# scan xlsx files
			if ($ext -eq 'xlsx') {
				$keywordFound = Get-ExcelText $fileFullName
				if ($keywordFound.Count -gt 0) {
					$obj = New-Object PSObject -Property @{
						Name = $fileFullName
						MatchedLines = $keywordFound
					}
					$keywordFoundFiles.Add($obj)
				}
			}
			
			# scan image files
			if ($ext -in @('png','jpg','jpeg','jfif','bmp','tif','tiff')) {
				$keywordFound = Get-ImageOcrMatches -Path $fileFullName -KeywordPattern $keywordPtn
				if ($keywordFound -and $keywordFound.Count -gt 0) {
					$obj = New-Object PSObject -Property @{
						Name         = $fileFullName
						MatchedLines = $keywordFound   # Hashtable: 'OCR' = lines
					}
					$keywordFoundFiles.Add($obj)
				}
			}
			
			# scan pdf files
			if ($ext -eq 'pdf') {
                $keywordFound = Get-PdfOcrMatches -Path $fileFullName -KeywordPattern $keywordPtn
                if ($keywordFound -and $keywordFound.Count -gt 0) {
                    $obj = New-Object PSObject -Property @{
                        Name         = $fileFullName
                        MatchedLines = $keywordFound
                    }
                    $keywordFoundFiles.Add($obj)
                }
            }
			
			
			
		}
	}
	

	# Print content scanning result
	if ($keywordFoundFiles.Count -gt 0) {
		Write-Host "***   Keyword(s) found in the following files:`n***"
		foreach($f in $keywordFoundFiles) {
			Write-Host "***   [File]: $($f.Name)"
			
			if ($f.MatchedLines -is [Hashtable]) {
				$f.MatchedLines.GetEnumerator() | Sort-Object Key | ForEach-Object {
					Write-Host ("***      [{0}] {1}" -f $_.Key, $_.Value)
				}
			} else {
				Write-Host "***      $($f.MatchedLines)"
			}
			
			Write-Host "***"
		}
	} else {Write-Host "***   No Keywords found in the scanned files.`n***`n***"}
	
	
}





####################################
### Scan external drive PnP logs ###
####################################
#
#	Initial added date: 2025-10-23
#

Write-Host "***`n************************************************************`n***"
Write-Host "***   Scanning traits of external storage in the last $days days..." -ForegroundColor Yellow
Write-Host "***`n************************************************************"
Write-Host "***"

$UMDFLogName = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"

# Check if UMDF log feature is currently enabled.
if ((Get-WinEvent -ListLog $UMDFLogName).IsEnabled) {
	Write-Host "***   UMDF event log is currently enabled.`n***"
} else {
	Write-Host "***   UMDF event log is currently disabled.`n***"
}

# Check UMDF records remaining in the system.
$Script:HasUMDF = $true

try {
	# Looking for keyword: 'finished Pnp or Power operation'
	$UMDFRecords = (Get-WinEvent -FilterHashtable @{LogName=$UMDFLogName; StartTime=$dateThreshold} -ErrorAction Stop| 
		Where-Object {($_.Message -match "finished")} | Select-Object TimeCreated, Message)
} catch {
	if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') {
		Write-Host "***   No UMDF events found in the last $days days..."
	} else {
		Write-Host "***   An error occurred while retrieving events: $_.Exception.Message"
	}
	$Script:HasUMDF = $false
} 

# Print PnP events if they are found
if ($Script:HasUMDF) {
	Write-Host ("***`n***   Total UMDF events found in the last {0} days: {1}" -f $days, $UMDFRecords.Count)
	
	foreach ($event in $UMDFRecords) {
		$eventMsg = $event.Message -replace 'Forwarded.*?device\s*', ''
		Write-Host ("***   [{0}] {1}" -f $event.TimeCreated, $eventMsg)
	}
}


Write-Host  "***"
Write-Host  "***"
Write-Host  "***"

# Parse USBSTOR driver-install blocks from setupapi.dev.log
Write-Host  "***   Extracting USBSTOR logs from setupapi.dev.log..."

$setupApiDevLogPath = "$env:SystemRoot\INF\setupapi.dev.log"
$log = Get-Content -LiteralPath $setupApiDevLogPath -Raw

# Regex searching USBSTOR in the header
$blockPtn = '(?im)^>>>[ \t]+\[(?:Device Install|Driver Install)[^\]]*?USB[^\]]*\](?:\r\n|\n|\r)[^\r\n]*'
$blocks = [regex]::Matches($log, $blockPtn)

$filteredBlocks = New-Object System.Collections.Generic.List[object]

# # regex testing code:
# if (blocks.Count -eq 0) { write-host "***   bullshit regex. do it again."}



# (2025-11-05) Helper to get friendly name from Registry
function Get-FriendlyName {
	param([string]$Path)
	
	if (-not (Test-Path $instanceRegPath)) {write-host "***   No instance path found"}
	else{
		$reg = Get-ItemProperty $instanceRegPath
		if ($reg.PSObject.Properties.Name -contains 'FriendlyName') {
			return $reg.FriendlyName
		}
		return "No friendly name found"
	}
		
}


foreach ($b in $blocks) { 
	$entry = $b.Groups[0].Value
	
	# Extract entries after the $dateThreshold
	if ($entry -match 'Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})') {
		$dateStr = $matches[1]
		$entryDate = [datetime]::ParseExact($dateStr, "yyyy/MM/dd HH:mm:ss", $null)
		
		if ($entryDate -ge $dateThreshold) {
			# (2025-11-05) Look for friendly name stored in registry based on the entry information
			$friendlyName = "No friendly name found"
			if ($entry -match '(?i)(?<=USBSTOR#)[^#]+#[^#]+') {
				$usbInstanceID = $matches[0].replace("#", "\")
				$instanceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\$usbInstanceID"
				$friendlyName = Get-FriendlyName $instanceRegPath
			}
			if ($entry -match '(?i)(?<=-\s*)USB\\[^\]]+') {
				$usbInstanceID = $matches[0]
				$instanceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$usbInstanceID"
				$friendlyName = Get-FriendlyName $instanceRegPath
			}
			
			$entry += "`n***   Friendly Name: $friendlyName"
			$filteredBlocks.Add($entry)
		}
	}
	
}

Write-Host "***`n***   Total USBSTOR logs found: $($filteredBlocks.Count)"
Write-Host "***"

foreach($e in $filteredBlocks) {
	($e).Replace(">>>", "*** ")
	Write-Host "***"
}



# Record end time
$endTime = Get-Date
$elapsedTime = $endTime - $startTime

Write-Host "***`n************************************************************`n***"
Write-Host "***   NSE System scan completed."
Write-Host "***   Scan duration: $elapsedTime"
Write-Host "***`n************************************************************"


# Stop logging
Stop-Transcript




# # Copying the logFile to the directory where the script is located (2025-10-23)
$destPath = $PSScriptRoot
Write-Host "`n"
if (Test-Path $logFile) {
	try {
		Copy-Item -Path $logFile -Destination $destPath -ErrorAction Stop
		$logFileName = $logFile.Split('\')[-1]
		$filePath = Join-Path -Path $destPath -ChildPath $logFileName
		Write-Host "The file successfully copied to: " -NoNewline
		Write-Host "$filePath"
	} catch {
		Write-Host "Something went wrong while copying the file: " -NoNewline
		Write-Host "$($_.Exception.Message)" -ForegroundColor Red
	}
} else {
	Write-Host "Cannot find the log file."
}
