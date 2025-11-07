# SystemScan10.ps1
# 
# NSE Security System Scan Report PowerShell Script
# 
# intended to scan laptops for potential exfiltration of data based on changes done in the past xxx days
# xxx is the number of days, default 56 days (8 weeks)

#
# Check out the SystemScan.README.txt for command line run instructions.

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
# Dongchan Lee 2025-11-05	Release 10.2 (minor fixes and improvements)
 
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
Write-Host "***   " -NoNewline
Write-Host "Scanning for files and directories containing data, modified or created in the last $days days..." -ForegroundColor Yellow
Write-Host  "***`n************************************************************"

# Record start time
$startTime = Get-Date

# Define the date threshold for filtering files
$dateThreshold = (Get-Date).AddDays(-$days)

# Define excluded directories
$excludedDirs = @("AppData", "Windows", "Program Files", "Program Files (x86)")

# Define data file extensions of interest
$dataFileExtensions = @(".jpg", ".png", ".mp4", ".mov", ".docx", ".xlsx", ".pptx", ".txt", ".pdf", ".csv", ".zip")

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
# Get all non-C: drives, exclude USB (DriveType = 2)
# (2025-11-05) Skipping network drive (DriveType = 4)
$nonUSBDrives = Get-CimInstance Win32_LogicalDisk | Where-Object {
    $_.DeviceID -ne 'C:' -and $_.DriveType -notin 2, 4
}

# Get corresponding PowerShell drives (PSDrive) for safe access
$extraDrives = @()
foreach ($drive in $nonUSBDrives) {
    $psDrive = Get-PSDrive -Name ($drive.DeviceID.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($psDrive) {
        $extraDrives += $psDrive
    }
}



# Some large directories

function Get-DriveFilesSafe {
	param(
		[string]$Root,
		[string[]]$Extensions
	)
	
}





if ($extraDrives) {
    Write-Host  "`n************************************************************"
    Write-Host  "***`n***   Scanning additional partitions and external drives..."

    foreach ($drive in $extraDrives) {
		
		# Handle a case when we cannot read the drive (2025-10-23)
		# Enveloped the preexisting codes with try-catch.
		#	- In general, the error occurs when the drive is too large and the scanning process runs out of memory.
		$driveLetter = $drive.Root
		Write-Host "***   Scanning drive: $driveLetter"
		try {
			# (2025-10-23) Added a condition "-and ($_.Length -gt 0)" to ignore file with size 0
			#	- In this way, we can also ignore cloud-only files existing in the endpoint.
			# 	- The local keeps the inks of cloud-only files, which are of size 0 on disk.
			# (2025-11-05) Minor fixes
			#	- Unwanted error message fix by adding "-ErrorAction Stop 2>$null" (The error message will be displayed at 'catch')
			#	- Skipping symbolic links (ReparsePoint in Windows) while scanning by adding "-Attributes !ReparsePoint"
			$files = Get-ChildItem -Path $driveLetter -Recurse -File -Attributes !ReparsePoint -ErrorAction Stop 2>$null | 
                 Where-Object { ($_.LastWriteTime -ge $dateThreshold -or $_.CreationTime -ge $dateThreshold) -and ($_.Extension -in $dataFileExtensions) -and ($_.Length -gt 0)} |
                 Select-Object FullName, LastWriteTime, CreationTime
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
    Write-Host "`n************************************************************"
    Write-Host "`n***   No relevant files found in user directories, Recycle Bin, or other partitions."
}


#############################
### File Content Scanning ###
#############################
#
#	Initially added date: 2025-10-31
#   The compatibility test was only carried out under Powershell v5.1.26100 and .Net Framework 4.8
#


# Define keywords to look up in documents
$defaultKeywords = @('confidential', 'nextstar energy', 'nse ')
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
	Copy-Item $Path $tmpZip
	Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force
	
	
	# (2025-11-05) Scanning logic fix for docx
	# 	- Now it scans through headers and footers as well.
	$fileNames = @(Join-Path $tmpFolder 'word\document.xml') + 
		(Get-ChildItem -LiteralPath (Join-Path $tmpFolder 'word') -Filter 'header*.xml' -ErrorAction SilentlyContinue |
			ForEach-Object { $_.FullName }) +
		(Get-ChildItem -LiteralPath (Join-Path $tmpFolder 'word') -Filter 'footer*.xml' -ErrorAction SilentlyContinue |
			ForEach-Object { $_.FullName })
	$docxTexts = @{}
	
	foreach($docxFile in $fileNames){
		[xml]$xml = Get-Content -LiteralPath $docxFile -Raw
		
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
	Copy-Item $Path $tmpZip -Force
	Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force
	
	$slidesDir = Join-Path $tmpFolder "ppt\slides"
	if (-not (Test-Path -LiteralPath $slidesDir)) {return}
	$slideFiles = Get-ChildItem -LiteralPath $slidesDir -Filter "slide*.xml" -File
	
	$slideTexts = @{}
	
	
	foreach($sf in $slideFiles) {
		[xml]$xml = Get-Content $sf.FullName -Raw
		
		$tNodes = $xml.SelectNodes('//*[local-name()="t" and namespace-uri()="http://schemas.openxmlformats.org/drawingml/2006/main"]')
		
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
	Copy-Item $Path $tmpZip -Force
	Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force
	
	
	$excelTexts = @{}
	
	# 1) sharedStrings.xml
	$sharedStrings = Join-Path $tmpFolder "xl\sharedStrings.xml"
	if (-not (Test-Path -LiteralPath $sharedStrings)) {
		Write-Warning "xl\sharedStrings.xml not found in $Path"
		return
	}
	[xml]$ssXml = [xml]$ssXml = Get-Content -LiteralPath $sharedStrings -Raw -Encoding UTF8
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
		[xml]$xml = Get-Content $df.FullName -Raw -Encoding UTF8
		
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
		[xml]$xml = Get-Content $cf.FullName -Raw -Encoding UTF8
		
		$paths = @(
			'//*[local-name()="t" and namespace-uri()="http://schemas.openxmlformats.org/drawingml/2006/main"]',
            '//*[local-name()="v" and namespace-uri()="http://schemas.openxmlformats.org/drawingml/2006/chart"]',
            '//*[local-name()="tx"]//*[local-name()="t"]',
            '//*[local-name()="rich"]//*[local-name()="t"]',
            '//*[local-name()="title"]//*[local-name()="t"]',
            '//*[local-name()="legend"]//*[local-name()="t"]'
		)
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


# Content scanning runs only if the script runs with -contentScan argument
if ($contentScan) {
	
	Write-Host "***`n************************************************************`n***"
	Write-Host "***   " -NoNewline
	Write-Host "Scanning file contents..." -ForegroundColor Yellow
	Write-Host "***`n***   Keywords are: $(($defaultKeywords | ForEach-Object { $_ } ) -join ',')"
	Write-Host "***`n************************************************************"
	Write-Host "***"
	
	foreach ($dir in $foundFiles.Keys) {
		foreach ($file in $foundFiles[$dir]) {
			$fileFullName = $file.FullName
			$ext = $fileFullName.Split('.')[-1]
			
			# scan txt files
			if ($ext -eq 'txt') {
				$keywordFound = Select-String -Path $fileFullName -Pattern $keywordPtn -SimpleMatch -ErrorAction SilentlyContinue
				
				if ($keywordFound) {
					$matches = Select-String -Path $fileFullName -Pattern $keywordPtn -SimpleMatch -ErrorAction SilentlyContinue
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
			
			
		}
	}
	

	# Print content scanning result
	if ($keywordFoundFiles.Count -gt 0) {
		Write-Host "***   Keyword(s) found in the following files:`n"
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
	}
	
	
}





####################################
### Scan external drive PnP logs ###
####################################
#
#	Initial added date: 2025-10-23
#

Write-Host "***`n************************************************************`n***"
Write-Host "***   " -NoNewline
Write-Host "Scanning traits of external storage in the last $days days..." -ForegroundColor Yellow
Write-Host "***`n************************************************************"
Write-Host "***"

$UMDFLogName = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"

# Check if UMDF log feature is currently enabled.
if ((Get-WinEvent -ListLog $UMDFLogName).IsEnabled) {
	Write-Host "***   UMDF event log is currently enabled.`n***"
} else {
	Write-Host "***   UMDF event log is currently disabled.`n***"
}

###
# Currently disabled to reduce the noise.
###
# # Check UMDF records remaining in the system.
# Write-Host  "***"
# Write-Host  "***   Total UMDF events found: $((Get-WinEvent -LogName $UMDFLogName).Count)"
# Write-Host  "***"
# Write-Host  "***"
# 
# if ($UMDFCount -eq 0) {
# 	Write-Host  "***   No UMDF events recorded in the system."
# } else {
# 	
# 	# Looking for keywords: "finished Pnp or Power operation"
# 	$UDMFRecords = (Get-WinEvent -FilterHashtable @{LogName=$UMDFLogName; StartTime=$dateThreshold} | 
# 		Where-Object {($_.Message -match "finished" )} | Select-Object TimeCreated, Message)
# 	
# 	foreach ($event in $UDMFRecords) {
# 		Write-Host ("***   $($event.TimeCreated) - $($event.Message)`n***")
# 	}
# }
# 
# Write-Host  "***"
# Write-Host  "***"
# Write-Host  "***"
# Write-Host  "***"

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

Write-Host "***   Total USBSTOR logs found: $($filteredBlocks.Count)"
Write-Host "***"
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




# Copying the logFile to the directory where the script is located (2025-10-23)
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
