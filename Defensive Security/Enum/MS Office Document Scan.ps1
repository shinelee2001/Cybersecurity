$keywords = @('confidential', 'top-secret', 'secret')

# Convert the keywords into regex
$keywordPtn = ($keywords | ForEach-Object{[regex]::Escape($_)}) -join "|"
$keywordPtn = "(?i:$keywordPtn)"

$keywordFoundFiles = New-Object System.Collections.Generic.List[object]

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
		
		$tNodes = $xml.SelectNodes('//*[local-name()="t"')
		
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
	} else {Write-Host "***   No Keywords found in the scanned files.`n***`n***"}
	
	
}
