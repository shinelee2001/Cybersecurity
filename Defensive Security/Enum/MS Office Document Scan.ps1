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
	Copy-Item -LiteralPath $Path $tmpZip -Force
	Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpFolder -Force
	
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
	Copy-Item -LiteralPath $Path $tmpZip -Force
	Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpFolder -Force
	
	
	$excelTexts = @{}
	
	# 1) sharedStrings.xml
	$sharedStrings = Join-Path $tmpFolder "xl\sharedStrings.xml"
	if (-not (Test-Path -LiteralPath $sharedStrings)) {
		# Write-Warning "xl\sharedStrings.xml not found in $Path"
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
