$keywords = @('confidential', 'top-secret', 'secret')

# Convert the keywords into regex
$keywordPtn = ($keywords | ForEach-Object{[regex]::Escape($_)}) -join "|"
$keywordPtn = "(?i:$keywordPtn)"

$keywordFoundFiles = New-Object System.Collections.Generic.List[object]

# Helper for DOXC
function Get-DoxcText {
	param([string]$Path)

    # Temp file and folder to unzip the document
    $tmpZip = [System.IO.Path]::ChangeExtension($Path, ".zip")
    $tmpFolder = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) "tmp_docx"

    # Check if the temp file or folder exists and remove them before unzip the current document
    if (Test-Path -LiteralPath $tmpFolder) {Remove-Item -Recurse -Force $tmpFolder}
    if (Test-Path -LiteralPath $tmpZip) {Remove-Item -Force $tmpZip}

    # Unzip the document in temp folder
    Copy-Item $Path $tmpZip
    Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force

    $documentXml = Join-Path $tmpFolder "word\document.xml"
    [xml]$xml = Get-Content $documentXml
    $textNodes = $xml.GetElementsByTagName("w:t")
    $text = ($textNodes | ForEach-Object{$_.'#text'}) -join ' '
    $lines = $text -split '\. '

    # Look up for the keywords
    $matched = $lines | Where-Object {$_ -match $keywordPtn}

    # Remove temp file and folder
    Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip

    if (-not ($matched)) {return}
    return $text
}

# Helper for PPTX
function Get-PptxText {
    param([string]$Path)

    # Temp file and folder to unzip document
    $tmpZip = [System.IO.Path]::ChangeExtension($Path, ".zip")
    $tmpFolder = Join-Path [System.IO.Path]::GetDirectoryName($Path) "tmp_pptx"

    # Check if the temp file or folder exists and remove them before unzip the current document
    if (Test-Path -LiteralPath $tmpFolder) {Remove-Item -Recurse -Force $tmpFolder}
    if (Test-Path -LiteralPath $tmpZip) {Remove-Item -Force $tmpZip}

    # Unzip the document in temp folder
    Copy-Item $Path $tmpZip
    Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force

    $slideDir = Join-Path $tmpFolder "ppt\slides"
    $slideFiles = Get-ChildItem $slideDir -Filter "slide*.xml" -File

    $slideTexts = @{}
    foreach($sf in $slideFiles){
        [xml]$xml = Get-Content $sf.FullName
        $textNodes = $xml.SelectNodes('//*[local-name()="t"]')
        $text = ($textNodes | ForEach-Object{$_.InnerText}) -join ' '
        $lines = $text -split '\. '

        # Look up for the keywords
        $matched = $lines | Where-Object{$_ -match $keywordPtn}
        if ($matched){$slideTexts[$sf.Name] = ($matched) -join "`n"}
    }

    # Remove temp file and folder
    Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip

    return $slideTexts
}

# Helper for XLSX
function Get-XlsxText {
    param([string]$Path)

    # Temp file and folder to unzip document
    $tmpZip = [System.IO.Path]::ChangeExtension($Path, ".zip")
    $tmpFolder = Join-Path [System.IO.Path]::GetDirectoryName($Path) "tmp_xlsx"

    # Check if the temp file or folder exists and remove them before unzip the current document
    if (Test-Path -LiteralPath $tmpFolder) {Remove-Item -Recurse -Force $tmpFolder}
    if (Test-Path -LiteralPath $tmpZip) {Remove-Item -Force $tmpZip}

    # Unzip the document in temp folder
    Copy-Item $Path $tmpZip
    Expand-Archive -Path $tmpZip -DestinationPath $tmpFolder -Force

    $excelTexts = @{}

    # 1) sharedStrings.xml
    $sharedStringsXml = Join-Path $tmpFolder "xl\sharedStrings.xml"
    [xml]$ssXml = Get-Content $sharedStringsXml
    $ssTextNodes = $ssXml.SelectNodes('//*[local-name()="t"]')
    $ssText = ($ssTextNodes | ForEach-Object{$_.InnerText}) -join ' '
    $ssLines = $ssText -split '\. '

    $ssMatched = $ssLines | Where-Object{$_ -match $keywordPtn}
    if ($ssMatched) {$excelTexts["sharedStrings.xml"]=($ssMatched -join "`n")}

    # 2) drawing*.xml
    $drawingDir = Join-Path $tmpFolder "xl\drawings"
    $drawingFiles = Get-ChildItem $drawingDir -Filter "drawing*.xml" -File
    foreach($df in $drawingFiles){
        [xml]$dfXml = Get-Content $df.FullName
        $dfTextNodes = $dfXml.SelectNodes('//*[local-name()="t"]')
        $dfText = ($dfTextNodes|ForEach-Object{$_.InnerText}) -join ' '
        $dfLines = $dfText -split '\. '

        $dfMatched = $dfLines | Where-Object{$_ -match $keywordPtn}
        if ($dfMatched){$excelTexts[$df.Name]=($dfMatched -join "`n")}
    }

    # 3) chartEx*.xml
    $chartDir = Join-Path $tmpFolder "xl\charts"
    $chartFiles = Get-ChildItem $chartDir -Filter "chart*.xml" -File
    foreach($cf in $chartFiles){
        [xml]$cfXml = Get-Content $cf.FullName
        $cfTextNodes = $cfXml.SelectNodes(
            '//*[local-name()="t"]',
            '//*[local-name()="v"]',
            '//*[local-name()="tx"]',
            '//*[local-name()="rich"]',
            '//*[local-name()="title"]',
            '//*[local-name()="legend"]'
            )
        $cfText = ($cfTextNodes|ForEach-Object{$_.InnerText}) -join ' '
        $cfLines = $cfText -split '\. '

        $cfMatched = $cfLines | Where-Object{$_ -match $keywordPtn}
        if ($cfMatched){$excelTexts[$cf.Name]=($cfMatched -join "`n")}
    }

    # Remove temp file and folder
    Remove-Item -Recurse -Force $tmpFolder
    Remove-Item -Force $tmpZip

    return $excelTexts
}
