<#
  Minimal Windows OCR helper
  - Requires: Windows PowerShell 5.1, Windows 10/11
  - Uses Windows.Media.Ocr with user profile languages
  - Reference: https://github.com/TobiasPSP/PsOcr/blob/main/Modules/PsOcr/1.1.0/root.psm1
#>

$script:OcrAwaiter    = $null
$script:OcrInitialized = $false
$script:OcrEngine      = $null

function Initialize-OcrRuntime {
    if ($script:OcrInitialized) { return }

    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw "This OCR helper requires Windows PowerShell (Desktop, 5.1)"
    }

    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
    } catch {
        throw "Failed to load System.Runtime.WindowsRuntime. Are you on Windows 10/11 with .NET Framework?"
    }

    # WinRT 타입들 강제로 로드
    $null = [Windows.Storage.StorageFile,                Windows.Storage,         ContentType = WindowsRuntime]
    $null = [Windows.Media.Ocr.OcrEngine,                Windows.Foundation,      ContentType = WindowsRuntime]
    $null = [Windows.Foundation.IAsyncOperation`1,       Windows.Foundation,      ContentType = WindowsRuntime]
    $null = [Windows.Graphics.Imaging.SoftwareBitmap,    Windows.Foundation,      ContentType = WindowsRuntime]
    $null = [Windows.Storage.Streams.RandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
    $null = [WindowsRuntimeSystemExtensions]

    # OCR 관련 WinRT 어셈블리 로드 유도
    $null = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages

    # IAsyncOperation<T>용 awaiter 찾기
    $script:OcrAwaiter = [WindowsRuntimeSystemExtensions].GetMember(
        'GetAwaiter', 'Method', 'Public,Static'
    ) | Where-Object {
        $_.GetParameters().Count -ge 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1

    if (-not $script:OcrAwaiter) {
        throw "Failed to locate WindowsRuntime awaiter method."
    }

    # OCR 엔진 생성 (사용자 프로필 언어 기반)
    $script:OcrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    if (-not $script:OcrEngine) {
        throw "Failed to create OCR engine. Check Windows OCR/language packs."
    }

    $script:OcrInitialized = $true
}

function Invoke-Async {
    param(
        [Parameter(Mandatory)][object]$AsyncTask,
        [Parameter(Mandatory)][Type]$As
    )

    Initialize-OcrRuntime

    return $script:OcrAwaiter.
        MakeGenericMethod($As).
        Invoke($null, @($AsyncTask)).
        GetResult()
}

function Convert-ImageToOcrObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path
    )

    Initialize-OcrRuntime

    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        return
    }

    # StorageFile
    $fileTask     = [Windows.Storage.StorageFile]::GetFileFromPathAsync($Path)
    $storageFile  = Invoke-Async $fileTask -As ([Windows.Storage.StorageFile])

    # Stream
    $contentTask  = $storageFile.OpenAsync([Windows.Storage.FileAccessMode]::Read)
    $fileStream   = Invoke-Async $contentTask -As ([Windows.Storage.Streams.IRandomAccessStream])

    # BitmapDecoder
    $decoderTask   = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($fileStream)
    $bitmapDecoder = Invoke-Async $decoderTask -As ([Windows.Graphics.Imaging.BitmapDecoder])

    # SoftwareBitmap
    $bitmapTask     = $bitmapDecoder.GetSoftwareBitmapAsync()
    $softwareBitmap = Invoke-Async $bitmapTask -As ([Windows.Graphics.Imaging.SoftwareBitmap])

    # OCR
    $ocrTask   = $script:OcrEngine.RecognizeAsync($softwareBitmap)
    $ocrResult = Invoke-Async $ocrTask -As ([Windows.Media.Ocr.OcrResult])

    $ocrResult.Lines | Select-Object -Property Text, @{
        Name       = 'Words'
        Expression = { $_.Words.Text }
    }
}

function Get-OcrText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $lines = Convert-ImageToOcrObject -Path $Path
    return ($lines | Select-Object -ExpandProperty Text) -join "`r`n"
}

function Convert-ImageToTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutFile
    )

    if (-not $OutFile) {
        $base = [IO.Path]::GetFileNameWithoutExtension($Path)
        $dir  = [IO.Path]::GetDirectoryName($Path)
        $OutFile = Join-Path $dir ($base + ".txt")
    }

    $text = Get-OcrText -Path $Path
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($OutFile, $text, $utf8NoBom)

    [PSCustomObject]@{
        Image   = $Path
        OutFile = $OutFile
        Length  = $text.Length
    }
}
