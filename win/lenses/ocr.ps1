<#
.SYNOPSIS
  honey (Windows) lens: ocr — OCR images bundled in agent skills and flag hidden
  INSTRUCTIONS (the multimodal "SkillCamo" blind spot). PowerShell mirror of
  lenses/ocr.sh. Offline; uses tesseract. Self-skips if tesseract isn't installed.

.PARAMETER RunDir
  Run directory to write lens-ocr.json into.
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

if (-not $RunDir) { Write-Error 'usage: ocr.ps1 -RunDir <dir>'; exit 2 }

if (-not (Get-Command tesseract -ErrorAction SilentlyContinue)) {
    Write-LensResult -RunDir $RunDir -Lens 'ocr' -Status 'skipped' -Findings @() -Note "tesseract not found - ocr lens skipped (install tesseract to enable image-payload detection)." | Out-Null
    Write-HoneyConsole "lens ocr: tesseract not installed, skipped"; exit 0
}

$home_ = Get-HoneyHome
$defaultRoots = @(
    (Join-Path $home_ '.claude\skills'), (Join-Path $home_ '.claude\plugins'),
    (Join-Path $home_ '.claude\scheduled-tasks'), (Join-Path $home_ '.config\claude\skills')
) -join ';'
$roots = (Get-HoneySetting 'HONEY_SKILL_ROOTS' $defaultRoots) -split ';' | Where-Object { $_ }
$max = [int](Get-HoneySetting 'HONEY_OCR_MAX' '300')
$injectRe = [regex](Get-HoneySettingRaw 'HONEY_OCR_PATTERNS' '(?i)ignore\s+(the\s+)?(previous|prior|above|earlier|all)|disregard\s+(the|all|any)|system\s+prompt|exfiltrat|curl\s+\S*http|wget\s+\S*http|base64\s+-d|~/\.(ssh|aws|config)|do\s+not\s+(tell|reveal|mention|inform)|override\s+.*instruction|send\s+.*(token|secret|credential|key)')
$exts = '.png','.jpg','.jpeg','.tif','.tiff','.bmp','.gif','.webp'

# Feed image bytes to tesseract via stdin (avoids leptonica path-read quirks).
function Invoke-Tesseract {
    param([string]$Image)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'tesseract'; $psi.Arguments = 'stdin stdout'
    $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true; $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Image)
        $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        return $out
    } catch { return '' } finally { $p.Dispose() }
}

$findings = New-Object System.Collections.ArrayList
$scanned = 0
$images = foreach ($root in $roots) {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $exts -contains $_.Extension.ToLower() }
    }
}
$images = @($images) | Select-Object -First $max

foreach ($img in $images) {
    $scanned++
    $text = Invoke-Tesseract $img.FullName
    if (-not $text) { continue }
    $m = $injectRe.Match($text)
    if ($m.Success) {
        $flat = ($text -replace '\s+', ' ')
        $idx = $flat.IndexOf($m.Value)
        $start = [Math]::Max(0, $idx - 30); $len = [Math]::Min($flat.Length - $start, $m.Value.Length + 60)
        $snippet = $flat.Substring($start, $len)
        [void]$findings.Add([pscustomobject]@{
            severity = 'high'; title = 'Instructions hidden in image (possible SkillCamo)'
            location = $img.FullName
            detail = "OCR recovered instruction-like text from this image (possible SkillCamo hidden payload): ...$snippet..."
            ref = 'multimodal-evasion'
        })
    }
}

$tv = ((& tesseract --version 2>&1 | Select-Object -First 1) -split '\s+')[1]
$note = "OCR-scanned $scanned image(s) under $($roots -join ';') for hidden instructions (tesseract $tv)"
if ($scanned -eq 0) { $note = "no images found under agent-skill roots: $($roots -join ';')" }
$status = if (@($findings).Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens 'ocr' -ToolVersion ([string]$tv) -Status $status -Findings @($findings) -Note $note | Out-Null
Write-HoneyConsole "lens ocr: status written ($(@($findings).Count) finding(s), $scanned image(s))"
exit 0
