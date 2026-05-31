<#
.SYNOPSIS
  honey (Windows): one bumblebee scan cycle. PowerShell port of run-scan.sh.
  Updates the bumblebee checkout + binary, deep-scans the home dir, writes a
  timestamped run dir with manifest.json, and points latest.txt at it.

.NOTES
  Config (env > honey.conf.ps1 > default): HONEY, BUMBLEBEE_REPO,
  BUMBLEBEE_SCAN_ROOT, BUMBLEBEE_MAX_DURATION. Exit 0 clean, 1 needs attention.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$honeyRoot = Get-HoneyRoot
$home_     = Get-HoneyHome
$repo      = Get-HoneySetting 'BUMBLEBEE_REPO'        (Join-Path $home_ 'git\bumblebee')
$scanRoot  = Get-HoneySetting 'BUMBLEBEE_SCAN_ROOT'   $home_
$maxDur    = Get-HoneySetting 'BUMBLEBEE_MAX_DURATION' '30m'
$goPkg     = 'github.com/perplexityai/bumblebee/cmd/bumblebee@latest'
$catalogDir = Join-Path $repo 'threat_intel'

# Preflight: catalogs must exist (the binary has none). Fail loud, like bash.
$catJsons = @(Get-ChildItem -Path $catalogDir -Filter '*.json' -ErrorAction SilentlyContinue)
if (-not (Test-Path $catalogDir) -or $catJsons.Count -eq 0) {
    Write-Error "honey: no threat_intel catalogs at $catalogDir. Clone bumblebee or set BUMBLEBEE_REPO (run setup.ps1)."
    exit 1
}

$ts = Get-HoneyTimestamp
$runDir = Join-Path $honeyRoot "runs\$ts"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$records  = Join-Path $runDir 'records.ndjson'
$diags    = Join-Path $runDir 'diagnostics.ndjson'
$findings = Join-Path $runDir 'findings.ndjson'
$summary  = Join-Path $runDir 'summary.json'
$manifestPath = Join-Path $runDir 'manifest.json'

function Log { param($m) Write-HoneyLog -HoneyRoot $honeyRoot -Message $m }
Log "run-scan $ts starting (repo=$repo scan_root=$scanRoot)"

# 1. Update the repo (fresh catalogs). Non-fatal.
$repoUpdated = $false
if (Test-Path (Join-Path $repo '.git')) {
    try { & git -C $repo pull --ff-only --quiet 2>$null; $repoUpdated = $true; Log "repo updated" }
    catch { Log "WARN repo update failed (continuing)" }
}
$repoCommit = 'unknown'
try { $repoCommit = (& git -C $repo rev-parse --short HEAD 2>$null) } catch { Write-Verbose 'repo commit unavailable' }

# 2. Update the binary. Non-fatal.
$binaryUpdated = $false
if (Get-Command go -ErrorAction SilentlyContinue) {
    try { & go install $goPkg 2>$null; $binaryUpdated = $true; Log "binary updated" }
    catch { Log "WARN go install failed (continuing)" }
}
$bin = (Get-Command bumblebee -ErrorAction SilentlyContinue)?.Source
if (-not $bin) {
    Log "ERROR bumblebee binary not found; aborting"
    '{"run_id":"' + $ts + '","status":"scan_error","error":"bumblebee binary not found"}' | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Set-HoneyLatest -HoneyRoot $honeyRoot -RunDir $runDir
    exit 1
}
$scannerVersion = (& bumblebee version 2>$null | Select-Object -First 1) -replace '^\S+\s+', ''
if (-not $scannerVersion) { $scannerVersion = 'unknown' }
Log "using binary $bin ($scannerVersion)"

# 3. Run the scan.
Log "scanning $scanRoot (max-duration $maxDur) ..."
& bumblebee scan --profile deep --root $scanRoot --exposure-catalog $catalogDir --findings-only --max-duration $maxDur > $records 2> $diags
$scanExit = $LASTEXITCODE
Log "scan exit code: $scanExit"

# 4. Split records (tolerant: skip a malformed line, keep valid findings).
$findingLines = @(); $summaryObj = $null
if (Test-Path $records) {
    foreach ($line in Get-Content -LiteralPath $records) {
        if (-not $line.Trim()) { continue }
        $rec = $null
        try { $rec = $line | ConvertFrom-Json } catch { continue }
        $rt = if ($rec.PSObject.Properties.Name -contains 'record_type') { $rec.record_type } else { '' }
        if ($rt -eq 'finding') { $findingLines += $line }
        elseif ($rt -eq 'scan_summary') { $summaryObj = $rec; $line | Set-Content -LiteralPath $summary -Encoding utf8 }
    }
}
$findingLines | Set-Content -LiteralPath $findings -Encoding utf8
if (-not (Test-Path $summary)) { '' | Set-Content -LiteralPath $summary -Encoding utf8 }

# Completed vs timed-out: prefer structured scan_summary.timed_out.
$scanCompleted = $true
if ($summaryObj -and ($summaryObj.PSObject.Properties.Name -contains 'timed_out')) {
    if ($summaryObj.timed_out) { $scanCompleted = $false }
} elseif (Test-Path $diags) {
    if (Select-String -Path $diags -Pattern 'timed_out=true' -Quiet) { $scanCompleted = $false }
}

$findingObjs = @($findingLines | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
$total = $findingObjs.Count
$bySev = @{}
foreach ($f in $findingObjs) {
    $s = if ($f.PSObject.Properties.Name -contains 'severity' -and $f.severity) { $f.severity } else { 'unknown' }
    if ($bySev.ContainsKey($s)) { $bySev[$s]++ } else { $bySev[$s] = 1 }
}

# Status (same precedence as bash).
$status =
    if ($scanExit -ne 0) { 'scan_error' }
    elseif ($total -gt 0) { 'exposed' }
    elseif (-not $scanCompleted) { 'incomplete' }
    else { 'clean' }

$filesConsidered = $null
if ($summaryObj -and ($summaryObj.PSObject.Properties.Name -contains 'files_considered')) { $filesConsidered = $summaryObj.files_considered }

$manifest = [ordered]@{
    run_id               = $ts
    finished_at          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host                 = [System.Net.Dns]::GetHostName()
    status               = $status
    scanner_version      = $scannerVersion
    repo_commit          = $repoCommit
    repo_updated         = $repoUpdated
    binary_updated       = $binaryUpdated
    scan_exit_code       = $scanExit
    scan_completed       = $scanCompleted
    scan_root            = $scanRoot
    catalog_dir          = $catalogDir
    findings_total       = $total
    findings_by_severity = $bySev
    files_considered     = $filesConsidered
}
($manifest | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $manifestPath -Encoding utf8
Set-HoneyLatest -HoneyRoot $honeyRoot -RunDir $runDir

Log "done: status=$status findings=$total -> $runDir"
if ($status -eq 'clean') { exit 0 } else { exit 1 }
