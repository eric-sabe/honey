<#
.SYNOPSIS
  honey (Windows): one full cycle — run-scan (bumblebee) then every lens,
  worst-wins overall. PowerShell port of daily-cycle.sh.

.NOTES
  Exit codes (match bash): 0 clean, 1 needs attention (fresh exposed/incomplete/
  scan_error), 2 cycle failure (no fresh manifest / stale latest). Carries the
  two adversarial-review fixes: the freshness guard (manifest run_id >= cycle
  start) and crashed-lens escalation (a lens that ran but wrote no verdict ->
  scan_error, never silently ignored).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$honeyRoot = Get-HoneyRoot
function Log { param($m) Write-HoneyLog -HoneyRoot $honeyRoot -Message $m }

Log "=== cycle start ==="
# Stamp the cycle start (same sortable form run-scan uses for run_id), so a stale
# `latest` left by an interrupted run can't be mistaken for a fresh result.
$cycleStart = Get-HoneyTimestamp

# 1. Scan.
& (Join-Path $PSScriptRoot 'run-scan.ps1')
$scanRc = $LASTEXITCODE
Log "run-scan.ps1 exit: $scanRc"

$runDir = Get-HoneyLatest -HoneyRoot $honeyRoot
$manifestPath = if ($runDir) { Join-Path $runDir 'manifest.json' } else { $null }
if (-not $runDir -or -not (Test-Path $manifestPath)) {
    Log "ERROR no manifest after scan; aborting cycle (run-scan exit $scanRc)"
    exit 2
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$runId = if ($manifest.PSObject.Properties.Name -contains 'run_id') { [string]$manifest.run_id } else { '' }
# Freshness guard: manifest must be from THIS cycle, not a stale latest.txt.
if (-not $runId -or ($runId -lt $cycleStart)) {
    Log "ERROR latest run ($runId) predates this cycle ($cycleStart) - run-scan did not complete; treating as failure"
    exit 2
}

$bbStatus = [string]$manifest.status
$bbTotal  = $manifest.findings_total
Log "manifest status=$bbStatus findings=$bbTotal run_dir=$runDir"

# 2. Lenses. Worst-wins; a lens that RAN but wrote no valid verdict -> scan_error.
$overall = $bbStatus
$lensDir = Join-Path $PSScriptRoot 'lenses'
if (Test-Path $lensDir) {
    foreach ($lens in Get-ChildItem -Path $lensDir -Filter '*.ps1' | Sort-Object Name) {
        $lname = $lens.BaseName
        & $lens.FullName -RunDir $runDir | Out-Null
        $ljPath = Join-Path $runDir "lens-$lname.json"
        $ok = $false
        if (Test-Path $ljPath) {
            try { $null = Get-Content -LiteralPath $ljPath -Raw | ConvertFrom-Json; $ok = $true } catch { $ok = $false }
        }
        if (-not $ok) {
            Log "lens ${lname}: CRASHED (no valid verdict) - escalating to scan_error"
            $overall = Resolve-WorseStatus $overall 'scan_error'
            continue
        }
        $lj = Get-Content -LiteralPath $ljPath -Raw | ConvertFrom-Json
        $lstatus = [string]$lj.status
        Log "lens ${lname}: status=$lstatus findings=$($lj.findings_total)"
        if ($lstatus -eq 'skipped') { continue }
        $overall = Resolve-WorseStatus $overall $lstatus
    }
}

Log "=== cycle end (bumblebee=$bbStatus overall=$overall) ==="
if ($overall -eq 'clean') { exit 0 } else { exit 1 }
