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
Import-Module (Join-Path $PSScriptRoot 'lib' 'Baseline.psm1') -Force
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

# 2. Lenses. Run each; the effective verdict is computed afterward through the
# suppression baseline. $crash tracks only lenses that ran but wrote no verdict.
$crash = 'clean'
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
            # A lens that RAN but wrote no verdict is a genuine crash; the
            # baseline (which reads written JSON) can't see it, so track it here.
            Log "lens ${lname}: CRASHED (no valid verdict) - escalating to scan_error"
            $crash = Resolve-WorseStatus $crash 'scan_error'
            continue
        }
        $lj = Get-Content -LiteralPath $ljPath -Raw | ConvertFrom-Json
        $lstatus = [string]$lj.status
        Log "lens ${lname}: status=$lstatus findings=$($lj.findings_total)"
    }
}

# Effective verdict AFTER the suppression baseline, via the same classifier
# report.ps1 uses (one source of truth). Suppressed findings drop out; MUTATED
# pins resurface; incomplete/scan_error are never downgraded. Then worst-wins
# the crashed-lens escalation in.
$eff = Get-HoneyEffectiveOverall -RunDir $runDir
$overall = Resolve-WorseStatus $eff.status $crash

Log "=== cycle end (bumblebee=$bbStatus overall=$overall suppressed=$($eff.suppressed) mutated=$($eff.mutated) expired=$($eff.expired)) ==="
if ($overall -eq 'clean') { exit 0 } else { exit 1 }
