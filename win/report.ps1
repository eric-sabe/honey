<#
.SYNOPSIS
  honey (Windows): render a triage report from a scan run — no AI. PowerShell
  port of report.sh. Reads manifest.json (bumblebee) + every lens-*.json and
  prints per-scanner sections plus the authoritative OVERALL verdict line.

.PARAMETER RunDir
  Run directory to report on. Defaults to the latest run (via latest.txt).

.NOTES
  THE VERDICT IS THE `OVERALL:` LINE — worst status across bumblebee and all
  active lenses. Exit 0 when OVERALL clean, 1 otherwise. This is the source of
  truth the routine must trust (never the bumblebee manifest alone).
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$honeyRoot = Get-HoneyRoot
if (-not $RunDir) { $RunDir = Get-HoneyLatest -HoneyRoot $honeyRoot }
if (-not $RunDir -or -not (Test-Path (Join-Path $RunDir 'manifest.json'))) {
    Write-Error "report: no manifest at $RunDir"
    exit 1
}
$manifest = Get-Content -LiteralPath (Join-Path $RunDir 'manifest.json') -Raw | ConvertFrom-Json

function Get-Prop { param($Obj,$Name,$Default='') if ($Obj.PSObject.Properties.Name -contains $Name -and $null -ne $Obj.$Name) { $Obj.$Name } else { $Default } }

$bbStatus = Get-Prop $manifest 'status' 'unknown'
$bbTotal  = Get-Prop $manifest 'findings_total' 0
$honHost  = Get-Prop $manifest 'host' '?'
$scanRoot = Get-Prop $manifest 'scan_root' '?'
$ver      = Get-Prop $manifest 'scanner_version' '?'
$when     = Get-Prop $manifest 'finished_at' '?'
# ConvertFrom-Json coerces ISO-8601 strings to [datetime] (rendered in local
# US locale). Re-render as the ISO/UTC string to match bash's output exactly.
if ($when -is [datetime]) { $when = $when.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
$catDir   = Get-Prop $manifest 'catalog_dir' '?'
$files = '?'
$sumPath = Join-Path $RunDir 'summary.json'
if (Test-Path $sumPath) {
    try { $files = Get-Prop ((Get-Content -LiteralPath $sumPath -Raw | ConvertFrom-Json)) 'files_considered' '?' } catch { $files = '?' }
}

$L = New-Object System.Collections.ArrayList
function Emit { param($s) [void]$L.Add($s) }

Emit "honey scan report  ($when)"
Emit "host: $honHost   scanned: $scanRoot   files: $files   scanner: $ver"
Emit ""

$overall = $bbStatus

# --- bumblebee section (canonical scanner) ----------------------------------
switch ($bbStatus) {
    'clean' { Emit "[OK] bumblebee: CLEAN - no exposure matches against the catalogs in $catDir." }
    'incomplete' {
        Emit "[!] bumblebee: INCOMPLETE - hit the time limit; coverage is PARTIAL."
        Emit "Absence of matches is NOT all-clear. Re-run with a larger BUMBLEBEE_MAX_DURATION or narrower root."
    }
    'scan_error' {
        Emit "[X] bumblebee: SCAN ERROR (scan_exit_code=$(Get-Prop $manifest 'scan_exit_code' '?'))."
        $diag = Join-Path $RunDir 'diagnostics.ndjson'
        if (Test-Path $diag) { Get-Content -LiteralPath $diag -Tail 5 | ForEach-Object { Emit "  $_" } }
    }
    'exposed' {
        $bySev = Get-Prop $manifest 'findings_by_severity' ([pscustomobject]@{})
        $sevStr = ($bySev.PSObject.Properties | ForEach-Object { "$($_.Value) $($_.Name)" }) -join ', '
        Emit "[!!] bumblebee: EXPOSED - $bbTotal match(es): $sevStr"
        $fp = Join-Path $RunDir 'findings.ndjson'
        if (Test-Path $fp) {
            Get-Content -LiteralPath $fp | Where-Object { $_.Trim() } | ForEach-Object {
                $f = $_ | ConvertFrom-Json
                Emit ("  - {0} {1}@{2} ({3})" -f (Get-Prop $f 'severity' '?').ToUpper(), (Get-Prop $f 'package_name' '?'), (Get-Prop $f 'version' '?'), (Get-Prop $f 'ecosystem' '?'))
                Emit ("      campaign : {0}" -f (Get-Prop $f 'catalog_name' '?'))
                Emit ("      where    : {0}" -f (Get-Prop $f 'source_file' '?'))
            }
        }
    }
}

# --- lens sections ----------------------------------------------------------
Get-ChildItem -Path $RunDir -Filter 'lens-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
    $lj = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    $name = Get-Prop $lj 'lens' $_.BaseName
    $st   = Get-Prop $lj 'status' 'unknown'
    $tot  = Get-Prop $lj 'findings_total' 0
    $note = Get-Prop $lj 'note' ''
    $overall = Resolve-WorseStatus $overall $st
    Emit ""
    switch ($st) {
        'skipped'    { Emit "-- lens ${name}: skipped ($note)" }
        'clean'      { Emit "[OK] lens ${name}: clean ($note)" }
        'incomplete' { Emit "[!] lens ${name}: incomplete ($note)" }
        'scan_error' { Emit "[X] lens ${name}: scan error ($note)" }
        'exposed'    {
            $bySev = Get-Prop $lj 'findings_by_severity' ([pscustomobject]@{})
            $sevStr = ($bySev.PSObject.Properties | ForEach-Object { "$($_.Value) $($_.Name)" }) -join ', '
            Emit "[!!] lens ${name}: $tot finding(s) [$sevStr]  ($note)"
            $rank = @{ critical=0; high=1; medium=2; low=3; unknown=4 }
            @(Get-Prop $lj 'findings' @()) |
                Sort-Object @{ Expression = { $r = $rank[[string](Get-Prop $_ 'severity' 'unknown')]; if ($null -eq $r) { 9 } else { $r } } } |
                ForEach-Object {
                    Emit ("  - {0}  {1}" -f (Get-Prop $_ 'severity' '?').ToUpper(), (Get-Prop $_ 'title' '?'))
                    $loc = Get-Prop $_ 'location' ''
                    if ($loc) { Emit "      where : $loc" }
                    $det = Get-Prop $_ 'detail' ''
                    if ($det) { Emit "      detail: $det" }
                }
        }
    }
}

# --- overall verdict --------------------------------------------------------
Emit ""
if ($overall -eq 'clean') {
    Emit "OVERALL: CLEAN across bumblebee and all active lenses."
    $L | ForEach-Object { Write-Output $_ }
    exit 0
}
Emit ("OVERALL: {0} - address critical/high items first." -f $overall.ToUpper())
Emit "Verify each fix manually; honey only reports, it never changes your system. Raw records under: $RunDir"
$L | ForEach-Object { Write-Output $_ }
exit 1
