<#
.SYNOPSIS
  honey (Windows): render a triage report from a scan run — no AI. PowerShell
  port of report.sh. Reads manifest.json (bumblebee) + every lens-*.json and
  prints per-scanner sections plus the authoritative OVERALL verdict line.

.PARAMETER RunDir
  Run directory to report on. Defaults to the latest run (via latest.txt).

.NOTES
  THE VERDICT IS THE `OVERALL:` LINE — worst status across bumblebee and all
  active lenses, AFTER the pin-and-diff suppression baseline is applied. Pinned,
  content-unchanged findings are suppressed (dropped from the verdict, still
  counted); a pinned file whose content CHANGED resurfaces as MUTATED. Raw run
  records are never modified. Exit 0 when OVERALL clean, 1 otherwise. This is the
  source of truth the routine must trust (never the bumblebee manifest alone).
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib' 'Baseline.psm1') -Force
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

# Suppression + verdict-policy tallies, accumulated across bumblebee + every
# lens. rev = active findings held below the severity floor (review tier).
$script:sup = 0; $script:mut = 0; $script:exp = 0; $script:rev = 0
# A class marker printed before a finding line (mutated/expired resurface loudly).
function Get-ClassMarker { param($c) switch ($c) { 'mutated' { '[MUTATED] ' } 'expired' { '[EXPIRED-PIN] ' } default { '' } } }

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
        $fp = Join-Path $RunDir 'findings.ndjson'
        $recs = @()
        if (Test-Path $fp) { $recs = Get-Content -LiteralPath $fp | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } }
        $cls = Get-HoneyClassifiedBumblebee -Records @($recs)
        $bs = @($cls | Where-Object { $_._class -eq 'suppressed' }).Count
        $active = @($cls | Where-Object { $_._class -ne 'suppressed' })
        $script:sup += $bs
        $script:mut += @($cls | Where-Object { $_._class -eq 'mutated' }).Count
        $script:exp += @($cls | Where-Object { $_._class -eq 'expired' }).Count
        if ($active.Count -eq 0) {
            Emit "[OK] bumblebee: CLEAN - all $bbTotal match(es) suppressed by baseline (review with honey-baseline.ps1)."
        } else {
            $overall = Resolve-WorseStatus $overall 'exposed'
            $bySev = @($active) | Group-Object severity | ForEach-Object { "$($_.Count) $($_.Name)" }
            $supStr = if ($bs -gt 0) { "  (+$bs suppressed)" } else { "" }
            Emit "[!!] bumblebee: EXPOSED - $($active.Count) match(es): $(( $bySev ) -join ', ')$supStr"
            $rank = @{ critical=0; high=1; medium=2; low=3; unknown=4 }
            @($active) | Sort-Object @{ Expression = { $r = $rank[[string](Get-Prop $_ 'severity' 'unknown')]; if ($null -eq $r) { 9 } else { $r } } } | ForEach-Object {
                Emit ("  - {0}{1} {2}@{3} ({4})" -f (Get-ClassMarker $_._class), (Get-Prop $_ 'severity' '?').ToUpper(), (Get-Prop $_ 'package_name' '?'), (Get-Prop $_ 'version' '?'), (Get-Prop $_ 'ecosystem' '?'))
                Emit ("      campaign : {0}" -f (Get-Prop $_ 'catalog_name' '?'))
                Emit ("      where    : {0}" -f (Get-Prop $_ 'source_file' '?'))
                if ($_._class -eq 'mutated') { Emit "      note     : content changed since this was pinned reviewed-benign - re-review before re-pinning." }
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
    Emit ""
    switch ($st) {
        'skipped'    { Emit "-- lens ${name}: skipped ($note)" }
        'clean'      { Emit "[OK] lens ${name}: clean ($note)" }
        'incomplete' { Emit "[!] lens ${name}: incomplete ($note)"; $overall = Resolve-WorseStatus $overall 'incomplete' }
        'scan_error' { Emit "[X] lens ${name}: scan error ($note)"; $overall = Resolve-WorseStatus $overall 'scan_error' }
        'exposed'    {
            $cls = Get-HoneyClassifiedLens -Scanner $name -LensObj $lj
            $s = @($cls | Where-Object { $_._class -eq 'suppressed' }).Count
            $blocking = @($cls | Where-Object { $_._class -ne 'suppressed' -and $_._blocking -eq 'yes' })
            $review   = @($cls | Where-Object { $_._class -ne 'suppressed' -and $_._blocking -eq 'no' })
            $script:sup += $s
            $script:mut += @($cls | Where-Object { $_._class -eq 'mutated' }).Count
            $script:exp += @($cls | Where-Object { $_._class -eq 'expired' }).Count
            $script:rev += $review.Count
            if (($blocking.Count + $review.Count) -eq 0) {
                Emit "[OK] lens ${name}: clean - all $tot finding(s) suppressed by baseline. ($note)"
            } else {
                $extras = ""
                if ($s -gt 0) { $extras += "  (+$s suppressed)" }
                if ($blocking.Count -gt 0 -and $review.Count -gt 0) { $extras += "  (+$($review.Count) review)" }
                if ($blocking.Count -gt 0) {
                    $overall = Resolve-WorseStatus $overall 'exposed'
                    $bySev = @($blocking) | Group-Object severity | ForEach-Object { "$($_.Count) $($_.Name)" }
                    Emit "[!!] lens ${name}: $($blocking.Count) finding(s) [$(( $bySev ) -join ', ')]$extras  ($note)"
                } else {
                    Emit "[~] lens ${name}: $($review.Count) review finding(s) - non-blocking (first-party or below the severity floor)$extras  ($note)"
                }
                $rank = @{ critical=0; high=1; medium=2; low=3; unknown=4 }
                @($cls | Where-Object { $_._class -ne 'suppressed' }) |
                    Sort-Object @{ Expression = { if ($_._blocking -eq 'yes') { 0 } else { 1 } } }, @{ Expression = { $r = $rank[[string](Get-Prop $_ 'severity' 'unknown')]; if ($null -eq $r) { 9 } else { $r } } } |
                    ForEach-Object {
                        $ptag = if ($_._provenance -eq 'first-party') { '  [1st-party]' } else { '' }
                        if ($_._blocking -eq 'no') {
                            Emit ("  o review {0}  {1} [non-blocking]" -f (Get-Prop $_ 'severity' '?').ToUpper(), (Get-Prop $_ 'title' '?'))
                            Emit "      where : $(Get-Prop $_ 'location' '')"
                        } else {
                            Emit ("  - {0}{1}  {2}{3}" -f (Get-ClassMarker $_._class), (Get-Prop $_ 'severity' '?').ToUpper(), (Get-Prop $_ 'title' '?'), $ptag)
                            $loc = Get-Prop $_ 'location' ''
                            if ($loc) { Emit "      where : $loc" }
                            $det = Get-Prop $_ 'detail' ''
                            if ($det) { Emit "      detail: $det" }
                            if ($_._class -eq 'mutated') { Emit "      note  : content changed since this was pinned reviewed-benign - re-review before re-pinning." }
                        }
                    }
            }
        }
    }
}

# --- suppression / policy summary -------------------------------------------
if (($script:sup + $script:mut + $script:exp + $script:rev) -gt 0) {
    Emit ""
    Emit "baseline: $($script:sup) suppressed, $($script:mut) mutated, $($script:exp) expired - honey.baseline.json. Review: honey-baseline.ps1 status"
    if ($script:rev -gt 0) {
        $ft = Get-HoneySetting 'HONEY_VERDICT_FLOOR' 'none'
        $ftt = Get-HoneySetting 'HONEY_VERDICT_FLOOR_TRUSTED' $ft
        Emit "policy: $($script:rev) finding(s) held below the severity floor (review tier, non-blocking). Floor: $ft / trusted $ftt."
    }
    if ($script:mut -gt 0) { Emit "[!!] $($script:mut) MUTATED: a file pinned as reviewed-benign has CHANGED. Treat as a possible rug pull and re-review." }
}

# --- overall verdict --------------------------------------------------------
$suffix = ""
if (($script:sup + $script:mut + $script:exp + $script:rev) -gt 0) {
    $parts = @()
    if ($script:sup -gt 0) { $parts += "$($script:sup) suppressed" }
    if ($script:rev -gt 0) { $parts += "$($script:rev) review" }
    if ($script:mut -gt 0) { $parts += "$($script:mut) mutated" }
    if ($script:exp -gt 0) { $parts += "$($script:exp) expired" }
    $suffix = " (" + ($parts -join ', ') + ")"
}

Emit ""
if ($overall -eq 'clean') {
    Emit "OVERALL: CLEAN$suffix across bumblebee and all active lenses."
    $L | ForEach-Object { Write-Output $_ }
    exit 0
}
Emit ("OVERALL: {0}{1} - address critical/high items first." -f $overall.ToUpper(), $suffix)
Emit "Verify each fix manually; honey only reports, it never changes your system. Raw records under: $RunDir"
$L | ForEach-Object { Write-Output $_ }
exit 1
