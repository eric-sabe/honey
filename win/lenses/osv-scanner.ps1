<#
.SYNOPSIS
  honey lens (Windows): osv-scanner — known vulns in project lockfiles/manifests
  across all ecosystems (npm, NuGet, PyPI, cargo, Go, …) via Google/OSV
  osv-scanner. PowerShell port of lenses/osv-scanner.sh — same normalized output,
  same vendored-path exclusion + dedup, same CVSS bucketing and stdlib deferral.

.PARAMETER RunDir
  The run directory to write lens-osv-scanner.json into.

.NOTES
  Self-skips (status "skipped", exit 0) if osv-scanner isn't installed.
  Config (env var > honey.conf.ps1 > default), mirroring the bash lens:
    HONEY_PROJECT_ROOTS         ; default ~\source\repos;~\git;~\code
    HONEY_OSV_OFFLINE=1         ; use local DBs
    HONEY_OSV_INCLUDE_GO_STDLIB ; keep Go stdlib advisories
    HONEY_OSV_EXCLUDE_PATHS     ; ERE of paths to drop (vendored/installed copies)
    HONEY_OSV_NO_DEDUPE=1       ; keep one finding per path
    HONEY_UPDATE_LENSES=0       ; skip go install @latest before scanning
#>
param([Parameter(Mandatory)][string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$lens = 'osv-scanner'

if (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue)) {
    Write-LensResult -RunDir $RunDir -Lens $lens -Status 'skipped' `
        -Note 'osv-scanner not installed — lens skipped. See README (vuln lenses).' | Out-Null
    Write-HoneyConsole "lens osv-scanner: not installed, skipped"
    return
}

# Optional self-update (default on), non-fatal — mirrors the bash lens.
if ((Get-HoneySetting 'HONEY_UPDATE_LENSES' '1') -eq '1' -and (Get-Command go -ErrorAction SilentlyContinue)) {
    try {
        & go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>$null
        Write-HoneyConsole "lens osv-scanner: updated to @latest"
    } catch { Write-HoneyConsole "lens osv-scanner: update skipped/failed — using existing binary" }
}

$osvVersion = (& osv-scanner --version 2>$null | Select-Object -First 1)
if (-not $osvVersion) { $osvVersion = 'unknown' }

# Project roots: default to the common Windows dev locations.
$home_ = Get-HoneyHome
$defaultRoots = @(
    (Join-Path $home_ 'source\repos'),
    (Join-Path $home_ 'git'),
    (Join-Path $home_ 'code')
) -join ';'
$projectRoots = Get-HoneySetting 'HONEY_PROJECT_ROOTS' $defaultRoots
$roots = @($projectRoots -split ';' | Where-Object { $_ -and (Test-Path $_) })

if ($roots.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $osvVersion -Status 'clean' `
        -Note "no project roots found among: $projectRoots" | Out-Null
    Write-HoneyConsole "lens osv-scanner: no project roots"
    return
}

$work = Join-Path $RunDir '.osv-scanner'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$raw = Join-Path $work 'osv.json'
$errLog = Join-Path $work 'errors.log'

$offline = @()
if ((Get-HoneySetting 'HONEY_OSV_OFFLINE' '0') -eq '1') {
    $offline = @('--offline-vulnerabilities', '--download-offline-databases')
}

# osv-scanner exits non-zero when it finds vulns OR on usage error; judge by
# whether it produced parseable JSON (mirrors the bash lens).
$rootArgs = @(); foreach ($r in $roots) { $rootArgs += @('-r', $r) }
& osv-scanner scan --format json @offline @rootArgs > $raw 2> $errLog

$data = $null
try { $data = Get-Content -LiteralPath $raw -Raw | ConvertFrom-Json } catch { $data = $null }

if ($null -eq $data) {
    # "No package sources found" = roots have no lockfiles to scan → CLEAN, not error.
    $errText = if (Test-Path $errLog) { Get-Content -LiteralPath $errLog -Raw } else { '' }
    if ($errText -match '(?i)no package sources found') {
        Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $osvVersion -Status 'clean' `
            -Note ("no lockfiles/manifests found under: {0}" -f ($roots -join ', ')) | Out-Null
        Write-HoneyConsole "lens osv-scanner: clean (no package sources)"
        return
    }
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $osvVersion -Status 'scan_error' `
        -Note "osv-scanner produced no valid JSON — see $errLog" | Out-Null
    Write-HoneyConsole "lens osv-scanner: scan_error (no JSON)"
    return
}

$keepStdlib  = (Get-HoneySetting 'HONEY_OSV_INCLUDE_GO_STDLIB' '0') -eq '1'
$dedupe      = (Get-HoneySetting 'HONEY_OSV_NO_DEDUPE' '0') -ne '1'
# Default exclude regex: vendored/installed copies + per-worktree node_modules.
# Matches both / and \ separators (Windows paths). Set empty to scan everything.
$excludeRe = Get-HoneySettingRaw 'HONEY_OSV_EXCLUDE_PATHS' '[\\/](node_modules|vendor|bower_components|\.pnpm|testdata|fixtures|\.claude[\\/]worktrees)[\\/]'

# Flatten results → one finding per (package, vuln group).
$raw_findings = New-Object System.Collections.ArrayList
foreach ($result in @($data.results)) {
    $src = if ($result.source.path) { $result.source.path } else { '' }
    if ($excludeRe -ne '' -and $src -match $excludeRe) { continue }
    foreach ($pkg in @($result.packages)) {
        $name = if ($pkg.package.name) { $pkg.package.name } else { '?' }
        $ver  = if ($pkg.package.version) { $pkg.package.version } else { '?' }
        $eco  = if ($pkg.package.ecosystem) { $pkg.package.ecosystem } else { '?' }
        if (-not $keepStdlib -and $name -eq 'stdlib') { continue }
        foreach ($g in @($pkg.groups)) {
            $cvss = $null
            if ($g.PSObject.Properties.Name -contains 'max_severity' -and $g.max_severity -ne '') {
                $parsed = 0.0
                if ([double]::TryParse([string]$g.max_severity, [ref]$parsed)) { $cvss = $parsed }
            }
            $ids = @($g.ids)
            [void]$raw_findings.Add([pscustomobject]@{
                severity = Get-SeverityFromCvss $cvss
                title    = "$name@$ver ($eco): " + ($ids -join ', ')
                location = $src
                detail   = ("CVSS {0}; advisories: {1}" -f ($(if($null -ne $cvss){$cvss}else{'null'})), ($ids -join ', '))
                ref      = if ($ids.Count -gt 0) { $ids[0] } else { '' }
                _key     = "$name@$ver|" + ($ids -join ',')
                _cvss    = if ($null -ne $cvss) { $cvss } else { -1 }
            })
        }
    }
}

# Dedupe identical (package@version + advisory) across paths: keep worst-severity
# instance, annotate how many extra paths it spanned.
$findings = @()
if ($dedupe) {
    foreach ($grp in ($raw_findings | Group-Object _key)) {
        $worst = $grp.Group | Sort-Object _cvss -Descending | Select-Object -First 1
        $extra = $grp.Count - 1
        $loc = $worst.location
        if ($extra -gt 0) { $loc = "$loc  (+$extra more path(s))" }
        $findings += [pscustomobject]@{
            severity = $worst.severity; title = $worst.title; location = $loc
            detail = $worst.detail; ref = $worst.ref
        }
    }
} else {
    $findings = $raw_findings | ForEach-Object {
        [pscustomobject]@{ severity=$_.severity; title=$_.title; location=$_.location; detail=$_.detail; ref=$_.ref }
    }
}
$findings = @($findings)

$note = "scanned $($roots.Count) project root(s): " + ($roots -join ', ')
if ($offline.Count -gt 0) { $note += '; offline DB' }
if (-not $keepStdlib)     { $note += '; Go stdlib advisories deferred to govulncheck' }
if ($excludeRe -ne '')    { $note += '; vendored/worktree paths excluded' }
if ($dedupe)              { $note += '; deduped across paths' }

$status = if ($findings.Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $osvVersion -Status $status `
    -Findings $findings -Note $note | Out-Null
Write-HoneyConsole "lens osv-scanner: $($findings.Count) finding(s) across $($roots.Count) root(s)"
