<#
.SYNOPSIS
  honey lens (Windows): govulncheck — Go vulnerabilities your code actually
  CALLS (reachability-aware). PowerShell port of lenses/govulncheck.sh.

.PARAMETER RunDir
  The run directory to write lens-govulncheck.json into.

.NOTES
  Self-skips if govulncheck (or go) isn't installed. Counts ONLY reachable
  `finding` messages (joined to their `osv` summary); the many `osv` messages
  are advisories-in-graph, not actionable, and are NOT counted. govulncheck
  -format json streams pretty-printed objects and exits 0 even with vulns, so
  we judge by parseable output, not exit code. HONEY_UPDATE_LENSES=0 skips the
  @latest self-update. Project roots via HONEY_PROJECT_ROOTS.
#>
param([Parameter(Mandatory)][string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$lens = 'govulncheck'

if (-not (Get-Command govulncheck -ErrorAction SilentlyContinue)) {
    Write-LensResult -RunDir $RunDir -Lens $lens -Status 'skipped' `
        -Note 'govulncheck not installed — lens skipped. See README (vuln lenses).' | Out-Null
    Write-HoneyConsole "lens govulncheck: not installed, skipped"
    return
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-LensResult -RunDir $RunDir -Lens $lens -Status 'skipped' `
        -Note 'go not installed — govulncheck needs it; skipped.' | Out-Null
    Write-HoneyConsole "lens govulncheck: go missing, skipped"
    return
}

if ((Get-HoneySetting 'HONEY_UPDATE_LENSES' '1') -eq '1') {
    try {
        & go install golang.org/x/vuln/cmd/govulncheck@latest 2>$null
        Write-HoneyConsole "lens govulncheck: updated to @latest"
    } catch { Write-HoneyConsole "lens govulncheck: update skipped/failed — using existing binary" }
}

$gvVersion = (& govulncheck -version 2>$null | Select-Object -First 1)
if (-not $gvVersion) { $gvVersion = 'unknown' }

$home_ = Get-HoneyHome
$defaultRoots = @(
    (Join-Path $home_ 'source\repos'), (Join-Path $home_ 'git'), (Join-Path $home_ 'code')
) -join ';'
$projectRoots = Get-HoneySetting 'HONEY_PROJECT_ROOTS' $defaultRoots
$roots = @($projectRoots -split ';' | Where-Object { $_ -and (Test-Path $_) })

# Discover Go modules (dirs with go.mod). Exclude copies that duplicate the real
# module: vendor/, the Go module cache (go/pkg/mod - read-only downloads), and
# git worktrees/scratch copies (.claude/worktrees). HONEY_GOVULN_EXCLUDE_PATHS
# overrides the regex (matches both / and \); set empty to scan everything.
$gvExclude = Get-HoneySettingRaw 'HONEY_GOVULN_EXCLUDE_PATHS' '[\\/](vendor|node_modules|\.claude[\\/]worktrees)[\\/]|[\\/](go|\.go)[\\/]pkg[\\/]mod[\\/]'
$modules = @()
foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -File -Filter 'go.mod' -ErrorAction SilentlyContinue |
        Where-Object { -not $gvExclude -or $_.FullName -notmatch $gvExclude } |
        ForEach-Object { $modules += $_.DirectoryName }
}
$modules = @($modules | Select-Object -Unique)

if ($modules.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $gvVersion -Status 'clean' `
        -Note "no Go modules found under: $projectRoots" | Out-Null
    Write-HoneyConsole "lens govulncheck: no Go modules"
    return
}

$work = Join-Path $RunDir '.govulncheck'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$errLog = Join-Path $work 'errors.log'

$all = @()
$scanned = 0; $errors = 0
foreach ($mod in $modules) {
    $scanned++
    $raw = Join-Path $work (($mod -replace '[\\/ :]', '_') + '.json')
    Push-Location $mod
    try { & govulncheck -format json ./... > $raw 2>> $errLog }
    catch { Write-Verbose "govulncheck threw for $mod (judged by output below)" }
    finally { Pop-Location }

    # govulncheck emits a STREAM of concatenated pretty-printed JSON objects
    # (not an array, not NDJSON) — parse via the stream helper (bash used jq -s).
    $msgs = ConvertFrom-JsonStream -Path $raw
    if ($null -eq $msgs) { $errors++; continue }
    $msgs = @($msgs)

    # Build osv-id → summary map from the `osv` messages.
    $sum = @{}
    foreach ($m in $msgs) {
        if ($m.PSObject.Properties.Name -contains 'osv' -and $m.osv) {
            $sum[$m.osv.id] = if ($m.osv.summary) { $m.osv.summary } else { $m.osv.id }
        }
    }
    # Emit one finding per reachable `finding` (non-empty trace), deduped by osv id.
    $seen = @{}
    foreach ($m in $msgs) {
        if (-not ($m.PSObject.Properties.Name -contains 'finding') -or -not $m.finding) { continue }
        $f = $m.finding
        if (-not $f.osv) { continue }
        $trace = @($f.trace)
        if ($trace.Count -eq 0) { continue }
        if ($seen.ContainsKey($f.osv)) { continue }
        $seen[$f.osv] = $true
        $top = $trace[0]
        $modName = if ($top.module) { $top.module } else { '?' }
        $fn = if ($top.PSObject.Properties.Name -contains 'function' -and $top.function) { " via $($top.function)" } else { '' }
        $fixed = if ($f.PSObject.Properties.Name -contains 'fixed_version' -and $f.fixed_version) { "; fixed in $($f.fixed_version)" } else { '; no fix available' }
        $loc = $mod
        if ($top.PSObject.Properties.Name -contains 'package' -and $top.package) { $loc = "$mod ($($top.package))" }
        $all += [pscustomobject]@{
            severity = 'high'   # reachable by definition → treat as high (no CVSS in govulncheck JSON)
            title    = "$($f.osv): " + $(if ($sum.ContainsKey($f.osv)) { $sum[$f.osv] } else { 'vulnerability' })
            location = $loc
            detail   = "reachable in $modName$fn$fixed"
            ref      = $f.osv
        }
    }
}
$all = @($all)

# Dedupe the SAME OSV id across modules into one finding (note module span),
# mirroring the osv-scanner lens. HONEY_GOVULN_NO_DEDUPE=1 keeps one per module.
if ((Get-HoneySetting 'HONEY_GOVULN_NO_DEDUPE' '0') -ne '1' -and $all.Count -gt 0) {
    $deduped = @()
    foreach ($grp in ($all | Group-Object ref)) {
        $f = $grp.Group[0]
        if ($grp.Count -gt 1) { $f.location = "$($f.location)  (+$($grp.Count - 1) more module(s))" }
        $deduped += $f
    }
    $all = @($deduped)
}

$note = "scanned $scanned Go module(s) under $projectRoots; reachable vulns only"
if ($gvExclude) { $note += "; vendor/worktree/module-cache excluded" }
if ((Get-HoneySetting 'HONEY_GOVULN_NO_DEDUPE' '0') -ne '1') { $note += "; deduped across modules" }
if ($errors -gt 0) { $note += "; $errors module error(s) — see $errLog" }

if ($errors -gt 0 -and $all.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $gvVersion -Status 'scan_error' -Note $note | Out-Null
} elseif ($all.Count -gt 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $gvVersion -Status 'exposed' -Findings $all -Note $note | Out-Null
} else {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $gvVersion -Status 'clean' -Note $note | Out-Null
}
Write-HoneyConsole "lens govulncheck: $($all.Count) reachable finding(s) across $scanned module(s)"
