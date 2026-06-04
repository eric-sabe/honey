<#
.SYNOPSIS
  Shared helpers for honey's native Windows (PowerShell 7) variant.

  Mirrors the bash core's semantics exactly so the two implementations stay
  behavior-compatible:
    - the lens contract (lens-<name>.json normalized shape),
    - worst-wins overall status ranking,
    - the freshness guard,
    - run-dir layout, with `latest.txt` standing in for the Unix `latest` symlink
      (a pointer file needs no admin/developer-mode, unlike Windows symlinks).

  Config precedence matches the bash side: explicit env var > honey.conf.ps1 >
  built-in default. honey.conf.ps1 (if present at the repo root) is dot-sourced.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Paths -------------------------------------------------------------------

# Repo root = parent of win/ (this file is win/lib/Honey.psm1 → ../../).
function Get-HoneyRoot {
    if ($env:HONEY) { return $env:HONEY }
    return (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
}

# The user's home directory. On Windows this is %USERPROFILE%; falls back to
# $HOME so the scripts are testable on macOS/Linux pwsh too.
function Get-HoneyHome {
    if ($env:USERPROFILE) { return $env:USERPROFILE }
    if ($env:HOME) { return $env:HOME }
    return (Resolve-Path '~').Path
}

# Dot-source optional machine-specific config (honey.conf.ps1) so non-default
# settings persist across shells and bare-environment scheduled tasks.
function Import-HoneyConfig {
    $conf = Join-Path (Get-HoneyRoot) 'honey.conf.ps1'
    if (Test-Path $conf) { . $conf }
}

# Resolve a setting: explicit value (env) wins, else default. PowerShell has no
# `${VAR:-default}`, so this is the standard helper for it.
function Get-HoneySetting {
    param([string]$Name, [string]$Default)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ($null -ne $v -and $v -ne '') { return $v }
    return $Default
}

# Like Get-HoneySetting but only an UNSET var falls back to the default — an
# explicit empty value is preserved. Mirrors bash `${VAR-default}`. Use for the
# "set empty to disable" knobs (e.g. HONEY_*_EXCLUDE_PATHS).
function Get-HoneySettingRaw {
    param([string]$Name, [string]$Default)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ($null -ne $v) { return $v }
    return $Default
}

# --- Status ranking (worst-wins), identical to bash overall_rank ------------

function Get-StatusRank {
    param([string]$Status)
    switch ($Status) {
        'scan_error' { 4 }
        'exposed'    { 3 }
        'incomplete' { 2 }
        'clean'      { 1 }
        'skipped'    { 1 }
        default      { 0 }
    }
}

# Worst of two statuses (the one with the higher rank).
function Resolve-WorseStatus {
    param([string]$A, [string]$B)
    if ((Get-StatusRank $B) -gt (Get-StatusRank $A)) { return $B } else { return $A }
}

# --- Lens contract -----------------------------------------------------------

# Write a lens-<name>.json in honey's normalized shape. Findings is an array of
# objects with: severity,title,location,detail,ref.
function Write-LensResult {
    param(
        [string]$RunDir,
        [string]$Lens,
        [string]$ToolVersion = 'unknown',
        [string]$Status,                       # clean|exposed|incomplete|scan_error|skipped
        [object[]]$Findings = @(),
        [string]$Note = ''
    )
    $total = @($Findings).Count
    $bySev = @{}
    foreach ($f in $Findings) {
        $s = if ($f.severity) { $f.severity } else { 'unknown' }
        if ($bySev.ContainsKey($s)) { $bySev[$s]++ } else { $bySev[$s] = 1 }
    }
    $obj = [ordered]@{
        lens                 = $Lens
        tool_version         = $ToolVersion
        status               = $Status
        findings_total       = $total
        findings_by_severity = $bySev
        findings             = @($Findings)
        note                 = $Note
    }
    $out = Join-Path $RunDir ("lens-{0}.json" -f $Lens)
    # -Depth high enough for nested finding objects; -Compress off for readability.
    ($obj | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $out -Encoding utf8
    return $out
}

# Map a numeric CVSS (0-10) to honey's severity buckets — same thresholds as the
# osv-scanner lens (>=9 critical, >=7 high, >=4 medium, else low; null=unknown).
function Get-SeverityFromCvss {
    param($Cvss)   # number or $null
    if ($null -eq $Cvss) { return 'unknown' }
    if ($Cvss -ge 9) { return 'critical' }
    if ($Cvss -ge 7) { return 'high' }
    if ($Cvss -ge 4) { return 'medium' }
    return 'low'
}

# --- latest.txt pointer (symlink stand-in) ----------------------------------

function Set-HoneyLatest {
    param([string]$HoneyRoot, [string]$RunDir)
    Set-Content -LiteralPath (Join-Path $HoneyRoot 'latest.txt') -Value $RunDir -Encoding utf8
}

function Get-HoneyLatest {
    param([string]$HoneyRoot)
    $p = Join-Path $HoneyRoot 'latest.txt'
    if (-not (Test-Path $p)) { return $null }
    $rd = (Get-Content -LiteralPath $p -Raw).Trim()
    if ($rd -and (Test-Path $rd)) { return $rd }
    return $null
}

# --- Logging -----------------------------------------------------------------

# Informational console output. Uses Write-Information (capturable/redirectable,
# unlike Write-Host) with the stream forced visible — honey's progress lines are
# informational, so this is the correct idiom and keeps PSScriptAnalyzer happy.
function Write-HoneyConsole {
    param([string]$Message)
    Write-Information $Message -InformationAction Continue
}

function Write-HoneyLog {
    param([string]$HoneyRoot, [string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "[$ts] $Message"
    Add-Content -LiteralPath (Join-Path $HoneyRoot 'cycle.log') -Value $line
    Write-HoneyConsole $line
}

# A sortable UTC run-id / timestamp, matching the bash `date -u +%Y%m%dT%H%M%SZ`.
function Get-HoneyTimestamp {
    return (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
}

# Parse a STREAM of concatenated JSON objects (e.g. govulncheck -format json,
# which emits {...}{...} pretty-printed, NOT an array and NOT NDJSON).
# ConvertFrom-Json rejects that ("Additional text encountered"), and `jq -s` is
# the bash equivalent we're replacing. Splits on a top-level '}'→'{' line
# boundary and parses each object. Returns $null if NOTHING parses (caller
# treats that as a scan error), else the array of parsed objects.
function ConvertFrom-JsonStream {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not $raw) { return $null }
    $chunks = [System.Text.RegularExpressions.Regex]::Split($raw, '(?<=\n})\n(?={)')
    $objs = @()
    foreach ($c in $chunks) {
        if (-not $c.Trim()) { continue }
        # A malformed chunk is deliberately skipped — a partial/truncated object
        # shouldn't discard the valid ones (mirrors the bash `fromjson?` tolerance).
        try { $objs += ($c | ConvertFrom-Json) } catch { Write-Verbose "skipped unparseable JSON chunk" }
    }
    if ($objs.Count -eq 0) { return $null }
    return $objs
}

Export-ModuleMember -Function Get-HoneyRoot, Get-HoneyHome, Import-HoneyConfig, Get-HoneySetting, Get-HoneySettingRaw,
    Get-StatusRank, Resolve-WorseStatus, Write-LensResult, Get-SeverityFromCvss,
    Set-HoneyLatest, Get-HoneyLatest, Write-HoneyConsole, Write-HoneyLog, Get-HoneyTimestamp,
    ConvertFrom-JsonStream
