<#
.SYNOPSIS
  honey (Windows): manage the pin-and-diff suppression baseline. PowerShell port
  of honey-baseline.sh.

.DESCRIPTION
  A baseline entry acknowledges a reviewed finding by (scanner, rule, location,
  occurrence index) AND a sha256 of the referenced content. A matching finding
  whose content still hashes the same is SUPPRESSED (dropped from the verdict,
  still shown). If the content changes, the finding resurfaces as MUTATED.
  See docs/BASELINE.plan.md.

  Commands:
    status [RunDir]                     dry-run tally (suppressed/mutated/expired/active)
    add    [RunDir] <filter> -Reason S [-Expires DAYS|never] [-AddedBy NAME]
    list   [-Expired | -Active]         show entries (flags expired)
    remove <filter>                     drop matching entries
    prune                               remove expired entries

  <filter> (combinable, AND): -All (excludes bumblebee) | -Scanner NAME |
    -Severity SEV | -Rule TEXT | -Location SUBSTR

  This tool NEVER changes system state; it only edits honey.baseline.json,
  which you review and commit.

.EXAMPLE
  pwsh -File win\honey-baseline.ps1 add -Scanner skillspector -Location references\ -Reason "first-party docs" -Expires 90
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('status','add','list','remove','prune','help')][string]$Command = 'help',
    [Parameter(Position = 1)][string]$RunDir,
    [switch]$All,
    [string]$Scanner,
    [string]$Severity,
    [string]$Rule,
    [string]$Location,
    [string]$Reason,
    [string]$Expires = '90',
    [string]$AddedBy = $env:USERNAME,
    [switch]$Expired,
    [switch]$Active
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib' 'Baseline.psm1') -Force
Import-HoneyConfig

function Say { param($m) Write-Information $m -InformationAction Continue }
function Die { param($m) Write-Error "honey-baseline: $m"; exit 2 }

$baselineFile = Get-HoneyBaselineFile

function Resolve-HoneyRun {
    param([string]$Dir)
    if ($Dir -and (Test-Path (Join-Path $Dir 'manifest.json'))) { return $Dir }
    $rd = Get-HoneyLatest -HoneyRoot (Get-HoneyRoot)
    if (-not $rd) { Die "no run dir (pass one, or run a scan so latest.txt exists)" }
    return $rd
}

function Initialize-HoneyBaseline {
    if (-not (Test-Path -LiteralPath $baselineFile)) {
        '{"version":1,"entries":[]}' | Set-Content -LiteralPath $baselineFile -Encoding utf8
    }
}

function Save-HoneyBaseline {
    param($Entries)
    $doc = [ordered]@{ version = 1; entries = @($Entries) }
    ($doc | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $baselineFile -Encoding utf8
}

function Get-HoneyEntryKey {
    param($e)
    # New entries are hashtables; existing (from JSON) are PSCustomObjects. Read
    # `index` uniformly from both so identity keys match across a re-add.
    $ix = 0
    if ($e -is [System.Collections.IDictionary]) {
        if ($e.Contains('index') -and $null -ne $e['index']) { $ix = $e['index'] }
    } elseif ($e.PSObject.Properties.Name -contains 'index' -and $null -ne $e.index) {
        $ix = $e.index
    }
    "$($e.scanner)$($e.rule)$($e.location)$ix"
}

# Any selector given? (guards against an accidental match-all.) Referencing the
# filter switches/strings here also marks them "used" for the analyzer.
$hasFilter = ($All -or $Scanner -or $Severity -or $Rule -or $Location)

switch ($Command) {

'status' {
    $run = Resolve-HoneyRun -Dir $RunDir
    $entries = @(Get-HoneyBaselineEntry)
    Say "baseline status  (run: $run)"
    Say "baseline: $baselineFile  ($($entries.Count) entr$(if ($entries.Count -eq 1) {'y'} else {'ies'}))"
    # NB: not $all — it would alias the [switch]$All parameter (case-insensitive).
    $classified = @(Get-HoneyClassifiedRun -RunDir $run)
    $s = @($classified | Where-Object { $_._class -eq 'suppressed' }).Count
    $m = @($classified | Where-Object { $_._class -eq 'mutated' }).Count
    $e = @($classified | Where-Object { $_._class -eq 'expired' }).Count
    $a = @($classified | Where-Object { $_._class -eq 'active' }).Count
    Say "  active:     $a   (contribute to the verdict)"
    Say "  suppressed: $s   (pinned & unchanged - hidden from the verdict)"
    Say "  mutated:    $m   (pinned content CHANGED - resurfaced, review now)"
    Say "  expired:    $e   (pin past its expiry - resurfaced)"
    if ($m -gt 0) { Say "[!!] $m mutated finding(s): a reviewed file changed since it was pinned." }
}

'list' {
    $entries = @(Get-HoneyBaselineEntry)
    $today = Get-HoneyToday
    if ($Expired) { $entries = @($entries | Where-Object { $_.expires -ne 'never' -and [string]$_.expires -lt $today }) }
    elseif ($Active) { $entries = @($entries | Where-Object { $_.expires -eq 'never' -or [string]$_.expires -ge $today }) }
    foreach ($e in $entries) {
        $flag = if ($e.expires -ne 'never' -and [string]$e.expires -lt $today) { 'EXPIRED ' } else { '        ' }
        Say "$flag[$($e.scanner)] $($e.rule)"
        Say "           $($e.location)  (index $(Get-HoneyEntryIndex $e))"
        Say "           reason: $($e.reason)   added: $($e.added)   expires: $($e.expires)"
    }
    $n = @(Get-HoneyBaselineEntry).Count
    Say "$n entr$(if ($n -eq 1) {'y'} else {'ies'}) in $baselineFile"
}

'prune' {
    Initialize-HoneyBaseline
    $today = Get-HoneyToday
    $before = @(Get-HoneyBaselineEntry)
    $kept = @($before | Where-Object { $_.expires -eq 'never' -or [string]$_.expires -ge $today })
    Save-HoneyBaseline $kept
    Say "pruned $($before.Count - $kept.Count) expired entr$(if (($before.Count - $kept.Count) -eq 1) {'y'} else {'ies'}); $($kept.Count) remain."
}

'add' {
    $run = Resolve-HoneyRun -Dir $RunDir
    if (-not $Reason) { Die "add: -Reason is required (why is this finding benign?)" }
    if (-not $hasFilter) { Die "add: refusing to pin with no selector - pass -All or a -Scanner/-Severity/-Rule/-Location filter" }
    if ($Expires -eq 'never') { $expiresDate = 'never' }
    elseif ($Expires -match '^\d+$') { $expiresDate = (Get-Date).ToUniversalTime().AddDays([int]$Expires).ToString('yyyy-MM-dd') }
    else { Die "add: -Expires must be a number of days or 'never'" }
    $added = Get-HoneyToday
    Initialize-HoneyBaseline

    # Filter classified findings inline (references the filter params in-body).
    # -All excludes bumblebee: pinning a known-compromised match must be explicit.
    $sel = @(Get-HoneyClassifiedRun -RunDir $run | Where-Object {
        (-not ($All -and $_._scanner -eq 'bumblebee')) -and
        (-not $Scanner  -or $_._scanner -eq $Scanner) -and
        (-not $Severity -or [string]$_.severity -eq $Severity) -and
        (-not $Rule     -or ([string]$_.rule).Contains($Rule)) -and
        (-not $Location -or ([string]$_._loc).Contains($Location))
    })
    if ($sel.Count -eq 0) { Say "add: no findings matched that filter in $run"; break }

    $newEntries = foreach ($f in $sel) {
        $loc = [string]$f._loc
        $abs = ConvertFrom-HoneyTilde (Split-HoneyLocationFile $loc)
        if (Test-Path -LiteralPath $abs -PathType Leaf) { $chash = Get-HoneyFileHash $abs; $csrc = 'file' }
        else { $chash = Get-HoneyStringHash (Get-HoneyFindingCanonical $f); $csrc = 'finding' }
        [ordered]@{
            scanner = [string]$f._scanner; rule = [string]$f.rule; location = $loc; index = [int]$f._index
            content_hash = $chash; content_source = $csrc
            severity = $(if ($f.PSObject.Properties.Name -contains 'severity' -and $f.severity) { [string]$f.severity } else { 'unknown' })
            reason = $Reason; added = $added; expires = $expiresDate; added_by = $AddedBy
        }
    }
    $newEntries = @($newEntries)

    # Merge: new entries replace any existing pin with the same identity key.
    $newKeys = @($newEntries | ForEach-Object { Get-HoneyEntryKey $_ })
    $kept = @(Get-HoneyBaselineEntry | Where-Object { $newKeys -notcontains (Get-HoneyEntryKey $_) })
    Save-HoneyBaseline (@($kept) + @($newEntries))

    $bcount = @($newEntries | Where-Object { $_.scanner -eq 'bumblebee' }).Count
    Say "pinned $($sel.Count) finding(s) into $baselineFile (expires: $expiresDate)."
    if ($bcount -gt 0) { Say "[!!] $bcount of these are bumblebee (known-compromised) matches - make sure that is intended." }
    Say "Review the diff and commit honey.baseline.json."
}

'remove' {
    Initialize-HoneyBaseline
    if (-not $hasFilter) { Die "remove: pass a selector (-All/-Scanner/-Severity/-Rule/-Location)" }
    $before = @(Get-HoneyBaselineEntry)
    $kept = @($before | Where-Object {
        -not (
            (-not ($All -and $_.scanner -eq 'bumblebee')) -and
            (-not $Scanner  -or $_.scanner -eq $Scanner) -and
            (-not $Severity -or [string]$_.severity -eq $Severity) -and
            (-not $Rule     -or ([string]$_.rule).Contains($Rule)) -and
            (-not $Location -or ([string]$_.location).Contains($Location))
        )
    })
    Save-HoneyBaseline $kept
    Say "removed $($before.Count - $kept.Count) entr$(if (($before.Count - $kept.Count) -eq 1) {'y'} else {'ies'}); $($kept.Count) remain."
}

default {
    Say "honey-baseline.ps1 <status|add|list|remove|prune> [-RunDir DIR] [filters] [-Reason STR] [-Expires DAYS|never]"
    Say "Filters: -All -Scanner NAME -Severity SEV -Rule TEXT -Location SUBSTR   (list also: -Expired | -Active)"
    Say "Pins reviewed-benign findings by content hash; a changed file resurfaces as MUTATED. See docs/BASELINE.plan.md."
}

}
