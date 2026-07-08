<#
.SYNOPSIS
  honey (Windows): pin-and-diff suppression baseline — PowerShell mirror of
  lib/baseline.sh. Imported by report.ps1, daily-cycle.ps1, honey-baseline.ps1
  so all three agree on one classification.

.NOTES
  Same model as bash: a baseline entry pins a finding by (scanner, rule,
  ~-relative location, occurrence index) AND a sha256 of the referenced file's
  content. A matching finding whose file hash still matches is SUPPRESSED
  (dropped from the verdict, still reported); a pinned file whose content
  CHANGED resurfaces as MUTATED (the rug-pull tripwire); an expired pin
  resurfaces as normal. See docs/BASELINE.plan.md.

  Content hashes are lowercase "sha256:<hex>" to match the bash format. The
  baseline file is per-machine (paths and line-endings differ across OSes), so
  it is not meant to be shared between the bash and Windows variants.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Import Honey WITHOUT -Force: a forced re-import here would evict Honey's
# commands from a caller that already imported it (report.ps1/daily-cycle.ps1).
Import-Module (Join-Path $PSScriptRoot 'Honey.psm1')

# --- config ------------------------------------------------------------------

function Get-HoneyBaselineFile {
    if ($env:HONEY_BASELINE) { return $env:HONEY_BASELINE }
    return (Join-Path (Get-HoneyRoot) 'honey.baseline.json')
}

# Entries array (empty when the file is absent/malformed).
function Get-HoneyBaselineEntry {
    $f = Get-HoneyBaselineFile
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    try {
        $doc = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        if ($doc.PSObject.Properties.Name -contains 'entries' -and $doc.entries) { return @($doc.entries) }
        return @()
    } catch { return @() }
}

# --- path helpers ------------------------------------------------------------

# ABS -> ~-relative (home prefix collapsed to ~). Mirrors the jq tildify.
function ConvertTo-HoneyTilde {
    param([string]$Path)
    $home_ = Get-HoneyHome
    if ($Path -eq $home_) { return '~' }
    if ($Path.StartsWith($home_ + [IO.Path]::DirectorySeparatorChar) -or $Path.StartsWith($home_ + '/')) {
        return '~/' + $Path.Substring($home_.Length + 1)
    }
    return $Path
}

# ~-relative -> ABS.
function ConvertFrom-HoneyTilde {
    param([string]$Path)
    $home_ = Get-HoneyHome
    if ($Path -eq '~') { return $home_ }
    if ($Path.StartsWith('~/') -or $Path.StartsWith('~\')) {
        return Join-Path $home_ $Path.Substring(2)
    }
    return $Path
}

# Drop a trailing :<line> from a "file:line" location, keeping a Windows drive
# colon intact.
function Split-HoneyLocationFile {
    param([string]$Location)
    if ($Location -match '^(.*):(\d+)$') { return $Matches[1] }
    return $Location
}

# --- hashing -----------------------------------------------------------------

# sha256 of a file's raw bytes -> "sha256:<lowerhex>" ('' on failure).
function Get-HoneyFileHash {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try { return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() }
    catch { return '' }
}

# sha256 of a UTF-8 string -> "sha256:<lowerhex>". Used for the finding-JSON
# fallback when a location is not an on-disk file.
function Get-HoneyStringHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return 'sha256:' + (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

# Canonical finding serialization for the finding-JSON fallback: original fields
# only (drop _-prefixed), keys sorted, compact. Deterministic within this port.
function Get-HoneyFindingCanonical {
    param($Finding)
    $o = [ordered]@{}
    $Finding.PSObject.Properties |
        Where-Object { -not $_.Name.StartsWith('_') } |
        Sort-Object Name |
        ForEach-Object { $o[$_.Name] = $_.Value }
    return ($o | ConvertTo-Json -Depth 12 -Compress)
}

function Get-HoneyToday { (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd') }

# --- classification ----------------------------------------------------------

# Classify an array of finding objects (each with .rule and ._rawloc, plus the
# original fields). Returns the findings with _loc/_index/_class/_reason added.
function Get-HoneyClassified {
    param([string]$Scanner, [object[]]$Findings)
    $entries = Get-HoneyBaselineEntry
    $today = Get-HoneyToday
    $seen = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($f in @($Findings)) {
        $rawloc = if ($f.PSObject.Properties.Name -contains '_rawloc') { [string]$f._rawloc } else { '' }
        $loc = ConvertTo-HoneyTilde $rawloc
        $rule = if ($f.PSObject.Properties.Name -contains 'rule') { [string]$f.rule } else { '' }
        $k = "$rule $loc"
        $idx = if ($seen.ContainsKey($k)) { $seen[$k] + 1 } else { 0 }
        $seen[$k] = $idx

        $f | Add-Member -NotePropertyName '_loc' -NotePropertyValue $loc -Force
        $f | Add-Member -NotePropertyName '_index' -NotePropertyValue $idx -Force

        $entry = $entries | Where-Object {
            $_.scanner -eq $Scanner -and $_.rule -eq $rule -and $_.location -eq $loc -and
            (([int](Get-HoneyEntryIndex $_)) -eq $idx)
        } | Select-Object -First 1

        if (-not $entry) {
            $f | Add-Member -NotePropertyName '_class' -NotePropertyValue 'active' -Force
            $f | Add-Member -NotePropertyName '_reason' -NotePropertyValue '' -Force
            [void]$out.Add($f); continue
        }

        $csource = if ($entry.PSObject.Properties.Name -contains 'content_source' -and $entry.content_source) { [string]$entry.content_source } else { 'file' }
        if ($csource -eq 'finding') {
            $curhash = Get-HoneyStringHash (Get-HoneyFindingCanonical $f)
        } else {
            $abs = ConvertFrom-HoneyTilde (Split-HoneyLocationFile $loc)
            $curhash = Get-HoneyFileHash $abs
        }
        $expires = if ($entry.PSObject.Properties.Name -contains 'expires' -and $entry.expires) { [string]$entry.expires } else { 'never' }
        $reason  = if ($entry.PSObject.Properties.Name -contains 'reason' -and $entry.reason) { [string]$entry.reason } else { '' }
        $cmp     = if ($entry.PSObject.Properties.Name -contains 'content_hash') { [string]$entry.content_hash } else { '' }

        $class = 'mutated'
        if ($curhash -and $curhash -eq $cmp) {
            if ($expires -ne 'never' -and $expires -lt $today) { $class = 'expired' } else { $class = 'suppressed' }
        }
        $f | Add-Member -NotePropertyName '_class' -NotePropertyValue $class -Force
        $f | Add-Member -NotePropertyName '_reason' -NotePropertyValue $reason -Force
        [void]$out.Add($f)
    }
    return $out.ToArray()
}

# An entry's index (defaults to 0 when absent).
function Get-HoneyEntryIndex {
    param($Entry)
    if ($Entry.PSObject.Properties.Name -contains 'index' -and $null -ne $Entry.index) { return $Entry.index }
    return 0
}

# Classify a lens's normalized findings (from lens-<name>.json object).
function Get-HoneyClassifiedLens {
    # "Lens" is a singular noun that happens to end in 's'.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    param([string]$Scanner, $LensObj)
    $src = @()
    if ($LensObj.PSObject.Properties.Name -contains 'findings' -and $LensObj.findings) { $src = @($LensObj.findings) }
    $prepped = foreach ($x in $src) {
        $c = $x | Select-Object *
        $c | Add-Member -NotePropertyName 'rule'    -NotePropertyValue ([string]$x.title) -Force
        $c | Add-Member -NotePropertyName '_rawloc' -NotePropertyValue ([string]$x.location) -Force
        $c
    }
    return Get-HoneyClassified -Scanner $Scanner -Findings @($prepped)
}

# Classify bumblebee findings (array of record objects from findings.ndjson).
function Get-HoneyClassifiedBumblebee {
    param([object[]]$Records)
    $prepped = foreach ($x in @($Records)) {
        $c = $x | Select-Object *
        $cid = if ($x.PSObject.Properties.Name -contains 'catalog_id') { [string]$x.catalog_id } else { '' }
        $pkg = if ($x.PSObject.Properties.Name -contains 'package_name') { [string]$x.package_name } else { '' }
        $src = if ($x.PSObject.Properties.Name -contains 'source_file') { [string]$x.source_file } else { '' }
        $c | Add-Member -NotePropertyName 'rule'    -NotePropertyValue "$cid|$pkg" -Force
        $c | Add-Member -NotePropertyName '_rawloc' -NotePropertyValue $src -Force
        $c
    }
    return Get-HoneyClassified -Scanner 'bumblebee' -Findings @($prepped)
}

# Classify EVERY scanner in a run dir, tagging each finding with _scanner.
# Used by the management CLI (status/add/remove).
function Get-HoneyClassifiedRun {
    param([string]$RunDir)
    $out = New-Object System.Collections.ArrayList
    $fp = Join-Path $RunDir 'findings.ndjson'
    if (Test-Path -LiteralPath $fp) {
        $recs = Get-Content -LiteralPath $fp | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
        foreach ($c in @(Get-HoneyClassifiedBumblebee -Records @($recs))) {
            $c | Add-Member -NotePropertyName '_scanner' -NotePropertyValue 'bumblebee' -Force
            [void]$out.Add($c)
        }
    }
    Get-ChildItem -Path $RunDir -Filter 'lens-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        $lj = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        $name = if ($lj.PSObject.Properties.Name -contains 'lens') { [string]$lj.lens } else { '' }
        if (-not $name) { return }
        foreach ($c in @(Get-HoneyClassifiedLens -Scanner $name -LensObj $lj)) {
            $c | Add-Member -NotePropertyName '_scanner' -NotePropertyValue $name -Force
            [void]$out.Add($c)
        }
    }
    return $out.ToArray()
}

# --- verdict -----------------------------------------------------------------

# Effective worst-wins status AFTER suppression, over bumblebee + every lens.
# Returns a hashtable: @{ status; suppressed; mutated; expired }.
# Only `exposed` scanners are re-evaluated; incomplete/scan_error/skipped pass
# through untouched.
function Get-HoneyEffectiveOverall {
    param([string]$RunDir)
    $sup = 0; $mut = 0; $exp = 0; $overall = 'clean'

    $manifestPath = Join-Path $RunDir 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $bst = if ($m.PSObject.Properties.Name -contains 'status') { [string]$m.status } else { 'unknown' }
        $fp = Join-Path $RunDir 'findings.ndjson'
        if ($bst -eq 'exposed' -and (Test-Path -LiteralPath $fp)) {
            $recs = Get-Content -LiteralPath $fp | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
            $cls = Get-HoneyClassifiedBumblebee -Records @($recs)
            $sup += @($cls | Where-Object { $_._class -eq 'suppressed' }).Count
            $mut += @($cls | Where-Object { $_._class -eq 'mutated' }).Count
            $exp += @($cls | Where-Object { $_._class -eq 'expired' }).Count
            if (@($cls | Where-Object { $_._class -ne 'suppressed' }).Count -gt 0) { $overall = Resolve-WorseStatus $overall 'exposed' }
        } else {
            $overall = Resolve-WorseStatus $overall $bst
        }
    }

    Get-ChildItem -Path $RunDir -Filter 'lens-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        $lj = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        $name = if ($lj.PSObject.Properties.Name -contains 'lens') { [string]$lj.lens } else { '' }
        $lst  = if ($lj.PSObject.Properties.Name -contains 'status') { [string]$lj.status } else { 'unknown' }
        if ($lst -eq 'exposed') {
            $cls = Get-HoneyClassifiedLens -Scanner $name -LensObj $lj
            $sup += @($cls | Where-Object { $_._class -eq 'suppressed' }).Count
            $mut += @($cls | Where-Object { $_._class -eq 'mutated' }).Count
            $exp += @($cls | Where-Object { $_._class -eq 'expired' }).Count
            if (@($cls | Where-Object { $_._class -ne 'suppressed' }).Count -gt 0) { $overall = Resolve-WorseStatus $overall 'exposed' }
        } else {
            $overall = Resolve-WorseStatus $overall $lst
        }
    }

    return @{ status = $overall; suppressed = $sup; mutated = $mut; expired = $exp }
}

Export-ModuleMember -Function Get-HoneyBaselineFile, Get-HoneyBaselineEntry,
    ConvertTo-HoneyTilde, ConvertFrom-HoneyTilde, Split-HoneyLocationFile,
    Get-HoneyFileHash, Get-HoneyStringHash, Get-HoneyFindingCanonical, Get-HoneyToday,
    Get-HoneyClassified, Get-HoneyClassifiedLens, Get-HoneyClassifiedBumblebee,
    Get-HoneyClassifiedRun, Get-HoneyEntryIndex, Get-HoneyEffectiveOverall
