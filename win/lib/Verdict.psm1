<#
.SYNOPSIS
  honey (Windows): verdict policy (provenance tier + severity floor) — PowerShell
  mirror of lib/verdict.sh. Imported by Baseline.psm1 so every classified finding
  carries _provenance and _blocking. See docs/VERDICT.plan.md.

.NOTES
  Provenance: a finding whose location matches HONEY_TRUSTED_PATTERNS is
  "first-party"; everything else "third-party". Severity floor: a finding
  escalates OVERALL only if its severity is at/above the floor for its
  provenance. Below-floor findings are still reported (a "review" tier) but do
  not flip the verdict. SAFE DEFAULT: floors default to `none` (everything
  blocks, as before).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Honey.psm1')

# ERE matched against a location to mark it first-party. Unset -> the Anthropic
# marketplace default; empty -> nothing is first-party. (mirrors ${VAR-default})
function Get-HoneyTrustedPattern {
    Get-HoneySettingRaw 'HONEY_TRUSTED_PATTERNS' 'claude-plugins-official'
}

function Get-HoneyProvenance {
    param([string]$Location)
    $pat = Get-HoneyTrustedPattern
    if ($pat -and ($Location -match $pat)) { return 'first-party' }
    return 'third-party'
}

# severity -> numeric rank (higher = worse); none = 0 so a `none` floor blocks all.
function Get-HoneySeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'critical' { 5 } 'high' { 4 } 'medium' { 3 } 'low' { 2 } 'unknown' { 1 } 'none' { 0 } default { 1 }
    }
}

# provenance -> the floor severity that applies to it.
function Get-HoneyFloorFor {
    param([string]$Provenance)
    $base = Get-HoneySetting 'HONEY_VERDICT_FLOOR' 'none'
    if ($Provenance -eq 'first-party') { return (Get-HoneySetting 'HONEY_VERDICT_FLOOR_TRUSTED' $base) }
    return $base
}

# severity, provenance -> $true if this finding escalates OVERALL.
function Test-HoneyBlocking {
    param([string]$Severity, [string]$Provenance)
    $floor = Get-HoneyFloorFor $Provenance
    if ($floor -eq 'none') { return $true }
    return ((Get-HoneySeverityRank $Severity) -ge (Get-HoneySeverityRank $floor))
}

Export-ModuleMember -Function Get-HoneyTrustedPattern, Get-HoneyProvenance,
    Get-HoneySeverityRank, Get-HoneyFloorFor, Test-HoneyBlocking
