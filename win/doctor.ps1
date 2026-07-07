<#
.SYNOPSIS
  honey (Windows): dependency + lens health check. PowerShell port of doctor.sh.
  Exit 0 if ready to scan, 1 otherwise. Optional lenses are informational and
  never affect the core pass/fail.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'lib' 'Baseline.psm1') -Force
Import-HoneyConfig

$home_ = Get-HoneyHome
$repo  = Get-HoneySetting 'BUMBLEBEE_REPO'      (Join-Path $home_ 'git\bumblebee')
$scanRoot = Get-HoneySetting 'BUMBLEBEE_SCAN_ROOT' $home_

$fails = 0
function Ok   { param($m) Write-HoneyConsole "  [OK] $m" }
function Bad  { param($m) Write-HoneyConsole "  [X] $m"; $script:fails++ }
function Hint { param($m) Write-HoneyConsole "      -> $m" }

Write-HoneyConsole "honey doctor (Windows) - checking dependencies"
Write-HoneyConsole ""
Write-HoneyConsole "config:"
Write-HoneyConsole "  HONEY=$(Get-HoneyRoot)"
Write-HoneyConsole "  BUMBLEBEE_REPO=$repo"
Write-HoneyConsole "  BUMBLEBEE_SCAN_ROOT=$scanRoot"
Write-HoneyConsole ""
Write-HoneyConsole "checks:"

# pwsh version (>= 7 for the cross-platform cmdlets used here)
if ($PSVersionTable.PSVersion.Major -ge 7) { Ok "PowerShell $($PSVersionTable.PSVersion)" }
else { Bad "PowerShell $($PSVersionTable.PSVersion) - honey's Windows scripts need 7+"; Hint "install PowerShell 7: winget install Microsoft.PowerShell" }

# git, go
if (Get-Command git -ErrorAction SilentlyContinue) { Ok "git ($((Get-Command git).Source))" }
else { Bad "git not found"; Hint "winget install Git.Git" }

if (Get-Command go -ErrorAction SilentlyContinue) {
    $gv = (& go env GOVERSION 2>$null) -replace '^go',''
    $maj,$min = ($gv -split '\.')[0,1]
    if (([int]$maj -gt 1) -or ([int]$maj -eq 1 -and [int]$min -ge 25)) { Ok "go $gv (>= 1.25)" }
    else { Bad "go $gv is too old (bumblebee needs 1.25+)"; Hint "https://go.dev/dl/" }
} else { Bad "go not found"; Hint "winget install GoLang.Go (need 1.25+)" }

# bumblebee binary + selftest
if (Get-Command bumblebee -ErrorAction SilentlyContinue) {
    Ok "bumblebee binary ($((& bumblebee version 2>$null | Select-Object -First 1)))"
    $st = (& bumblebee selftest 2>&1); if ($LASTEXITCODE -eq 0) { Ok "bumblebee selftest: $st" }
    else { Bad "bumblebee selftest FAILED"; Hint "reinstall: go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest" }
} else { Bad "bumblebee not found on PATH"; Hint "go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest" }

# catalogs
$catDir = Join-Path $repo 'threat_intel'
$catJsons = @(Get-ChildItem -Path $catDir -Filter '*.json' -ErrorAction SilentlyContinue)
if ((Test-Path $catDir) -and $catJsons.Count -gt 0) { Ok "threat_intel catalogs: $($catJsons.Count) found in $repo" }
else {
    Bad "no threat_intel catalogs at $catDir"
    Hint "git clone https://github.com/perplexityai/bumblebee `"$repo`"  (or set BUMBLEBEE_REPO / run setup.ps1)"
}

# scan root
if (Test-Path $scanRoot) { Ok "scan root exists ($scanRoot)" } else { Bad "scan root does not exist ($scanRoot)" }

# Optional lenses (informational only).
Write-HoneyConsole ""
Write-HoneyConsole "optional lenses:"
$lensTools = [ordered]@{
    'osv-scanner'  = 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest'
    'govulncheck'  = 'go install golang.org/x/vuln/cmd/govulncheck@latest'
    'skillspector' = 'install per https://github.com/NVIDIA/skillspector (Python 3.12+)'
}
foreach ($t in $lensTools.Keys) {
    if (Get-Command $t -ErrorAction SilentlyContinue) { Ok "lens $t active" }
    else { Write-HoneyConsole "  [ ] lens $t inactive (optional)"; Hint $lensTools[$t] }
}
# honey-native lens: no external tool, uses .NET Unicode enumeration — always on.
Ok "lens smuggle active (native; invisible-Unicode/bidi + remote-include detection)"

# Suppression baseline (informational; never affects pass/fail).
Write-HoneyConsole ""
Write-HoneyConsole "suppression baseline:"
$bfile = Get-HoneyBaselineFile
if (Test-Path -LiteralPath $bfile) {
    $entries = @(Get-HoneyBaselineEntry)
    $today = Get-HoneyToday
    $expired = @($entries | Where-Object { $_.expires -ne 'never' -and [string]$_.expires -lt $today }).Count
    Ok "baseline present ($($entries.Count) pin(s)) - $bfile"
    if ($expired -gt 0) { Hint "$expired pin(s) expired; review with honey-baseline.ps1 list -Expired, then honey-baseline.ps1 prune" }
} else {
    Ok "no baseline yet (all findings active) - create pins with honey-baseline.ps1 add"
}

Write-HoneyConsole ""
if ($fails -eq 0) {
    Write-HoneyConsole "All checks passed - honey is ready. Run:  pwsh -File win\daily-cycle.ps1"
    Write-HoneyConsole "Scanner + threat intel by Perplexity: https://github.com/perplexityai/bumblebee"
    exit 0
} else {
    Write-HoneyConsole "$fails check(s) failed. Fix the items above, then re-run doctor.ps1 (or run setup.ps1)."
    exit 1
}
