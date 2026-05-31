<#
.SYNOPSIS
  honey (Windows): one-command setup. PowerShell port of setup.sh.
  Verifies toolchain, locates/clones the bumblebee checkout (persisting a
  non-default path to honey.conf.ps1), go-installs the Go vuln lenses, points to
  skillspector, then runs doctor.ps1.

.NOTES
  HONEY_SETUP_INSTALL_LENSES=0 skips the optional-lens step.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
# Capture whether BUMBLEBEE_REPO was pinned BEFORE config/defaults apply.
$repoExplicit = [bool]$env:BUMBLEBEE_REPO
Import-HoneyConfig

$honeyRoot = Get-HoneyRoot
$home_ = Get-HoneyHome
$conf  = Join-Path $honeyRoot 'honey.conf.ps1'

function Ok   { param($m) Write-HoneyConsole "  [OK] $m" }
function Bad  { param($m) Write-HoneyConsole "  [X] $m" }
function Hint { param($m) Write-HoneyConsole "      -> $m" }

# Persist a setting to honey.conf.ps1 (gitignored), written so env still wins:
#   if (-not $env:VAR) { $env:VAR = 'value' }
function Set-Persisted {
    param([string]$Name, [string]$Value)
    if (-not (Test-Path $conf)) {
        '# honey.conf.ps1 - machine-specific config (gitignored). Written by setup.ps1.' | Set-Content -LiteralPath $conf -Encoding utf8
    }
    $lines = @(Get-Content -LiteralPath $conf | Where-Object { $_ -notmatch "^\s*if \(-not \`$env:$Name\)" })
    $lines += ('if (-not $env:{0}) {{ $env:{0} = ''{1}'' }}' -f $Name, $Value)
    $lines | Set-Content -LiteralPath $conf -Encoding utf8
    Ok "persisted $Name=$Value to honey.conf.ps1"
}

Write-HoneyConsole "honey setup (Windows)"
Write-HoneyConsole ""

# 1. Toolchain we can't auto-install.
$needTool = $false
foreach ($t in @(@('git','winget install Git.Git'), @('go','winget install GoLang.Go (need 1.25+)'))) {
    if (Get-Command $t[0] -ErrorAction SilentlyContinue) { Ok "$($t[0]) present" }
    else { Bad "$($t[0]) not found"; Hint $t[1]; $needTool = $true }
}
if ($PSVersionTable.PSVersion.Major -lt 7) { Bad "PowerShell 7+ required"; $needTool = $true }
if ($needTool) { Write-HoneyConsole "`nInstall the tool(s) above, then re-run setup.ps1"; exit 1 }

# 2. bumblebee checkout. Respect an explicit/persisted BUMBLEBEE_REPO; else find
#    an existing clone before cloning a duplicate; else clone to the default.
$repo = Get-HoneySetting 'BUMBLEBEE_REPO' (Join-Path $home_ 'git\bumblebee')
function Test-CatalogPresent { param($r) (Test-Path (Join-Path $r 'threat_intel')) -and (@(Get-ChildItem (Join-Path $r 'threat_intel') -Filter '*.json' -EA SilentlyContinue).Count -gt 0) }

if (-not $repoExplicit -and -not (Test-Path $conf) -and -not (Test-CatalogPresent $repo)) {
    Write-HoneyConsole "  looking for an existing bumblebee checkout ..."
    $found = $null
    Get-ChildItem -Path $home_ -Recurse -Directory -Filter 'threat_intel' -Depth 6 -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '[\\/]bumblebee[\\/]' } |
        ForEach-Object { if (-not $found -and (Test-CatalogPresent $_.Parent.FullName)) { $found = $_.Parent.FullName } }
    if ($found -and $found -ne $repo) {
        Write-HoneyConsole "  Found an existing bumblebee clone at: $found"
        Write-HoneyConsole "  honey's default is: $repo"
        $useIt = $true
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
            $ans = Read-Host "  Use the existing clone instead of cloning a new one? [Y/n]"
            if ($ans -match '^[Nn]') { $useIt = $false }
        }
        if ($useIt) { $repo = $found; Set-Persisted 'BUMBLEBEE_REPO' $found }
    }
}

if (Test-CatalogPresent $repo) {
    Ok "bumblebee checkout present ($repo)"
} elseif (Test-Path (Join-Path $repo '.git')) {
    Write-HoneyConsole "  updating bumblebee checkout ($repo) ..."
    try { & git -C $repo pull --ff-only --quiet; Ok "checkout updated" } catch { Bad "pull failed (continuing)" }
} else {
    Write-HoneyConsole "  cloning bumblebee into $repo ..."
    try { & git clone --quiet https://github.com/perplexityai/bumblebee $repo; Ok "cloned bumblebee" }
    catch { Bad "clone failed"; Hint "clone manually or set BUMBLEBEE_REPO, then re-run"; exit 1 }
}

# 3. bumblebee binary.
Write-HoneyConsole "  installing bumblebee binary ..."
try { & go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest; Ok "binary installed" }
catch { Bad "go install failed"; exit 1 }

# 4. Optional Go-based lenses.
if ((Get-HoneySetting 'HONEY_SETUP_INSTALL_LENSES' '1') -eq '1') {
    Write-HoneyConsole ""
    Write-HoneyConsole "optional vuln-scanning lenses (Go-based - safe to install now):"
    foreach ($l in @(
        @('osv-scanner','github.com/google/osv-scanner/cmd/osv-scanner@latest'),
        @('govulncheck','golang.org/x/vuln/cmd/govulncheck@latest'))) {
        if (Get-Command $l[0] -ErrorAction SilentlyContinue) { Ok "$($l[0]) already installed" }
        else {
            Write-HoneyConsole "  installing $($l[0]) ..."
            try { & go install $l[1]; Ok "$($l[0]) installed" } catch { Bad "$($l[0]) install failed (optional - continuing)" }
        }
    }
    Write-HoneyConsole ""
    Write-HoneyConsole "optional agent-skill lens (separate Python install - NOT installed automatically):"
    if (Get-Command skillspector -ErrorAction SilentlyContinue) { Ok "skillspector already installed" }
    else { Hint "scans AI agent skills; install per https://github.com/NVIDIA/skillspector, then it activates automatically" }
}

# 5. Verify.
Write-HoneyConsole ""
Write-HoneyConsole "running doctor to verify ..."
Write-HoneyConsole ""
$env:BUMBLEBEE_REPO = $repo  # ensure doctor sees the resolved repo this session
& (Join-Path $PSScriptRoot 'doctor.ps1')
exit $LASTEXITCODE
