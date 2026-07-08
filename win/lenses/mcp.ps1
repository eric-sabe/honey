<#
.SYNOPSIS
  honey (Windows) lens: mcp — inventory MCP server manifests and detect RUG PULLS
  by hashing each server's definition and diffing across runs. PowerShell mirror
  of lenses/mcp.sh (offline; no external tool).

.DESCRIPTION
  Closes the MCP blind spot (servers with no SKILL.md). Findings:
    • MCP-DRIFT  (high)   — a known server's definition CHANGED since last run.
    • MCP-NEW    (low)    — a server appeared that wasn't here before.
    • MCP-RISKY  (medium) — launch command fetches-and-executes remote code.
  First run seeds the state silently; drift/new detection starts next run.

.PARAMETER RunDir
  Run directory to write lens-mcp.json into.
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

if (-not $RunDir) { Write-Error 'usage: mcp.ps1 -RunDir <dir>'; exit 2 }

$home_ = Get-HoneyHome
$honeyRoot = Get-HoneyRoot
$state = Get-HoneySetting 'HONEY_MCP_STATE' (Join-Path $honeyRoot '.mcp-state.json')
$today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
$riskyRe = [regex]'(?i)(curl|wget)[^|]*\|\s*(sh|bash)|bash\s+-c|(^|[^a-z])sh\s+-c|[^a-z]eval[^a-z]'

function Get-Prop { param($o,$n) if ($o -and $o.PSObject.Properties.Name -contains $n) { $o.$n } else { $null } }

# Deep-sort object keys so the canonical form (and its hash) is stable across a
# benign key reorder — mirrors the bash `jq walk` normalization.
function ConvertTo-SortedNode {
    param($o)
    if ($null -eq $o) { return $o }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $ord = [ordered]@{}
        $o.PSObject.Properties | Sort-Object Name | ForEach-Object { $ord[$_.Name] = (ConvertTo-SortedNode $_.Value) }
        return [pscustomobject]$ord
    }
    if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        return @($o | ForEach-Object { ConvertTo-SortedNode $_ })
    }
    return $o
}
function Get-CanonHash { param($def)
    $canon = (ConvertTo-SortedNode $def | ConvertTo-Json -Depth 20 -Compress)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return @{ canon = $canon; hash = 'sha256:' + (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canon)) | ForEach-Object { $_.ToString('x2') }) -join '') } }
    finally { $sha.Dispose() }
}

# --- discover configs -------------------------------------------------------
$defaultConfigs = @(
    (Join-Path $home_ '.claude.json'),
    (Join-Path $home_ 'AppData\Roaming\Claude\claude_desktop_config.json'),
    (Join-Path $home_ 'Library/Application Support/Claude/claude_desktop_config.json'),
    (Join-Path $home_ '.cursor\mcp.json'), (Join-Path $home_ '.vscode\mcp.json'),
    (Join-Path $home_ '.codeium\windsurf\mcp_config.json')
) -join ';'
$configs = New-Object System.Collections.ArrayList
foreach ($c in ((Get-HoneySetting 'HONEY_MCP_CONFIGS' $defaultConfigs) -split ';' | Where-Object { $_ })) {
    if (Test-Path -LiteralPath $c -PathType Leaf) { [void]$configs.Add($c) }
}
$projectRoots = (Get-HoneySetting 'HONEY_PROJECT_ROOTS' ((@(
    (Join-Path $home_ 'source\repos'), (Join-Path $home_ 'git'), (Join-Path $home_ 'code')) -join ';'))) -split ';' | Where-Object { $_ }
foreach ($root in $projectRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -Depth 6 -File -ErrorAction SilentlyContinue |
        Where-Object { ($_.Name -eq '.mcp.json' -or $_.Name -eq 'mcp.json') -and $_.FullName -notmatch '[\\/](node_modules|\.git)[\\/]' } |
        ForEach-Object { [void]$configs.Add($_.FullName) }
}
$configs = @($configs | Sort-Object -Unique)

if ($configs.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens 'mcp' -Status 'skipped' -Findings @() -Note "no MCP configs found (host configs + .mcp.json under project roots)" | Out-Null
    Write-HoneyConsole "lens mcp: no MCP configs, skipped"; exit 0
}

# --- load state -------------------------------------------------------------
$seeding = -not (Test-Path -LiteralPath $state)
$prev = @{}
if (-not $seeding) {
    try {
        $sj = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        $sv = Get-Prop $sj 'servers'
        if ($sv) { $sv.PSObject.Properties | ForEach-Object { $prev[$_.Name] = $_.Value } }
    } catch { $prev = @{} }
}

# --- extract servers, diff, scan -------------------------------------------
$findings = New-Object System.Collections.ArrayList
function Add-Finding { param($Sev,$Title,$Loc,$Detail)
    [void]$findings.Add([pscustomobject]@{ severity=$Sev; title=$Title; location=$Loc; detail=$Detail; ref='mcp-manifest' })
}
$newState = @{}
$srvCount = 0

foreach ($cfg in $configs) {
    try { $doc = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json } catch { continue }
    $serverMaps = @()
    $m = Get-Prop $doc 'mcpServers'; if ($m) { $serverMaps += $m }
    $s = Get-Prop $doc 'servers';    if ($s) { $serverMaps += $s }
    $projects = Get-Prop $doc 'projects'
    if ($projects) { $projects.PSObject.Properties | ForEach-Object { $pm = Get-Prop $_.Value 'mcpServers'; if ($pm) { $serverMaps += $pm } } }

    foreach ($map in $serverMaps) {
        foreach ($p in $map.PSObject.Properties) {
            $name = $p.Name; $def = $p.Value
            $srvCount++
            $ch = Get-CanonHash $def
            $key = "$cfg::$name"
            $firstSeen = if ($prev.ContainsKey($key) -and (Get-Prop $prev[$key] 'first_seen')) { [string]$prev[$key].first_seen } else { $today }

            if (-not $seeding) {
                if (-not $prev.ContainsKey($key)) {
                    Add-Finding 'low' "New MCP server: $name" $cfg "server '$name' appeared since the last run - confirm you added it. Definition: $($ch.canon)"
                } elseif ([string]$prev[$key].hash -ne $ch.hash) {
                    Add-Finding 'high' "MCP manifest changed (possible rug pull): $name" $cfg "server '$name' definition CHANGED since last run - a server that alters its manifest after approval is the canonical rug-pull vector. Re-review. Now: $($ch.canon)"
                }
            }
            if ($riskyRe.IsMatch($ch.canon)) {
                Add-Finding 'medium' "MCP server runs a fetch-and-exec command: $name" $cfg "launch command pipes remote content into a shell or uses bash -c/eval - a code-execution vector. Definition: $($ch.canon)"
            }
            $newState[$key] = [ordered]@{ hash = $ch.hash; first_seen = $firstSeen; last_seen = $today }
        }
    }
}

# --- persist state ----------------------------------------------------------
([ordered]@{ servers = $newState } | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $state -Encoding utf8

$note = "inventoried $srvCount MCP server(s); manifest hash-and-diff for rug pulls (state: $state)"
if ($seeding) { $note += "; FIRST RUN seeded the baseline manifest (drift/new detection starts next run)" }
$status = if (@($findings).Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens 'mcp' -ToolVersion '1' -Status $status -Findings @($findings) -Note $note | Out-Null
Write-HoneyConsole "lens mcp: status written ($(@($findings).Count) finding(s), $srvCount server(s), seeding=$seeding)"
exit 0
