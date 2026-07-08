<#
.SYNOPSIS
  honey (Windows) lens: mcp-scan — wrap Invariant Labs mcp-scan / Snyk Agent Scan
  (hybrid rules+model analysis of MCP servers & skills). PowerShell mirror of
  lenses/mcp-scan.sh.

.DESCRIPTION
  OPT-IN and NOT offline: mcp-scan's default mode calls a CLOUD API and shares
  tool names/descriptions with the vendor. Self-skips unless
  HONEY_ENABLE_MCP_SCAN=1. honey's native offline `mcp` lens covers the
  no-phone-home path.

.PARAMETER RunDir
  Run directory to write lens-mcp-scan.json into.
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

if (-not $RunDir) { Write-Error 'usage: mcp-scan.ps1 -RunDir <dir>'; exit 2 }
function Skip($note) { Write-LensResult -RunDir $RunDir -Lens 'mcp-scan' -Status 'skipped' -Findings @() -Note $note | Out-Null; Write-HoneyConsole "lens mcp-scan: skipped"; exit 0 }

if ((Get-HoneySetting 'HONEY_ENABLE_MCP_SCAN' '0') -ne '1') {
    Skip "opt-in lens (cloud/phones home) - set HONEY_ENABLE_MCP_SCAN=1 to enable; honey's native offline 'mcp' lens covers the no-network path."
}
if (-not (Get-Command mcp-scan -ErrorAction SilentlyContinue)) {
    Skip "HONEY_ENABLE_MCP_SCAN=1 but mcp-scan not installed - see https://github.com/snyk/agent-scan (pip install mcp-scan / uvx mcp-scan)."
}

$ver = (& mcp-scan --version 2>$null | Select-Object -First 1)
$argStr = Get-HoneySetting 'HONEY_MCP_SCAN_ARGS' '--local-only'
$raw = Join-Path $RunDir '.mcp-scan-raw.json'
& mcp-scan scan --json @($argStr -split ' ') 2>(Join-Path $RunDir '.mcp-scan.log') | Set-Content -LiteralPath $raw -Encoding utf8

$findings = New-Object System.Collections.ArrayList
try {
    $doc = Get-Content -LiteralPath $raw -Raw | ConvertFrom-Json
} catch {
    Write-LensResult -RunDir $RunDir -Lens 'mcp-scan' -Status 'scan_error' -Findings @() -Note "mcp-scan produced no valid JSON - see $RunDir\.mcp-scan.log (auth? SNYK_TOKEN/OPENAI_API_KEY needed for non-local scans)." | Out-Null
    Write-HoneyConsole "lens mcp-scan: no valid JSON"; exit 0
}

# Defensive recursive walk: collect objects that look like findings.
function Get-Field($o, [string[]]$names) { foreach ($n in $names) { if ($o.PSObject.Properties.Name -contains $n -and $o.$n) { return [string]$o.$n } } return '' }
function Walk($o) {
    if ($null -eq $o) { return }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        $sev = Get-Field $o @('severity','risk','level')
        $title = Get-Field $o @('title','name','label','issue','description')
        if ($sev -and $title) {
            [void]$findings.Add([pscustomobject]@{
                severity = $sev.ToLower(); title = $title
                location = (Get-Field $o @('location','path','server','tool','file'))
                detail = (Get-Field $o @('description','detail','message'))
                ref = (Get-Field $o @('code','rule')); _k = "$sev|$title"
            })
        }
        foreach ($p in $o.PSObject.Properties) { Walk $p.Value }
    } elseif ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) {
        foreach ($i in $o) { Walk $i }
    }
}
Walk $doc
$uniq = @($findings | Sort-Object _k -Unique | ForEach-Object { $_.PSObject.Properties.Remove('_k'); $_ })
Remove-Item -LiteralPath $raw -ErrorAction SilentlyContinue

$note = "mcp-scan / Snyk Agent Scan ($ver); hybrid rules+model analysis. Args: $argStr"
$status = if (@($uniq).Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens 'mcp-scan' -ToolVersion ([string]$ver) -Status $status -Findings @($uniq) -Note $note | Out-Null
Write-HoneyConsole "lens mcp-scan: status written ($(@($uniq).Count) finding(s))"
exit 0
