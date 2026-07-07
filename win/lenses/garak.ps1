<#
.SYNOPSIS
  honey (Windows) lens: garak — wrap NVIDIA garak (LLM vulnerability scanner that
  probes a LIVE model). PowerShell mirror of lenses/garak.sh.

.DESCRIPTION
  Doubly OPT-IN: probes a live model, makes network calls, slow. Self-skips
  unless HONEY_ENABLE_GARAK=1 AND HONEY_GARAK_TARGET is set. Never part of the
  default cycle.

.PARAMETER RunDir
  Run directory to write lens-garak.json into.
#>
param([string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

if (-not $RunDir) { Write-Error 'usage: garak.ps1 -RunDir <dir>'; exit 2 }
function Skip($note) { Write-LensResult -RunDir $RunDir -Lens 'garak' -Status 'skipped' -Findings @() -Note $note | Out-Null; Write-HoneyConsole "lens garak: skipped"; exit 0 }

if ((Get-HoneySetting 'HONEY_ENABLE_GARAK' '0') -ne '1') {
    Skip "opt-in lens (probes a LIVE model, makes network calls, slow) - set HONEY_ENABLE_GARAK=1 and HONEY_GARAK_TARGET to enable."
}
if (-not (Get-Command garak -ErrorAction SilentlyContinue)) {
    Skip "HONEY_ENABLE_GARAK=1 but garak not installed - pip install garak (https://github.com/NVIDIA/garak)."
}
$target = Get-HoneySetting 'HONEY_GARAK_TARGET' ''
if (-not $target) {
    Skip "garak enabled but no target - set HONEY_GARAK_TARGET (e.g. '--model_type openai --model_name gpt-4o-mini')."
}

$ver = (& garak --version 2>$null | Select-Object -First 1)
$prefix = Join-Path $RunDir '.garak'
$gargs = @($target -split ' ')
$probes = Get-HoneySetting 'HONEY_GARAK_PROBES' ''
if ($probes) { $gargs += @('--probes', $probes) }
$gargs += @('--report_prefix', $prefix)
& garak @gargs *> (Join-Path $RunDir '.garak.log')

$report = Get-ChildItem -LiteralPath $RunDir -Filter '.garak*.report.jsonl' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $report) {
    Write-LensResult -RunDir $RunDir -Lens 'garak' -Status 'scan_error' -Findings @() -Note "garak produced no report - see $RunDir\.garak.log (model/auth/target config?)." | Out-Null
    Write-HoneyConsole "lens garak: no report"; exit 0
}

$minpass = [double](Get-HoneySetting 'HONEY_GARAK_MIN_PASS' '0.9')
$findings = New-Object System.Collections.ArrayList
foreach ($line in [System.IO.File]::ReadLines($report.FullName)) {
    if (-not $line.Trim()) { continue }
    try { $e = $line | ConvertFrom-Json } catch { continue }
    if (($e.PSObject.Properties.Name -contains 'entry_type') -and $e.entry_type -ne 'eval') { continue }
    $total = if ($e.PSObject.Properties.Name -contains 'total' -and $e.total) { [double]$e.total } else { 1 }
    $passed = if ($e.PSObject.Properties.Name -contains 'passed') { [double]$e.passed } else { 0 }
    $rate = if ($total -eq 0) { 0 } else { $passed / $total }
    if ($rate -lt $minpass) {
        $probe = if ($e.PSObject.Properties.Name -contains 'probe') { [string]$e.probe } else { '?' }
        $detector = if ($e.PSObject.Properties.Name -contains 'detector') { [string]$e.detector } else { '?' }
        $sev = if ($rate -lt 0.5) { 'high' } elseif ($rate -lt 0.8) { 'medium' } else { 'low' }
        [void]$findings.Add([pscustomobject]@{
            severity = $sev; title = "Model failed probe: $probe"; location = $detector
            detail = "pass rate $([math]::Floor($rate*100))% on probe $probe / detector $detector"; ref = 'garak'
        })
    }
}

$note = "garak ($ver) probed $target; findings are model weaknesses below $minpass pass rate (report: $($report.FullName))"
$status = if (@($findings).Count -gt 0) { 'exposed' } else { 'clean' }
Write-LensResult -RunDir $RunDir -Lens 'garak' -ToolVersion ([string]$ver) -Status $status -Findings @($findings) -Note $note | Out-Null
Write-HoneyConsole "lens garak: status written ($(@($findings).Count) finding(s))"
exit 0
