<#
.SYNOPSIS
  honey lens (Windows): skillspector — scan installed AI agent skills for
  malicious/risky patterns via NVIDIA SkillSpector. PowerShell port of
  lenses/skillspector.sh.

.PARAMETER RunDir
  The run directory to write lens-skillspector.json into.

.NOTES
  Self-skips if skillspector isn't installed. Static (--no-llm) by default;
  HONEY_SKILLSPECTOR_LLM=1 enables its LLM stage. Skill roots via
  HONEY_SKILL_ROOTS (default the skill dirs under ~\.claude). NOT auto-updated
  (Python package; honey never mutates Python envs) — re-install for new patterns.
  SkillSpector exits 1 when it FINDS issues, so we judge by valid JSON, not exit.
#>
param([Parameter(Mandatory)][string]$RunDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'Honey.psm1') -Force
Import-HoneyConfig

$lens = 'skillspector'

if (-not (Get-Command skillspector -ErrorAction SilentlyContinue)) {
    Write-LensResult -RunDir $RunDir -Lens $lens -Status 'skipped' `
        -Note 'skillspector not installed - lens skipped. See README (agent-skill lens).' | Out-Null
    Write-HoneyConsole "lens skillspector: not installed, skipped"
    return
}
$ssVersion = (& skillspector --version 2>$null | Select-Object -First 1)
if (-not $ssVersion) { $ssVersion = 'unknown' }

$llmArgs = @('--no-llm')
if ((Get-HoneySetting 'HONEY_SKILLSPECTOR_LLM' '0') -eq '1') { $llmArgs = @() }

$home_ = Get-HoneyHome
$defaultRoots = @(
    (Join-Path $home_ '.claude\skills'),
    (Join-Path $home_ '.claude\plugins'),
    (Join-Path $home_ '.claude\scheduled-tasks'),
    (Join-Path $home_ '.config\claude\skills')
) -join ';'
$skillRoots = Get-HoneySetting 'HONEY_SKILL_ROOTS' $defaultRoots
$roots = @($skillRoots -split ';' | Where-Object { $_ -and (Test-Path $_) })

# Each dir containing a SKILL.md is one skill.
$skills = @()
foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -File -Filter 'SKILL.md' -ErrorAction SilentlyContinue |
        ForEach-Object { $skills += $_.DirectoryName }
}
$skills = @($skills | Select-Object -Unique)

if ($skills.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $ssVersion -Status 'clean' `
        -Note "no agent skills found under: $skillRoots" | Out-Null
    Write-HoneyConsole "lens skillspector: no skills found"
    return
}

$work = Join-Path $RunDir '.skillspector'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$errLog = Join-Path $work 'errors.log'

$all = @()
$scanned = 0; $errors = 0
foreach ($skill in $skills) {
    $scanned++
    $raw = Join-Path $work (($skill -replace '[\\/ :]', '_') + '.json')
    # SkillSpector exits 1 on findings (success); judge by valid JSON produced.
    try { & skillspector scan $skill @llmArgs --format json --output $raw 2>> $errLog | Out-Null }
    catch { Write-Verbose "skillspector threw for $skill (judged by output)" }

    $data = $null
    try { $data = Get-Content -LiteralPath $raw -Raw | ConvertFrom-Json } catch { $data = $null }
    if ($null -eq $data) { Add-Content -LiteralPath $errLog -Value "no valid JSON for: $skill"; $errors++; continue }

    foreach ($issue in @(if ($data.PSObject.Properties.Name -contains 'issues') { $data.issues } else { @() })) {
        $id      = if ($issue.PSObject.Properties.Name -contains 'id' -and $issue.id) { $issue.id } else { '' }
        $pattern = if ($issue.PSObject.Properties.Name -contains 'pattern' -and $issue.pattern) { $issue.pattern } else { '' }
        $title   = (($id + ' ' + $pattern).Trim())
        if (-not $title) { $title = 'finding' }
        $file = if ($issue.location -and $issue.location.file) { $issue.location.file } else { 'SKILL.md' }
        $loc  = "$skill/$file"
        if ($issue.location -and $issue.location.start_line) { $loc += ":$($issue.location.start_line)" }
        $detail = ''
        foreach ($k in @('explanation','finding','intent')) {
            if ($issue.PSObject.Properties.Name -contains $k -and $issue.$k) { $detail = $issue.$k; break }
        }
        $sev = if ($issue.PSObject.Properties.Name -contains 'severity' -and $issue.severity) { ([string]$issue.severity).ToLower() } else { 'unknown' }
        $all += [pscustomobject]@{
            severity = $sev
            title    = $title
            location = $loc
            detail   = $detail
            ref      = if ($issue.PSObject.Properties.Name -contains 'category' -and $issue.category) { $issue.category } else { '' }
        }
    }
}
$all = @($all)

$note = "scanned $scanned skill(s) under $skillRoots"
if ($errors -gt 0)        { $note += "; $errors scan error(s) - see $errLog" }
if ($llmArgs.Count -eq 0) { $note += '; LLM stage ON' }

if ($errors -gt 0 -and $all.Count -eq 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $ssVersion -Status 'scan_error' -Note $note | Out-Null
} elseif ($all.Count -gt 0) {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $ssVersion -Status 'exposed' -Findings $all -Note $note | Out-Null
} else {
    Write-LensResult -RunDir $RunDir -Lens $lens -ToolVersion $ssVersion -Status 'clean' -Note $note | Out-Null
}
Write-HoneyConsole "lens skillspector: $($all.Count) finding(s) across $scanned skill(s)"
