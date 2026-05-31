<#
.SYNOPSIS
  honey (Windows): run a cycle, then a Windows toast notification on non-clean.
  PowerShell port of notify-cycle.sh. Entry point for the scheduled task.

.NOTES
  [W] Windows-only verification: toast delivery. Logic is cross-platform.
  Derives the verdict by recomputing worst-wins across manifest + every
  lens-*.json (NOT the bumblebee manifest alone) — the false-all-clear lesson.
  Honors daily-cycle exit: only 0/1 mean a trustworthy run; anything else is a
  failure (stale/no manifest). Toast via BurntToast if available, else a
  Windows.UI.Notifications shim, else logs (never fails the cycle).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib' 'Honey.psm1') -Force
Import-HoneyConfig
$honeyRoot = Get-HoneyRoot
function Log { param($m) Write-HoneyLog -HoneyRoot $honeyRoot -Message "notify: $m" }

# Best-effort Windows toast; never throws.
function Send-Toast {
    param([string]$Title, [string]$Message)
    try {
        if (Get-Module -ListAvailable BurntToast) {
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text $Title, $Message | Out-Null
            return
        }
        # Fallback: native Windows toast via WinRT (no module needed on Win10/11).
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
            [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $texts = $xml.GetElementsByTagName('text')
        $texts.Item(0).AppendChild($xml.CreateTextNode($Title)) | Out-Null
        $texts.Item(1).AppendChild($xml.CreateTextNode($Message)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('honey').Show($toast)
    } catch {
        Log "no toast mechanism available (BurntToast/WinRT); message: $Title - $Message"
    }
}

# Run the cycle. Exit codes: 0 clean, 1 needs attention, anything else = failure.
& (Join-Path $PSScriptRoot 'daily-cycle.ps1')
$rc = $LASTEXITCODE

$runDir = Get-HoneyLatest -HoneyRoot $honeyRoot
$manifestPath = if ($runDir) { Join-Path $runDir 'manifest.json' } else { $null }
if (($rc -ne 0 -and $rc -ne 1) -or -not $manifestPath -or -not (Test-Path $manifestPath)) {
    Send-Toast "Bumblebee scan FAILED" "No fresh results produced - see $honeyRoot\cycle.log"
    Log "cycle failed / no fresh manifest (daily-cycle rc=$rc)"
    exit 1
}

# Recompute worst-wins across bumblebee manifest + all lens-*.json, so a
# lens-only exposure (clean bumblebee) still notifies. Name the scanners that fired.
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$status = [string]$manifest.status
$hits = New-Object System.Collections.ArrayList
if ($status -eq 'exposed') { [void]$hits.Add("bumblebee($($manifest.findings_total))") }
Get-ChildItem -Path $runDir -Filter 'lens-*.json' -ErrorAction SilentlyContinue | ForEach-Object {
    $lj = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    if ([string]$lj.status -eq 'skipped') { return }
    $status = Resolve-WorseStatus $status ([string]$lj.status)
    if ([string]$lj.status -eq 'exposed') { [void]$hits.Add("$($lj.lens)($($lj.findings_total))") }
}

# Deterministic report beside the run (and into cycle.log), for non-clean runs.
if ($status -ne 'clean') {
    $report = Join-Path $runDir 'report.txt'
    try { & (Join-Path $PSScriptRoot 'report.ps1') $runDir | Set-Content -LiteralPath $report -Encoding utf8 }
    catch { Log "report generation failed: $($_.Exception.Message)" }
}

switch ($status) {
    'clean'      { Log "clean - no notification" }
    'exposed'    { Send-Toast "Bumblebee: exposure(s) found" (($hits -join ', ') + " - see runs\latest report.txt"); Log "notified: exposed [$($hits -join ', ')]" }
    'incomplete' { Send-Toast "Bumblebee scan INCOMPLETE" "Partial coverage - raise BUMBLEBEE_MAX_DURATION"; Log "notified: incomplete" }
    'scan_error' { Send-Toast "Bumblebee scan ERROR" "See cycle.log and runs\latest"; Log "notified: scan_error" }
    default      { Send-Toast "Bumblebee: status=$status" "See runs\latest\manifest.json"; Log "notified: $status" }
}
exit $rc
