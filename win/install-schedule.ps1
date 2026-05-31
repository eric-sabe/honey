<#
.SYNOPSIS
  honey (Windows): schedule the notify cycle via Task Scheduler. PowerShell port
  of install-schedule.sh (which used launchd/cron).

  Usage:  pwsh -File win\install-schedule.ps1 [install|uninstall|status] [HH:mm]

.NOTES
  [W] Windows-only — uses ScheduledTasks cmdlets (Register/Get/Unregister).
  Default action install; default time 12:00 local. Registers a per-user daily
  task running `pwsh -File win\notify-cycle.ps1`. Reversible with uninstall.
#>
param(
    [ValidateSet('install','uninstall','status')] [string]$Action = 'install',
    [string]$Time = '12:00'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName  = 'honey-bumblebee-notify'
$honeyRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$entry     = Join-Path $PSScriptRoot 'notify-cycle.ps1'
$pwshPath  = (Get-Process -Id $PID).Path  # the pwsh running this

if (-not ($Time -match '^([01]?\d|2[0-3]):([0-5]\d)$')) {
    Write-Error "time must be HH:mm (24-hour), got '$Time'"; exit 1
}

switch ($Action) {
    'install' {
        $action  = New-ScheduledTaskAction -Execute $pwshPath `
                     -Argument "-NoProfile -File `"$entry`""
        $trigger = New-ScheduledTaskTrigger -Daily -At $Time
        # Run whether or not the user is logged on is NOT used (needs a password);
        # run on the user's interactive token so toasts can appear.
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                      -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Description "honey daily supply-chain scan ($honeyRoot)" -Force | Out-Null
        Write-Output "Installed scheduled task '$taskName' - runs daily at $Time (local)."
        Write-Output "Run now to test:  Start-ScheduledTask -TaskName $taskName"
        Write-Output "NOTE: toasts appear only while you're logged on; the task runs on your interactive session."
    }
    'uninstall' {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Output "Removed scheduled task '$taskName'."
        } else { Write-Output "No scheduled task '$taskName' to remove." }
    }
    'status' {
        $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($t) {
            $info = $t | Get-ScheduledTaskInfo
            Write-Output "Task '$taskName': $($t.State); next run $($info.NextRunTime); last result $($info.LastTaskResult)"
        } else { Write-Output "Task '$taskName' is not installed." }
    }
}
