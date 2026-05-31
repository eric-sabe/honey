# honey on Windows 11 — test guide

The PowerShell variant under `win/` was authored and tested on macOS pwsh 7.5.4
(the orchestration, all three lens normalizers, run-scan, daily-cycle, report,
setup, doctor — all verified behavior-identical to the bash version). What
**couldn't** be tested off-Windows is marked **[W]** below: Windows toast
notifications, Task Scheduler, real `C:\` paths, and the real scanners on
Windows. That's what this guide is for.

Please run through it on Windows 11 and note anything that differs from the
"expected" lines. Copy/paste the console output back if something looks off.

## 0. Prerequisites

```powershell
# PowerShell 7+ (NOT Windows PowerShell 5.1):
$PSVersionTable.PSVersion          # expect 7.x
# If missing:  winget install Microsoft.PowerShell

# Toolchain:
winget install Git.Git
winget install GoLang.Go           # need Go 1.25+
# jq is NOT required — the PowerShell port uses native JSON.

# Optional, for real toast notifications (otherwise it falls back gracefully):
Install-Module BurntToast -Scope CurrentUser
```

Clone honey, then `cd` into it. All commands below are run from the repo root.

## 1. setup.ps1  — clones bumblebee, installs Go lenses, persists config

```powershell
pwsh -File win\setup.ps1
```

**Expected:** checks git/go/pwsh; clones bumblebee to `~\git\bumblebee` (or finds
an existing clone and offers to use it); `go install`s bumblebee + osv-scanner +
govulncheck; points to skillspector (not auto-installed); ends with doctor
showing all-green and exit 0.

**[W] Watch for:** the discovery prompt ("Use the existing clone? [Y/n]") only
when an existing clone is found at a non-default path; a non-default choice
should be written to `honey.conf.ps1`.

## 2. doctor.ps1 — health check

```powershell
pwsh -File win\doctor.ps1
```

**Expected:** `[OK]` for PowerShell 7, git, go ≥1.25, bumblebee binary +
selftest, threat_intel catalogs, scan root. Active lenses listed. Exit 0.

## 3. daily-cycle.ps1 — the full scan (no notification)

```powershell
pwsh -File win\daily-cycle.ps1
```

**[W] This is the big one — first real Windows scan.** Expected: bumblebee scans
`%USERPROFILE%`, lenses scan your project roots (`~\source\repos`, `~\git`,
`~\code` by default) and agent skills under `~\.claude`. Cycle log lines end
with `=== cycle end (bumblebee=… overall=…)`. Exit 0 if everything clean, 1 if
anything is exposed/incomplete/error.

Things to confirm:
- It writes `runs\<timestamp>\` with `manifest.json` + `lens-*.json`.
- `latest.txt` (not a symlink) points at the newest run dir.
- `C:\` paths in the output look right (no `/`-vs-`\` mangling).
- **Full coverage:** if a scheduled/limited run sees far fewer files than this
  manual one, note it — Windows has no exact "Full Disk Access" analog, but
  some user-profile dirs may be access-restricted.

To point the vuln lenses at where your code actually lives:
```powershell
$env:HONEY_PROJECT_ROOTS = "C:\dev;D:\work"
pwsh -File win\daily-cycle.ps1
```

## 4. report.ps1 — render the latest run

```powershell
pwsh -File win\report.ps1
```

**Expected:** a section per scanner and a final `OVERALL: <verdict>` line. Exit 0
only if `OVERALL: CLEAN`. **Confirm the false-all-clear guard:** if bumblebee is
clean but a lens found something, the OVERALL must read EXPOSED (not "all clear").

## 5. [W] notify-cycle.ps1 — scan + Windows toast

```powershell
pwsh -File win\notify-cycle.ps1
```

**[W] Verify the toast actually appears** on a non-clean run (and that a clean
run is silent). To force a non-clean run for testing, drop a known-vulnerable
lockfile in a scanned project root, e.g.:
```powershell
$d = "$env:USERPROFILE\git\honey-toast-test"; New-Item -ItemType Directory -Force $d | Out-Null
'{"name":"v","version":"1","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.11"}}}' |
  Set-Content "$d\package-lock.json"
$env:HONEY_PROJECT_ROOTS = $d
pwsh -File win\notify-cycle.ps1     # expect a toast: "Bumblebee: exposure(s) found"
Remove-Item -Recurse -Force $d
```
If BurntToast isn't installed it falls back to the built-in WinRT toast; if that
fails it just logs (never errors). Note which path fired.

## 6. [W] install-schedule.ps1 — Task Scheduler

```powershell
pwsh -File win\install-schedule.ps1 install 12:00
pwsh -File win\install-schedule.ps1 status
Start-ScheduledTask -TaskName honey-bumblebee-notify   # run it now to test
pwsh -File win\install-schedule.ps1 uninstall          # clean up after
```

**[W] Verify:** the task registers, `status` shows it, a manual `Start` runs the
cycle (check `cycle.log` updated), and `uninstall` removes it. Toasts from a
scheduled run appear only while you're logged on (by design — it runs on your
interactive session, no stored password).

## What to report back

For each numbered step: ✅ worked as expected, or ❌ + the console output. The
[W] steps (3, 5, 6) and the `C:\` path handling are where surprises are most
likely. Everything else already passed on macOS pwsh, so a failure there would
point to a genuine Windows-specific difference worth fixing.
