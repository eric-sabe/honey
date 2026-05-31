# honey on Windows 11 — implementation plan

Two deliverables, sequenced cheapest-first. Track 1 ships value in ~an hour and
proves the scanners work on your box; Track 2 is the native rewrite.

Status legend:  [ ] todo   [~] author-on-mac, verify-on-win   [W] Windows-only

---

## Track 1 — WSL2 support (low effort, high reliability)

honey already runs on Linux. WSL2 *is* Linux on Win11, so the scripts run
unchanged. Scope is documentation + one notification check.

- [ ] **README: "Windows 11 (WSL2)" section.** Install WSL2 (`wsl --install`),
      clone honey inside the WSL filesystem (NOT `/mnt/c` — slow + perms), run
      `./setup.sh` exactly as on Linux.
- [W] **Verify WSLg notifications.** `notify-cycle.sh` already calls
      `notify-send`; on Win11 WSLg this should surface a real toast. Confirm,
      and if `notify-send` is absent: `sudo apt install libnotify-bin`.
- [W] **Verify scheduling.** cron in WSL2 works but only while WSL is running.
      Document the Win11-reliable alternative: a Task Scheduler entry that runs
      `wsl ~/git/honey/notify-cycle.sh` at logon/daily (covered in Track 2's
      scheduler work — the .ps1 installer can target WSL too).
- [ ] **Scope note.** WSL2 honey scans the *Linux* filesystem. Right for devs
      who work inside WSL; wrong for native `C:\` projects → that's Track 2.

**Acceptance:** on the Win box, `./daily-cycle.sh` under WSL2 produces a run +
verdict, and a non-clean run pops a Windows notification.

---

## Track 2 — Native PowerShell variant (the real port)

A parallel orchestration layer in PowerShell 7 (`pwsh`), calling the SAME Go
scanner binaries. Lives under `win/` so the bash tree is untouched.

### Why this is more tractable than it looks
- Scanners are cross-platform already: bumblebee / osv-scanner / govulncheck
  install via `go install` on Windows; skillspector via pip. **No scanner code
  changes.**
- The lens **contract is just JSON** — each lens writes
  `lens-<name>.json {lens,status,findings_total,findings_by_severity,findings[],note}`
  and the cycle takes the worst status. PowerShell does JSON natively
  (ConvertFrom/ConvertTo-Json) — `jq` is not needed.
- pwsh 7 is on the mac dev box, so the orchestration/normalizer logic can be
  **authored and unit-tested here**; only Windows-native pieces (toast,
  Task Scheduler, `C:\` paths, FullDisk-equivalent) need the Windows box.

### File-by-file port (bash → pwsh), under `win/`
- [~] `win/lib/Honey.psm1` — shared module: config load (honey.conf →
      `honey.conf.ps1` or reuse env), path resolver, the `Rank`/worst-wins
      helper, `Emit-Lens` (writes normalized JSON), color/log helpers.
- [~] `win/run-scan.ps1` — `git pull` + `go install` bumblebee, run
      `bumblebee scan --profile deep --root $env:USERPROFILE
      --exposure-catalog <repo>\threat_intel --findings-only`, split records,
      build `manifest.json`. Replace the `latest` **symlink** with either a
      junction (`New-Item -ItemType Junction`) or a `latest.txt` pointer file
      (junctions need no admin; pointer file is simplest + portable).
- [~] `win/daily-cycle.ps1` — run-scan, then each `win/lenses/*.ps1`,
      worst-wins overall, exit 0/1/2. Port the freshness guard (manifest run_id
      >= cycle start) and the crashed-lens→scan_error escalation.
- [~] `win/lenses/osv-scanner.ps1` — `osv-scanner scan --format json -r
      $roots`; port the normalizer INCLUDING the vendored-path exclusion
      (`node_modules|vendor|.pnpm|...`) + dedup. Win paths use `\`; the exclude
      regex must match both separators.
- [~] `win/lenses/govulncheck.ps1` — per Go module under project roots;
      count only `finding` messages, join to `osv` summaries; validate the
      pretty-printed stream.
- [~] `win/lenses/skillspector.ps1` — scan skill dirs; on Windows skills live
      under `%USERPROFILE%\.claude\...` (same relative layout). Static --no-llm
      default.
- [~] `win/report.ps1` — per-scanner sections + `OVERALL:` line, exit 0/1.
      Verdict source of truth, same as bash.
- [W] `win/notify-cycle.ps1` — run daily-cycle, then a Windows toast on
      non-clean (BurntToast module, or a Windows.UI.Notifications shim, or
      fallback to writing report.txt + a console bell). Derive verdict from the
      report's OVERALL, NOT the bumblebee manifest (the false-all-clear lesson).
- [W] `win/install-schedule.ps1` — register a **Task Scheduler** job
      (`Register-ScheduledTask`) running `pwsh -File win\notify-cycle.ps1`
      daily; install/uninstall/status verbs mirroring the bash installer.
- [~] `win/setup.ps1` — check pwsh7/git/go, clone/locate bumblebee (persist a
      non-default path), `go install` the Go lenses, point to skillspector,
      run a doctor check. Mirror the bash setup's discover-existing-clone +
      persist behavior.
- [~] `win/doctor.ps1` — dependency + active-lens health check.

### Config & paths
- [~] Default scan root: `$env:USERPROFILE` (= `~`). Project roots default to
      `$env:USERPROFILE\source\repos;...\git;...\code` (VS default is
      `source\repos`). Persist overrides in `honey.conf.ps1` (gitignored).
- [~] Symlink replacement: decide junction vs `latest.txt`. Recommend
      `latest.txt` containing the run dir path — zero privilege, both readers
      (report.ps1, notify) updated to resolve it. Keep bash `latest` symlink
      untouched on Unix.

### Known coverage caveat (document, don't pretend to fix)
- [ ] **bumblebee's detection is Unix-oriented.** Cross-platform lockfiles
      (package-lock.json, requirements.txt, go.sum, Cargo.lock) ARE found on
      Windows, but Windows-native package managers (winget / Chocolatey /
      Scoop) and Windows path layouts (`%APPDATA%\npm`) are NOT in bumblebee's
      source list. README must state plainly: native-Windows honey covers
      project/lockfile + agent-skill + Go-reachability surfaces well, and
      OS-level Windows package managers not at all (an upstream bumblebee gap).

### Investigated & deferred: a winget/Chocolatey/Scoop lens (NO go for now)
Researched 2026-05-31. Conclusion: **not buildable to honey's quality bar with
data that exists today.** Recorded so this isn't re-investigated cold.

- **No tool to wrap.** The existing lenses each wrap a scanner that already does
  the matching (osv-scanner→OSV.dev, govulncheck→vuln.go.dev). For these three
  there is no equivalent: OSV.dev has **no winget/chocolatey/scoop ecosystem**
  (its ~30 ecosystems include npm/PyPI/Go/NuGet/crates/RubyGems/Debian/Alpine/…
  but none of the Windows package managers), and `winget audit` is an open
  feature request (microsoft/winget-cli#2204), not a shipping command. Choco
  moderates/removes malware but publishes **no advisory feed or removed-package
  API** (only a scrapeable search UI). Scoop: nothing.
- **Inventory is easy; matching is the problem.** `winget export` / `choco
  export` / `scoop export` all emit clean name+version JSON — so a lens *could*
  inventory trivially. The blocker is what to match against.
- **Catalog options evaluated:**
  - bumblebee catalog schema is simple+decoupled (`{schema_version, entries:[{id,
    name, ecosystem, package, versions[], severity, source}]}`) — a lens can
    supply its own `ecosystem` string. So the format is not the issue.
  - CISA KEV (https://github.com/cisagov/kev-data) — CC0 JSON, authoritative,
    actively-exploited. BUT keyed by **vendor+product**, not package@version, so
    matching `winget list` needs a fuzzy name→product mapping → false-positive
    risk honey explicitly avoids. Usable only as *enrichment* ("this CVE is in
    KEV = actively exploited"), not as a precise matching source.
  - Self-curated `threat_intel/windows/` — exact, reliable, but pure manual
    threat-intel curation (bumblebee's own model). Real ongoing cost; only as
    complete as kept.
- **What would unblock it (any one):** (a) OSV.dev adds a winget/choco ecosystem;
  (b) bumblebee upstream adds these as recognized ecosystems (best home — open an
  issue/PR); (c) someone publishes a parseable+redistributable known-bad-Windows-
  package feed. Until then, leave it out.
- **Net coverage impact: small.** The Windows package managers' unique surface is
  OS-level *applications* (Chrome, VS Code, …) — exactly the surface with no good
  catalog. Dependency-vulnerability coverage (the bulk of dev-box risk) is already
  handled by osv-scanner (incl. **NuGet**, a real OSV ecosystem), govulncheck, and
  bumblebee's cross-platform lockfile parsing.

### CI
- [~] Add a `pwsh -NoProfile -Command "..."` parse/lint pass (PSScriptAnalyzer)
      for `win/**/*.ps1` to the existing GitHub Actions workflow (ubuntu runner
      has pwsh; or add a windows-latest job). Keeps the bash `shellcheck` job.

---

## Sequencing
1. Track 1 README + WSL notify/schedule verification (fast win on the Win box).
2. Track 2 authored + unit-tested on the mac (pwsh 7 present): module, run-scan,
   lenses, report, doctor, setup — everything that doesn't need Windows APIs.
3. Track 2 Windows-only pieces verified on the Win box: toast, Task Scheduler,
   junction/latest.txt, `C:\` scan roots, real scanner runs.
4. README "Windows 11 (native)" section + CI lint for `win/`.

## What can be done WITHOUT the Windows box (here, now)
Everything marked `[~]`: author the PowerShell module + scripts and run their
JSON-normalization / worst-wins / report logic under pwsh 7 on macOS against
the same fixtures we used for the bash lenses. Only `[W]` items truly wait.
