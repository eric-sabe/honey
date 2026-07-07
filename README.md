# honey

[![ci](https://github.com/eric-sabe/honey/actions/workflows/ci.yml/badge.svg)](https://github.com/eric-sabe/honey/actions/workflows/ci.yml)

A hands-off supply-chain watchdog for your dev machine. honey runs
best-in-class security scanners on a schedule, unifies their results into one
verdict, and (optionally) has Claude DM you a triage write-up each day.

honey doesn't detect anything itself — it **orchestrates** scanners, each a
"lens" on a different risk:

| Lens | Answers | Upstream |
|---|---|---|
| **bumblebee** *(core)* | "Do I have a known-compromised package/extension?" | [Perplexity](https://github.com/perplexityai/bumblebee) |
| osv-scanner | "Do my dependencies have known CVEs?" (all ecosystems) | [Google/OSV](https://github.com/google/osv-scanner) |
| govulncheck | "Do I actually *call* a vulnerable Go function?" | [Go team](https://golang.org/x/vuln) |
| skillspector | "Is an installed AI agent skill behaving maliciously?" | [NVIDIA](https://github.com/NVIDIA/skillspector) |

bumblebee (the only required scanner) is a read-only inventory collector that
flags on-disk package/extension/version metadata matching a known-compromised
entry in a threat-intelligence catalog. The lenses are **opt-in** and inert
until you install their tool. honey adds the update→scan→report loop,
worst-wins verdict, scheduling, and reporting — **all detection capability and
threat data are the upstreams'**, above all [Perplexity](https://www.perplexity.ai)'s
bumblebee. See [Acknowledgements](#acknowledgements).

Use honey three ways, smallest footprint first:

- **Plain scanner** — `./daily-cycle.sh`, read the verdict. No Claude, no
  scheduler, no accounts.
- **Scheduled + desktop notification** — a launchd/cron job alerts you on
  findings, with a deterministic report. No Claude required.
- **Daily Claude routine** — a Claude Code *Local* routine scans on a schedule
  and DMs an enriched triage write-up to Slack.

## Quickstart

```sh
git clone https://github.com/<you>/honey && cd honey
./setup.sh        # clones bumblebee, installs the binary + Go vuln lenses, verifies
./daily-cycle.sh  # run a scan; read runs/latest/manifest.json for the verdict
```

`setup.sh` is idempotent and ends by running `./doctor.sh`, which prints a
✓/✗ line for every dependency with exact fix-it commands for anything
missing. If a scan ever misbehaves, run `./doctor.sh` first.

By default `setup.sh` also offers to install the two Go-based vulnerability
[lenses](#lenses--additional-scanners-optional) (osv-scanner, govulncheck) —
you already have Go. The Python-based skillspector lens is pointed to, not
auto-installed. Pass `HONEY_SETUP_INSTALL_LENSES=0 ./setup.sh` to skip lenses.

### Requirements

**Core:** `bash`, `git`, [`jq`](https://jqlang.org), and [Go](https://go.dev)
**1.25+** (bumblebee needs 1.25+). macOS or Linux. `setup.sh` checks all of
these and tells you the install command for anything you're missing — it won't
guess your package manager. These also cover the two Go-based vuln lenses
(osv-scanner, govulncheck), which install via `go install`.

**Per optional lens:** only the `skillspector` lens adds a requirement —
**Python 3.12+** (install it per
[SkillSpector's README](https://github.com/NVIDIA/skillspector)). The vuln
lenses need nothing beyond the core toolchain. `./doctor.sh` shows which
lenses are active and how to enable inactive ones.

> **Why a bumblebee *checkout* and not just the binary?** The threat-intel
> catalogs live in the repo's `threat_intel/` directory, not inside the
> installed binary. honey needs both: the binary to scan, and a git checkout
> for the catalogs (which it `git pull`s each run to stay current).
> `setup.sh` handles both.

## How a scan cycle works

1. `git pull --ff-only` the bumblebee checkout — fresh `threat_intel/`
   catalogs (they're updated upstream via PR).
2. `go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest` — fresh
   binary.
3. `bumblebee scan --profile deep --root $HOME --exposure-catalog <repo>/threat_intel
   --findings-only` → writes a timestamped run dir + `manifest.json`.
4. `daily-cycle.sh` exits `0` when `status` is `clean`, `1` otherwise — so a
   scheduler or routine can branch on it.

A clean machine produces no findings — that's the "all clear". Results live
**outside** the bumblebee checkout and `~/go`, so neither the `git pull` nor
the `go install` can delete them.

### manifest `status` values

- `clean`      — scan completed, no matches.
- `exposed`    — one or more catalog matches (see `findings.ndjson`).
- `incomplete` — hit `--max-duration`; coverage partial, NOT all-clear.
- `scan_error` — scan failed; see `cycle.log` / `diagnostics.ndjson`.

## Lenses — additional scanners (optional)

bumblebee is honey's canonical lens (known-bad catalog matching). honey can
run **additional lenses** alongside it — independent scanners that cover a
different surface — and fold their results into one report. Each lens lives in
[`lenses/`](lenses) as a small script; if its underlying tool isn't installed,
the lens is **inert** (a clean machine with no lens tools behaves exactly as
bumblebee-only). The cycle's overall verdict is the **worst** across bumblebee
and every active lens — a lens can escalate concern, never mask a bumblebee
finding.

Every lens is **opt-in**: honey never installs a lens's tool for you, and an
uninstalled lens is fully inert. Install the tool, and the lens activates on
the next run. `./doctor.sh` shows which lenses are active.

| Lens | Tool | Covers | Install |
|---|---|---|---|
| `skillspector` | [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | AI agent skills (`SKILL.md` + scripts): prompt injection, data exfil, excessive agency, tool poisoning | per its README (Python 3.12+) |
| `smuggle` | honey-native | **Scanner-evasion** in agent-skill/instruction files: invisible-Unicode (tag chars), bidi overrides (Trojan Source), zero-width chars, and remote-include instructions — the tricks static pattern scanners miss | none (uses `perl`; PowerShell uses native .NET) |
| `osv-scanner` | [Google/OSV osv-scanner](https://github.com/google/osv-scanner) | Known vulns in lockfiles/manifests across **all** ecosystems (npm, pypi, cargo, go, …) | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| `govulncheck` | [Go vuln team govulncheck](https://golang.org/x/vuln) | Go vulns that your code **actually calls** (reachability-aware → far less noise) | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

**What each answers.** bumblebee: *"do I have a known-compromised package?"*
(exact catalog match). skillspector: *"is this agent skill behaving
maliciously?"* (content analysis). smuggle: *"is something hidden from the
scanners — invisible Unicode, a bidi trick, a remote include?"* (evasion).
osv-scanner: *"do my dependencies have known CVEs?"* (broad). govulncheck: *"do I
actually reach a vulnerable Go function?"* (deep, low-noise). Together they cover
reactive, proactive, breadth, depth, and anti-evasion.

**Where the vuln lenses scan.** osv-scanner and govulncheck scan your *project*
directories, not all of `$HOME`. Set `HONEY_PROJECT_ROOTS` (colon-separated;
default `~/git:~/code:~/Developer:~/src`) to control this. The skillspector
lens scans skill dirs under `~/.claude` (override with `HONEY_SKILL_ROOTS`).

**Declared deps, not vendored copies.** osv-scanner walks into `node_modules`,
`vendor/`, `.pnpm`, and every nested `.claude/worktrees/*` — flagging the same
transitive dependency dozens of times across installed copies (one real run
produced 2,954 findings, 81% of them duplicated vendored packages; after
filtering, 402 real ones). By default honey **excludes those paths and dedupes
identical `package@version`+advisory across lockfiles**, so you see each real
vulnerable dependency once. Tune via `HONEY_OSV_EXCLUDE_PATHS` (set empty to
scan everything) and `HONEY_OSV_NO_DEDUPE=1`.

**Go division of labor.** osv-scanner and govulncheck overlap on Go. By
default osv-scanner **defers Go stdlib advisories to govulncheck** — otherwise
it flags every stdlib CVE for your `go` directive (often dozens, unreachable,
no CVSS). govulncheck reports only the stdlib vulns you actually call. Set
`HONEY_OSV_INCLUDE_GO_STDLIB=1` to keep them in osv-scanner anyway.

Both vuln lenses run static DB lookups (osv-scanner → OSV.dev with
`HONEY_OSV_OFFLINE=1` for local DBs; govulncheck → vuln.go.dev). skillspector
runs static (`--no-llm`) by default — honey's Claude routine is the semantic
layer; set `HONEY_SKILLSPECTOR_LLM=1` to use SkillSpector's own LLM stage.

### Staying current

Two things can go stale — the vuln **data** and the scanner **binaries** —
and honey treats them differently:

- **Vuln data is always live.** osv-scanner and govulncheck query their
  databases (OSV.dev, vuln.go.dev) on every scan, so a CVE published yesterday
  is caught today with no update step.
- **Go lens binaries auto-update.** Before scanning, honey `go install
  @latest`s osv-scanner and govulncheck (just as it does the bumblebee binary).
  Set `HONEY_UPDATE_LENSES=0` to disable. The update is non-fatal: if it fails
  (offline, etc.) the lens keeps its existing binary and scans anyway. A
  breaking upstream change surfaces as `scan_error` (visible), never a false
  clean.
- **skillspector is NOT auto-updated.** Its detection patterns are bundled in
  the installed package, and its install method (pip/pipx/venv) is yours —
  honey never mutates Python environments. Re-install it periodically per its
  README to get new patterns.

## Suppression baseline (pin-and-diff)

Static scanners are noisy. A daily run over trusted, first-party agent skills
can emit dozens of findings that are false positives against reference or
documentation material — enough to drag `OVERALL` to `EXPOSED` every day and
bury a *real* finding. honey lets you acknowledge a reviewed-benign finding
**once** so it stops contributing to the daily verdict — without going blind to
the thing honey exists to catch.

The mechanism is **pin, not mute**. A suppression entry doesn't say "ignore this
skill" (trust-by-location is blindness-by-location — a first-party plugin that
ships a malicious update keeps its path). It says *"I reviewed this exact content
and judged this finding benign — tell me the instant the content changes."* Each
entry records a **sha256 of the referenced file**, so:

- pinned finding, file **unchanged** → **suppressed** (dropped from the verdict, still counted);
- pinned finding, file **changed** → **MUTATED** — resurfaces loudly (the rug-pull tripwire);
- pin past its **expiry** (default 90 days) → resurfaces as normal.

Every suppressed finding is therefore also a change-detector on the content it
vouches for. Suppression is a **report-layer re-rank, never a deletion** — raw
run records are untouched — and a suppressed run **never** reads as a bare
all-clear: the verdict always carries the tallies, e.g.
`OVERALL: CLEAN (12 suppressed)` or `OVERALL: EXPOSED — … (12 suppressed, 2 mutated)`.
Design details and the threat model are in [`docs/BASELINE.plan.md`](docs/BASELINE.plan.md).

**Manage it** with [`honey-baseline.sh`](honey-baseline.sh) (Windows:
[`win/honey-baseline.ps1`](win/honey-baseline.ps1)) — it only edits
`honey.baseline.json`, never your system:

```bash
./honey-baseline.sh status                       # dry-run: suppressed/mutated/expired/active tally
./honey-baseline.sh add --scanner skillspector \
    --location references/ \
    --reason "first-party marketplace docs; describes patterns, not executable" --expires 90
./honey-baseline.sh list [--expired|--active]     # review pins (flags expired)
./honey-baseline.sh remove --scanner skillspector --location references/
./honey-baseline.sh prune                         # drop expired pins
```

`add` filters are combinable (AND): `--all` (excludes bumblebee), `--scanner`,
`--severity`, `--rule`, `--location`. Pinning a **bumblebee** (known-compromised)
match is opt-in and loud — `--all` excludes it; you must name `--scanner
bumblebee` explicitly. `honey.baseline.json` is **committed and reviewable** on
purpose: baseline edits show up in `git diff` / PR review, which is itself an
anti-gaming control.

**What it does and does not defend.** The content hash is the right defense
against silent post-review mutation (manifest-alteration rug pulls, source
swaps). It is structurally blind to payloads that were never flagged in the
first place — sleeper/trigger-activated code, instructions fetched from a remote
URL at runtime, or content hidden in bundled images. The baseline can only
suppress what a lens surfaced; widening the scanned surface is separate work.

## Verdict policy (provenance + severity floor)

Where the baseline pins *specific* findings, the verdict policy is the *broad*
dial for the daily marketplace noise. Two settings, applied after suppression
([`docs/VERDICT.plan.md`](docs/VERDICT.plan.md)):

- **Provenance** — a finding whose location matches `HONEY_TRUSTED_PATTERNS`
  (default `claude-plugins-official`) is tagged **first-party**; the report shows
  a `[1st-party]` marker.
- **Severity floor** — a finding escalates `OVERALL` only at/above the floor for
  its provenance (`HONEY_VERDICT_FLOOR` for third-party, `HONEY_VERDICT_FLOOR_TRUSTED`
  for first-party). Below-floor findings move to a **review tier**: still
  printed and counted (`OVERALL: … (65 review)`), but non-blocking.

```bash
# Demote first-party low/medium noise to the review tier (high/critical still block):
export HONEY_VERDICT_FLOOR_TRUSTED=high
# Or, for a marketplace you fully trust, demote all of its non-critical findings:
export HONEY_VERDICT_FLOOR_TRUSTED=critical
```

**Safe by default:** floors default to `none` — every finding blocks, exactly as
before. Provenance labeling is on (informational). **bumblebee always blocks**
(known-compromised catalog), and a **MUTATED** pin always blocks (rug-pull
tripwire) — the floor is a lens-noise dial, never a mute for genuine danger.

## Optional: daily Slack triage via a Claude Local routine

If you use [Claude Code](https://claude.com/claude-code) and have the Slack
connector enabled, you can have the whole thing run daily and DM you the
analysis — no extra credentials, because a *Local* routine reuses your own
Claude auth and connectors.

1. In the Routines hub: **New routine → Local**.
2. Paste the prompt from [`routine-prompt.md`](routine-prompt.md) (it runs
   `daily-cycle.sh` to scan, `report.sh` for the factual baseline, then DMs
   you an enriched write-up). Set `HONEY_DIR` in it to your checkout path.
3. Set the schedule (e.g. daily at noon).

On a clean run you get a one-line all-clear; on an `exposed` run you get
per-finding triage with drafted remediation, layering Claude's tailored
judgment on top of `report.sh`'s deterministic facts. Because it's *Local*,
it can see your real filesystem (so the scan is meaningful) — a *Remote* cloud
routine cannot, and would always report clean.

**Lenses in the routine — already handled.** The prompt runs `report.sh`,
which covers bumblebee *and every active lens*, so the routine picks up
osv-scanner / govulncheck / skillspector automatically once their tools are
installed — no prompt change needed. Two things make this work without manual
config:
- `daily-cycle.sh` sets its own PATH (including `~/go/bin` and `~/.local/bin`),
  so the lens tools resolve even though a Local routine starts with a bare
  environment.
- The vuln lenses default to scanning `~/git:~/code:~/Developer:~/src`. A Local
  routine does not inherit your shell's env vars, so if your projects live
  elsewhere, persist it in `honey.conf` (add
  `export HONEY_PROJECT_ROOTS="${HONEY_PROJECT_ROOTS:-/my/projects:/other}"`) —
  every script, including the routine's, reads that. (Or add a `Set
  HONEY_PROJECT_ROOTS=… before running the scripts.` line to the prompt.)
  Same applies to a non-default `BUMBLEBEE_REPO`, which `setup.sh` persists for
  you — see [Configuration](#configuration-env-vars-all-optional).

To triage by hand in a chat instead ("triage the latest honey run"), see
[`triage-guide.md`](triage-guide.md).

## Optional: daily scan + desktop notification (no Claude, no Slack)

Don't use Claude or Slack? Schedule the scan with your OS and get a native
desktop notification when something needs attention — no accounts, no
connectors.

```sh
./install-schedule.sh            # daily at noon (local); pass HH:MM to change
./install-schedule.sh status     # is it scheduled?
./install-schedule.sh uninstall  # remove it
```

- **macOS** → installs a per-user **launchd** agent (`com.honey.bumblebee.notify`)
  and notifies via `osascript` (built in) or `terminal-notifier` if installed.
- **Linux** → installs a user **cron** line and notifies via `notify-send`
  (libnotify), provided a graphical session is active.

It runs [`notify-cycle.sh`](notify-cycle.sh), which scans and — only when the
verdict is `exposed` / `incomplete` / `scan_error` — pops a notification
pointing at `runs/latest/report.txt`. Clean runs are silent.

**You still get analysis without Claude.** [`report.sh`](report.sh) renders a
readable triage report straight from the structured findings — verdict,
coverage, and each match grouped by severity with its location, confidence,
and standard per-ecosystem remediation steps (npm/pip/go/bundler/composer/
brew/extension). The notify path writes it to `runs/latest/report.txt`
automatically; you can also run it anytime:

```sh
./report.sh                 # report on the latest run
./report.sh runs/<TS>       # report on a specific run
```

The Claude routine produces richer, tailored prose and reasons about your
specific project layout, but the facts and standard fixes are all in
`report.sh` deterministically — so the no-Claude path is genuinely
actionable, not just a "something matched" ping.

> **macOS permissions:** a scheduled job scanning all of `$HOME` may need
> *Full Disk Access* (System Settings → Privacy & Security) to read protected
> directories, and notifications must be allowed for the running process. If a
> scheduled run sees fewer files than a manual one, Full Disk Access is why.

## Manual use

```sh
./doctor.sh                      # health check + which lenses are active
./run-scan.sh                    # just bumblebee (no cycle wrapper, no lenses)
./daily-cycle.sh                 # bumblebee + all active lenses + overall verdict
./report.sh                      # render the latest run (bumblebee + every lens)

# Narrow the scan or change the time budget:
BUMBLEBEE_SCAN_ROOT="$HOME/code" BUMBLEBEE_MAX_DURATION=20m ./run-scan.sh

# Point the vuln lenses at your projects:
HONEY_PROJECT_ROOTS="$HOME/work:$HOME/repos" ./daily-cycle.sh
```

After any run, `runs/latest/manifest.json` has the verdict and
`runs/latest/findings.ndjson` has any matches.

## Configuration (env vars, all optional)

All settings are environment variables with working defaults — a default
install needs none of them. Set them inline (`HONEY_PROJECT_ROOTS=… ./daily-cycle.sh`)
or export them in your shell.

**Persisting a setting (`honey.conf`).** Env vars don't survive across shells,
and a Claude *Local* routine / cron job starts with a bare environment that
won't see them. For settings that must stick — most often a non-default
`BUMBLEBEE_REPO` — `setup.sh` writes a gitignored `honey.conf` at the repo
root that every script sources. If `setup.sh` finds an existing bumblebee
checkout at a non-default path, it offers to use it and persists the choice
there (rather than cloning a duplicate). Precedence is **env var > honey.conf
> built-in default**, so an explicit env var still overrides the file for a
one-off run. You can also hand-edit `honey.conf` — one `export VAR=…` per line.

| Var | Default | Purpose |
|---|---|---|
| `HONEY` | the scripts' own directory | where runs are written |
| `BUMBLEBEE_REPO` | `$HOME/git/bumblebee` | bumblebee checkout (for catalogs) |
| `BUMBLEBEE_SCAN_ROOT` | `$HOME` | what bumblebee scans |
| `BUMBLEBEE_MAX_DURATION` | `30m` | bumblebee scan time cap |
| `HONEY_PROJECT_ROOTS` | `~/git:~/code:~/Developer:~/src` | where the vuln lenses (osv-scanner, govulncheck) look for projects |
| `HONEY_SKILL_ROOTS` | skill dirs under `~/.claude` | where the skillspector and smuggle lenses look for agent skills |
| `HONEY_SMUGGLE_EXCLUDE` | `node_modules`/`.git`/`vendor`/`.pnpm` | smuggle lens: skip files whose path matches (ERE) |
| `HONEY_UPDATE_LENSES` | `1` | `go install @latest` the Go lens binaries (osv-scanner, govulncheck) before scanning; `0` to skip |
| `HONEY_OSV_OFFLINE` | `0` | osv-scanner: use local vuln DBs instead of OSV.dev |
| `HONEY_OSV_INCLUDE_GO_STDLIB` | `0` | osv-scanner: keep Go stdlib advisories (default defers them to govulncheck) |
| `HONEY_OSV_EXCLUDE_PATHS` | `node_modules`/`vendor`/`.pnpm`/`testdata`/`fixtures`/`.claude/worktrees` (ERE) | osv-scanner: skip findings whose source path matches — keeps the scan on *declared* manifests, not installed/vendored copies. Set empty to scan everything. |
| `HONEY_OSV_NO_DEDUPE` | `0` | osv-scanner: `1` keeps one finding per path; default collapses identical `package@version`+advisory across paths into one (`+N more`) |
| `HONEY_SKILLSPECTOR_LLM` | `0` | skillspector: enable its own LLM stage (default static `--no-llm`) |
| `HONEY_BASELINE` | `<repo>/honey.baseline.json` | path to the suppression baseline (pin-and-diff); see [Suppression baseline](#suppression-baseline-pin-and-diff) |
| `HONEY_TRUSTED_PATTERNS` | `claude-plugins-official` | ERE; a finding whose location matches is **first-party** (else third-party). Empty ⇒ nothing trusted. See [Verdict policy](#verdict-policy-provenance--severity-floor) |
| `HONEY_VERDICT_FLOOR` | `none` | min severity (`none\|low\|medium\|high\|critical`) at which a **third-party** finding escalates OVERALL; below it → non-blocking "review" tier (still reported) |
| `HONEY_VERDICT_FLOOR_TRUSTED` | = `HONEY_VERDICT_FLOOR` | same, for **first-party** findings. Set `high` (or `critical`) to demote trusted-marketplace low/medium noise to review |

## Layout

```
honey/
├── setup.sh          # one-command setup: bumblebee + Go vuln lenses, then verify
├── doctor.sh         # dependency health check with fix-it hints
├── lib/preflight.sh  # shared dependency checks (sourced by the above)
├── run-scan.sh       # update repo+binary, deep-scan, write a run + manifest
├── daily-cycle.sh    # one cycle: run-scan, exit 0=clean / 1=needs attention
├── notify-cycle.sh   # scan + native desktop notification (no-Claude path)
├── report.sh         # deterministic triage report (bumblebee + all lenses; no AI)
├── honey-baseline.sh # manage the pin-and-diff suppression baseline (add/list/remove/prune/status)
├── honey.baseline.json # the suppression baseline (committed & reviewable; NOT gitignored)
├── install-schedule.sh # schedule notify-cycle via launchd (macOS) / cron (Linux)
├── lib/baseline.sh   # shared suppression classifier (sourced by report/daily-cycle/CLI)
├── lenses/           # optional additional scanners, each self-skips if its tool is absent
│   ├── skillspector.sh  # AI agent skills (NVIDIA SkillSpector)
│   ├── osv-scanner.sh   # multi-ecosystem lockfile vulns (Google/OSV)
│   └── govulncheck.sh   # Go reachability-aware vulns (Go vuln team)
├── docs/BASELINE.plan.md # suppression baseline design + threat model
├── routine-prompt.md # prompt for the Claude Local routine (scheduled path)
├── triage-guide.md   # guide for triaging a run by hand in a chat
├── win/              # native Windows (PowerShell 7) port — mirrors every script above
├── runs/<TS>/        # one timestamped run per scan (gitignored — host inventory)
│   ├── manifest.json      # bumblebee verdict + metadata
│   ├── findings.ndjson    # bumblebee finding records
│   └── lens-<name>.json   # each active lens's normalized findings
└── latest -> runs/…  # symlink to the most recent run (gitignored)
```

`runs/`, `latest`, and `*.log` are **gitignored** — they contain an inventory
of your machine and should never be published. `honey.baseline.json` is
deliberately **not** gitignored: suppression pins are meant to be reviewed in
version control.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Anything unexpected | `./doctor.sh` — it pinpoints the cause |
| `command not found: bumblebee` | Go's bin dir isn't on `PATH`; `doctor.sh` prints the `export PATH=…` line to add |
| Scan finds nothing even when it should | Usually a missing/stale catalog checkout — `./setup.sh` re-clones/updates it |
| `jq not found` | `brew install jq` (macOS) / `sudo apt-get install jq` (Debian/Ubuntu) |
| `go` build fails | Need Go 1.25+; upgrade from <https://go.dev/dl/> |
| Status `incomplete` | Scan hit the time cap; raise `BUMBLEBEE_MAX_DURATION` or narrow `BUMBLEBEE_SCAN_ROOT` |

## Acknowledgements

honey is a thin wrapper. The actual scanning engine and all threat
intelligence are the work of **[Perplexity](https://www.perplexity.ai)**:

- **[bumblebee](https://github.com/perplexityai/bumblebee)** — the read-only
  inventory collector and exposure scanner honey drives. Every detection,
  every ecosystem parser, the scan profiles, and the record schema are
  bumblebee's.
- **[threat_intel catalogs](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)**
  — the maintained exposure catalogs of recent supply-chain campaigns that
  honey matches against, assembled by Perplexity from public
  threat-intelligence reporting and updated via PRs.

Both are published by Perplexity under the Apache License 2.0. honey adds only
the update→scan→report loop, scheduling, and reporting around them. If honey
is useful to you, the credit for the hard part belongs upstream — please star
and follow [bumblebee](https://github.com/perplexityai/bumblebee).

The optional [lenses](#lenses--additional-scanners-optional) wrap further
upstream tools — honey installs none of them automatically and redistributes
no code; each lens is inert unless you install its tool yourself:

- **[NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)** (Apache 2.0)
  — all AI-agent-skill vulnerability detection in the `skillspector` lens.
- **[osv-scanner](https://github.com/google/osv-scanner)** by Google / the
  OSV-Scanner authors (Apache 2.0) — all multi-ecosystem lockfile vulnerability
  detection in the `osv-scanner` lens.
- **[govulncheck](https://golang.org/x/vuln)** by the Go Authors (BSD-style)
  — all Go reachability-aware vulnerability detection in the `govulncheck` lens.

All detection capability and vulnerability data are the work of these upstream
projects. See [NOTICE](NOTICE) for full attribution.

## License

honey is licensed under [Apache 2.0](LICENSE). It depends on, but does not
include, [bumblebee](https://github.com/perplexityai/bumblebee) and its
threat_intel catalogs, which are independently licensed by Perplexity under
Apache 2.0. See [NOTICE](NOTICE) for attribution.
