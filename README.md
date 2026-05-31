# honey

[![ci](https://github.com/eric-sabe/honey/actions/workflows/ci.yml/badge.svg)](https://github.com/eric-sabe/honey/actions/workflows/ci.yml)

honey turns [bumblebee](https://github.com/perplexityai/bumblebee) into a
hands-off supply-chain watchdog for your dev machine. bumblebee is a
read-only inventory collector: it flags on-disk package/extension/version
metadata that exactly matches a known-compromised entry in a
threat-intelligence catalog. honey wraps it in an
**update → scan → report** loop, and (optionally) has Claude DM you a triage
write-up in Slack each day.

> **Credit:** the heavy lifting is [Perplexity](https://www.perplexity.ai)'s.
> [**bumblebee**](https://github.com/perplexityai/bumblebee) (the scanner) and
> its [**threat_intel**](https://github.com/perplexityai/bumblebee/tree/main/threat_intel)
> exposure catalogs are published and maintained by Perplexity under
> Apache 2.0. honey is just a thin scheduling/reporting wrapper around them —
> all detection capability and threat data come from bumblebee. See
> [Acknowledgements](#acknowledgements).

You can use honey two ways:

- **As a plain scanner** — run one command, read the verdict. No Claude, no
  Slack, no scheduler required.
- **As a daily routine** — a Claude Code *Local* routine runs the scan on a
  schedule and DMs the analysis to Slack. (Optional, see below.)

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

`bash`, `git`, [`jq`](https://jqlang.org), and [Go](https://go.dev) **1.25+**
(bumblebee needs 1.25+). macOS or Linux. `setup.sh` checks all of these and
tells you the install command for anything you're missing — it won't guess
your package manager.

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
| `osv-scanner` | [Google/OSV osv-scanner](https://github.com/google/osv-scanner) | Known vulns in lockfiles/manifests across **all** ecosystems (npm, pypi, cargo, go, …) | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| `govulncheck` | [Go vuln team govulncheck](https://golang.org/x/vuln) | Go vulns that your code **actually calls** (reachability-aware → far less noise) | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

**What each answers.** bumblebee: *"do I have a known-compromised package?"*
(exact catalog match). skillspector: *"is this agent skill behaving
maliciously?"* (content analysis). osv-scanner: *"do my dependencies have known
CVEs?"* (broad). govulncheck: *"do I actually reach a vulnerable Go function?"*
(deep, low-noise). Together they cover reactive, proactive, breadth, and depth.

**Where the vuln lenses scan.** osv-scanner and govulncheck scan your *project*
directories, not all of `$HOME`. Set `HONEY_PROJECT_ROOTS` (colon-separated;
default `~/git:~/code:~/Developer:~/src`) to control this. The skillspector
lens scans skill dirs under `~/.claude` (override with `HONEY_SKILL_ROOTS`).

**Go division of labor.** osv-scanner and govulncheck overlap on Go. By
default osv-scanner **defers Go stdlib advisories to govulncheck** — otherwise
it flags every stdlib CVE for your `go` directive (often dozens, unreachable,
no CVSS). govulncheck reports only the stdlib vulns you actually call. Set
`HONEY_OSV_INCLUDE_GO_STDLIB=1` to keep them in osv-scanner anyway.

Both vuln lenses run static DB lookups (osv-scanner → OSV.dev with
`HONEY_OSV_OFFLINE=1` for local DBs; govulncheck → vuln.go.dev). skillspector
runs static (`--no-llm`) by default — honey's Claude routine is the semantic
layer; set `HONEY_SKILLSPECTOR_LLM=1` to use SkillSpector's own LLM stage.

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
- The vuln lenses default to scanning `~/git:~/code:~/Developer:~/src`. If your
  projects live elsewhere, add a line to the routine prompt before STEP 1, e.g.
  `Set HONEY_PROJECT_ROOTS=/my/projects:/other before running the scripts.`
  (A Local routine does not inherit env vars from your shell.)

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

| Var | Default | Purpose |
|---|---|---|
| `HONEY` | the scripts' own directory | where runs are written |
| `BUMBLEBEE_REPO` | `$HOME/git/bumblebee` | bumblebee checkout (for catalogs) |
| `BUMBLEBEE_SCAN_ROOT` | `$HOME` | what bumblebee scans |
| `BUMBLEBEE_MAX_DURATION` | `30m` | bumblebee scan time cap |
| `HONEY_PROJECT_ROOTS` | `~/git:~/code:~/Developer:~/src` | where the vuln lenses (osv-scanner, govulncheck) look for projects |
| `HONEY_SKILL_ROOTS` | skill dirs under `~/.claude` | where the skillspector lens looks for agent skills |
| `HONEY_OSV_OFFLINE` | `0` | osv-scanner: use local vuln DBs instead of OSV.dev |
| `HONEY_OSV_INCLUDE_GO_STDLIB` | `0` | osv-scanner: keep Go stdlib advisories (default defers them to govulncheck) |
| `HONEY_SKILLSPECTOR_LLM` | `0` | skillspector: enable its own LLM stage (default static `--no-llm`) |

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
├── install-schedule.sh # schedule notify-cycle via launchd (macOS) / cron (Linux)
├── lenses/           # optional additional scanners, each self-skips if its tool is absent
│   ├── skillspector.sh  # AI agent skills (NVIDIA SkillSpector)
│   ├── osv-scanner.sh   # multi-ecosystem lockfile vulns (Google/OSV)
│   └── govulncheck.sh   # Go reachability-aware vulns (Go vuln team)
├── routine-prompt.md # prompt for the Claude Local routine (scheduled path)
├── triage-guide.md   # guide for triaging a run by hand in a chat
├── runs/<TS>/        # one timestamped run per scan (gitignored — host inventory)
│   ├── manifest.json      # bumblebee verdict + metadata
│   ├── findings.ndjson    # bumblebee finding records
│   └── lens-<name>.json   # each active lens's normalized findings
└── latest -> runs/…  # symlink to the most recent run (gitignored)
```

`runs/`, `latest`, and `*.log` are **gitignored** — they contain an inventory
of your machine and should never be published.

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

## License

honey is licensed under [Apache 2.0](LICENSE). It depends on, but does not
include, [bumblebee](https://github.com/perplexityai/bumblebee) and its
threat_intel catalogs, which are independently licensed by Perplexity under
Apache 2.0. See [NOTICE](NOTICE) for attribution.
