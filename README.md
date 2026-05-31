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
./setup.sh        # clones bumblebee, installs the binary, verifies everything
./daily-cycle.sh  # run a scan; read runs/latest/manifest.json for the verdict
```

`setup.sh` is idempotent and ends by running `./doctor.sh`, which prints a
✓/✗ line for every dependency with exact fix-it commands for anything
missing. If a scan ever misbehaves, run `./doctor.sh` first.

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

### Bundled lens: `skillspector` (AI agent skills)

[NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) scans installed
AI agent skills (`SKILL.md` + bundled scripts, as loaded by Claude Code, Codex,
Gemini CLI, etc.) for prompt injection, data exfiltration, excessive agency,
tool poisoning, and other agent-specific risks — a surface bumblebee's
package/catalog model doesn't cover. honey complements it: bumblebee answers
*"do I have a known-compromised package?"*, skillspector answers *"is this
skill, which no catalog knows yet, behaving maliciously?"*

This lens is **opt-in** and adds no dependency unless you install SkillSpector
yourself (it needs Python 3.12+; honey never installs it for you). Once
`skillspector` is on your `PATH`, the lens activates automatically and scans
the skill directories under `~/.claude` (override with `HONEY_SKILL_ROOTS`, a
colon-separated list). It runs SkillSpector's **static analysis** (`--no-llm`)
by default — deterministic, no API keys; honey's own Claude routine is the
semantic layer. Set `HONEY_SKILLSPECTOR_LLM=1` to enable SkillSpector's LLM
stage instead.

`./doctor.sh` shows which lenses are active. A lens being inactive never fails
the core checks.

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
./doctor.sh                      # health check — run this if anything's off
./run-scan.sh                    # just the scan (no cycle wrapper)
./daily-cycle.sh                 # scan + verdict

# Narrow the scan or change the time budget:
BUMBLEBEE_SCAN_ROOT="$HOME/code" BUMBLEBEE_MAX_DURATION=20m ./run-scan.sh
```

After any run, `runs/latest/manifest.json` has the verdict and
`runs/latest/findings.ndjson` has any matches.

## Configuration (env vars, all optional)

| Var | Default | Purpose |
|---|---|---|
| `HONEY` | the scripts' own directory | where runs are written |
| `BUMBLEBEE_REPO` | `$HOME/git/bumblebee` | bumblebee checkout (for catalogs) |
| `BUMBLEBEE_SCAN_ROOT` | `$HOME` | what to scan |
| `BUMBLEBEE_MAX_DURATION` | `30m` | scan time cap |

## Layout

```
honey/
├── setup.sh          # one-command setup: clone bumblebee, install binary, verify
├── doctor.sh         # dependency health check with fix-it hints
├── lib/preflight.sh  # shared dependency checks (sourced by the above)
├── run-scan.sh       # update repo+binary, deep-scan, write a run + manifest
├── daily-cycle.sh    # one cycle: run-scan, exit 0=clean / 1=needs attention
├── notify-cycle.sh   # scan + native desktop notification (no-Claude path)
├── report.sh         # deterministic triage report (bumblebee + all lenses; no AI)
├── install-schedule.sh # schedule notify-cycle via launchd (macOS) / cron (Linux)
├── lenses/           # optional additional scanners (e.g. skillspector.sh)
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
