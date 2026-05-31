# honey

honey turns [bumblebee](https://github.com/perplexityai/bumblebee) into a
hands-off supply-chain watchdog for your dev machine. bumblebee is a
read-only inventory collector: it flags on-disk package/extension/version
metadata that exactly matches a known-compromised entry in a
threat-intelligence catalog. honey wraps it in an
**update → scan → report** loop, and (optionally) has Claude DM you a triage
write-up in Slack each day.

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

## Optional: daily Slack triage via a Claude Local routine

If you use [Claude Code](https://claude.com/claude-code) and have the Slack
connector enabled, you can have the whole thing run daily and DM you the
analysis — no extra credentials, because a *Local* routine reuses your own
Claude auth and connectors.

1. In the Routines hub: **New routine → Local**.
2. Paste the prompt from [`routine-prompt.md`](routine-prompt.md) (it runs
   `daily-cycle.sh`, reads the verdict, and DMs you the result).
3. Set the schedule (e.g. daily at noon).

The routine follows the analysis instructions in
[`triage-guide.md`](triage-guide.md). On a clean run you get a one-line
all-clear; on an `exposed` run you get per-finding triage with drafted
remediation. Because it's *Local*, it can see your real filesystem (so the
scan is meaningful) — a *Remote* cloud routine cannot, and would always
report clean.

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
├── routine-prompt.md # prompt for the Claude Local routine (optional path)
├── triage-guide.md   # analysis instructions the routine follows
├── runs/<TS>/        # one timestamped run per scan (gitignored — host inventory)
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

## License

[Apache 2.0](LICENSE).
