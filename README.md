# honey

Local, automated supply-chain exposure checks using
[bumblebee](https://github.com/perplexityai/bumblebee) + its `threat_intel/`
catalogs. A Claude Code **Local routine** runs the scan daily, then DMs the
analysis to Slack.

bumblebee is a read-only inventory collector: it flags on-disk
package/extension/version metadata that exactly matches a known-compromised
entry in a threat-intelligence catalog. honey wraps it in an
update → scan → report loop and hands the results to Claude for triage.

## How it's wired

A Local routine (Routines hub → New routine → **Local**) runs on your machine
with your Claude auth and connectors. Each day it:

1. runs `daily-cycle.sh` — updates the catalogs + binary, deep-scans `$HOME`,
   writes a timestamped run under `runs/`, and
2. reads the verdict from `latest/` and **DMs the result to you in Slack** via
   the connected Slack integration.

Because it's a *Local* routine it can see your real filesystem (so the scan is
meaningful) and reuse your Slack connector (no webhook or bot token needed).
The routine prompt is in [`routine-prompt.md`](routine-prompt.md); the
analysis instructions are in [`triage-guide.md`](triage-guide.md).

## Prerequisites

- macOS or Linux, `bash`, `git`, [`jq`](https://jqlang.org), and
  [Go](https://go.dev) 1.25+ (for `go install`).
- A local checkout of [bumblebee](https://github.com/perplexityai/bumblebee).
  Point honey at it with `BUMBLEBEE_REPO` (default: `$HOME/git/bumblebee`).
- The bumblebee binary on your `PATH` (`go install
  github.com/perplexityai/bumblebee/cmd/bumblebee@latest`).

## Layout

```
honey/
├── run-scan.sh       # update repo+binary, deep-scan $HOME, write a run + manifest
├── daily-cycle.sh    # one cycle: run-scan, exit 0=clean / 1=needs attention. Data only.
├── routine-prompt.md # the prompt for the Claude Local routine
├── triage-guide.md   # the analysis instructions the routine follows
├── runs/<TS>/        # one timestamped run per scan (gitignored — machine inventory)
│   ├── records.ndjson      # raw scan stdout (findings + scan_summary)
│   ├── findings.ndjson     # finding records only (empty = no matches)
│   ├── summary.json        # the scan_summary record
│   ├── diagnostics.ndjson  # scanner stderr diagnostics
│   ├── manifest.json       # run verdict + metadata
│   └── update.log          # git pull + go install + scan log
└── latest -> runs/<newest> # symlink to the most recent run (gitignored)
```

Results live **outside** the bumblebee checkout and `~/go`, so neither
`git pull` nor `go install` can delete them. `runs/`, `latest`, and `*.log`
are gitignored — they contain a host inventory and should never be published.

## What a cycle does

1. `git pull --ff-only` the bumblebee checkout (fresh `threat_intel/`
   catalogs, which arrive via PR upstream).
2. `go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest`.
3. `bumblebee scan --profile deep --root $HOME --exposure-catalog <repo>/threat_intel
   --findings-only` → write the run dir + `manifest.json`.
4. `daily-cycle.sh` exits `0` when `status` is `clean`, `1` otherwise.

## manifest `status` values

- `clean`      — scan completed, no matches.
- `exposed`    — one or more catalog matches.
- `incomplete` — hit `--max-duration`; coverage partial, NOT all-clear.
- `scan_error` — scan failed; see `cycle.log` / `diagnostics.ndjson`.

## Run manually

```sh
# Full cycle (scans $HOME, writes a run):
./daily-cycle.sh

# Just the scan:
./run-scan.sh

# Override the scan root or time budget:
BUMBLEBEE_SCAN_ROOT="$HOME/git" BUMBLEBEE_MAX_DURATION=20m ./run-scan.sh
```

After a run, read `latest/manifest.json` for the verdict.

## Configuration (env vars, all optional)

| Var | Default |
|---|---|
| `HONEY` | the directory containing the scripts |
| `BUMBLEBEE_REPO` | `$HOME/git/bumblebee` |
| `BUMBLEBEE_SCAN_ROOT` | `$HOME` |
| `BUMBLEBEE_MAX_DURATION` | `30m` |
