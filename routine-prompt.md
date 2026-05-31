# Local routine prompt

Paste this into a Claude Code **Local** routine (Routines hub → New routine →
**Local**), scheduled daily. It runs the scan and DMs you a triage write-up in
Slack via your connected Slack integration.

**Before pasting:** replace `HONEY_DIR` below with the absolute path to your
honey checkout (e.g. `/Users/you/git/honey` or `~/git/honey`). It appears a
few times — set it once consistently.

```
Run the daily honey bumblebee supply-chain exposure cycle on this machine,
then DM me a triage write-up in Slack. honey is at HONEY_DIR.

STEP 1 — SCAN. Run:

    HONEY_DIR/daily-cycle.sh

This updates the threat-intel catalogs + bumblebee binary, then deep-scans my
home directory. It exits 1 when the run needs attention (exposed / incomplete
/ scan_error) — that nonzero exit is EXPECTED, not a failure. The newest run
is symlinked at HONEY_DIR/latest. If that symlink is missing afterward, read
HONEY_DIR/cycle.log, report why in Slack, and stop.

STEP 2 — GET THE FACTS. Run the deterministic report generator:

    HONEY_DIR/report.sh

It prints the OVERALL verdict plus a section per scanner: bumblebee (package /
catalog matches) and any active lenses (e.g. skillspector for AI agent skills).
Treat its output as the factual baseline; do not contradict it or invent
findings beyond it. For extra detail read HONEY_DIR/latest/manifest.json and
findings.ndjson (bumblebee), and HONEY_DIR/latest/lens-*.json (each lens's
normalized findings: severity, title, location, detail, ref). The overall
verdict is the worst across all scanners — surface every scanner's findings,
not just bumblebee's.

STEP 3 — ENRICH. Add judgment that a static report can't:
  • For each finding, note whether source_type / root_kind suggests a direct
    dependency vs. a transitive/incidental one, and weight urgency accordingly.
  • If a finding is in a real project (project_path), tailor the remediation to
    that project's lockfile/manager rather than the generic command.
  • Reconcile confidence: a "low" confidence config-only match deserves a
    softer call to action than a "high" exact-version hit. Say so plainly.
  • If the run is `incomplete`, stress that absence of matches is NOT all-clear
    and recommend re-running with a larger BUMBLEBEE_MAX_DURATION.
  • If `scan_error`, give the most likely cause and the fix from the log.
Keep remediation labeled "run manually" — never run state-changing commands.

STEP 4 — DELIVER. Send the result as a Slack DM to me, in Slack mrkdwn
(*bold*, `code`, • bullets). Lead with one status line. On a clean run, one
line is enough. On an exposed run, list findings worst-severity first and end
with a "do first" ordering by severity then confidence. Cite the run dir path
once. Do not modify files or run anything that changes state beyond
daily-cycle.sh and report.sh above.
```

The deterministic baseline lives in [`report.sh`](report.sh) and the analysis
conventions in [`triage-guide.md`](triage-guide.md); this prompt layers
tailored judgment and Slack delivery on top of them.
