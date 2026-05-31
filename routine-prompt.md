# Local routine prompt

Paste this into a Claude Code **Local** routine (Routines hub → New routine →
Local), scheduled daily. It runs the scan and DMs the analysis to Slack via
your connected Slack integration. Adjust the `honey` path if you cloned
elsewhere.

```
Run the daily honey bumblebee supply-chain exposure cycle on this machine,
then DM me the results in Slack.

STEP 1 — SCAN. Run this script (it updates the threat-intel catalogs + the
bumblebee binary, then deep-scans my home directory):

    ~/git/honey/daily-cycle.sh

It exits 1 when the run needs attention (exposed / incomplete / scan_error) —
that nonzero exit is EXPECTED, not a failure. The newest run is symlinked at
~/git/honey/latest. If that symlink is missing, read ~/git/honey/cycle.log,
report why, and stop.

STEP 2 — READ THE VERDICT. Read ~/git/honey/latest/manifest.json and branch
on `status`:

  • clean — DM me one line: "Bumblebee all clear on <host> — scanned
    <scan_root> (<files_considered from summary.json> files), no exposure
    matches." Then stop.

  • exposed — read ~/git/honey/latest/findings.ndjson (one finding per line).
    For EACH finding include: package + version, ecosystem, severity, campaign
    (catalog_name); location (source_file, root_kind); confidence and what it
    means (high = exact installed version; low = config/spec reference, not
    proof of an installed build); and drafted remediation — the exact
    command(s) to pin/remove/upgrade away from the bad version for that
    ecosystem (npm/pnpm/yarn, pip, go, bundler, composer, brew, or extension
    uninstall), labeled "run manually". Enrich each finding from its matched
    catalog entry under the manifest's catalog_dir (the finding's catalog_id
    maps to an entry there). End with a "do first" line ordered by severity
    then confidence.

  • incomplete (scan_completed=false) — the walk hit --max-duration, so
    coverage is partial and absence of matches is NOT all-clear. Say so and
    suggest re-running with a larger BUMBLEBEE_MAX_DURATION.

  • scan_error (scan_exit_code != 0) — read cycle.log and
    ~/git/honey/latest/diagnostics.ndjson, give the likely cause and fix.

STEP 3 — DELIVER. Send the write-up as a Slack DM to me. Use Slack mrkdwn
formatting (*bold*, `code`, • bullets). Do not modify files or run
state-changing commands beyond daily-cycle.sh in step 1. Be specific, cite
the run dir path once, and don't invent findings beyond the records.
```
