# Local routine prompt

Paste this into a Claude Code **Local** routine (Routines hub → New routine →
**Local**), scheduled daily. It runs honey's multi-scanner security sweep and
DMs you a triage write-up in Slack via your connected Slack integration.

**Before pasting:** replace `HONEY_DIR` below with the absolute path to your
honey checkout (e.g. `/Users/you/git/honey` or `~/git/honey`). It appears a
few times — set it once consistently.

```
Run honey's daily supply-chain security sweep on this machine, then DM me a
triage write-up in Slack. honey is at HONEY_DIR.

honey orchestrates several read-only security scanners and merges them into one
verdict — you don't need to know their internals, just surface what they find:
  • bumblebee   — installed packages/extensions matching known-compromised
                  supply-chain campaigns (the core scanner)
  • osv-scanner — known CVEs in project lockfiles across all ecosystems
  • govulncheck — Go vulnerabilities the code actually calls (reachable)
  • skillspector— malicious/risky patterns in installed AI agent skills
The vuln/skill scanners are optional "lenses" that only run if their tool is
installed; whichever are active contribute to the same verdict.

STEP 1 — SCAN. Run:

    HONEY_DIR/daily-cycle.sh

This refreshes each scanner and its data, then runs them: bumblebee over my
home directory, the lenses over my projects and agent skills. It exits 1 when
the run needs attention (exposed / incomplete / scan_error) — that nonzero exit
is EXPECTED, not a failure. The newest run is symlinked at HONEY_DIR/latest. If
that symlink is missing afterward, read HONEY_DIR/cycle.log, report why in
Slack, and stop.

STEP 2 — GET THE FACTS. Run the deterministic report generator:

    HONEY_DIR/report.sh

THE VERDICT IS THE `OVERALL:` LINE THAT report.sh PRINTS — nothing else. It is
the worst status across bumblebee AND every active lens (osv-scanner,
govulncheck, skillspector). report.sh also exits 0 only when OVERALL is clean,
1 otherwise.

CRITICAL — do not produce a false all-clear:
  • Use ONLY the OVERALL line for the verdict. Do NOT read the verdict from
    manifest.json — that is bumblebee ALONE and is `clean` even when a lens
    found exposures. (This is the #1 mistake; the manifest is one scanner, not
    the verdict.)
  • You may report "all clear" ONLY if report.sh prints `OVERALL: CLEAN`. If it
    prints `OVERALL: EXPOSED` (or INCOMPLETE / SCAN_ERROR), the run is NOT
    clear — even if bumblebee itself was clean.

SUPPRESSION BASELINE — the OVERALL line may carry a tally, e.g.
`OVERALL: CLEAN (12 suppressed)` or `OVERALL: EXPOSED — … (12 suppressed, 2 mutated)`:
  • `suppressed` = findings the user reviewed and pinned as benign in
    honey.baseline.json; they are intentionally dropped from the verdict. Do NOT
    re-alarm on them — mention the count in passing, nothing more.
  • `mutated` = a file that was pinned reviewed-benign has CHANGED since it was
    pinned (marked 🔁 MUTATED in the report). Treat this as HIGH signal — a
    possible rug pull / tampered dependency — surface it prominently and never
    fold it into "all clear". A run with any `mutated` is never CLEAN.
  • `expired` = a pin passed its expiry and resurfaced; treat as a normal active
    finding due for re-review.
  • `review` = active findings held BELOW the severity floor (verdict policy) —
    typically first-party / trusted-marketplace low/medium noise. They are
    reported but non-blocking. Summarize them briefly ("N low-severity first-party
    findings, non-blocking"); do not treat them as urgent. A run whose only
    findings are `review` is CLEAN.
  • `CLEAN (N suppressed)` / `CLEAN (N review)` is still all-clear — but name the
    counts ("all clear; N previously reviewed / N below-floor findings"), not a
    bare "all clear".

Treat report.sh's output as the factual baseline; do not contradict it or
invent findings beyond it. For extra detail read HONEY_DIR/latest/lens-*.json
(each lens's normalized findings: severity, title, location, detail, ref) and,
for bumblebee specifically, manifest.json + findings.ndjson. Surface EVERY
scanner's findings, not just bumblebee's.

STEP 3 — ENRICH. Add judgment a static report can't, per scanner:
  • bumblebee: note whether source_type / root_kind suggests a direct vs.
    transitive/incidental dependency; tailor remediation to the project's
    lockfile/manager when project_path is real; reconcile confidence — a "low"
    config-only match warrants a softer call to action than a "high" exact
    version hit.
  • osv-scanner (CVEs): lead with the worst CVSS; note that a known CVE in a
    dependency may or may not be reachable — recommend upgrading to the fixed
    version, and flag where govulncheck (if present) can confirm reachability.
  • govulncheck (Go): these are REACHABLE by definition — your code calls the
    vulnerable path, so treat them as higher urgency than an equivalent
    osv-scanner-only hit; cite the fixed version from the detail.
  • skillspector (agent skills): explain the risk in plain terms (e.g. prompt
    injection, data exfiltration, excessive agency) and which skill/file; an
    untrusted or recently-installed skill flagged here deserves prompt review.
  • If the run is `incomplete`, stress that absence of matches is NOT all-clear
    and recommend re-running with a larger BUMBLEBEE_MAX_DURATION.
  • If any scanner is `scan_error`, give the most likely cause and the fix from
    the log — and note that its surface went UNSCANNED this run.
Keep remediation labeled "run manually" — never run state-changing commands.

STEP 4 — DELIVER. Send the result as a Slack DM to me, in Slack mrkdwn
(*bold*, `code`, • bullets). Lead with the OVERALL status from STEP 2.
  • OVERALL: CLEAN → a one-line all-clear is enough (and only then).
  • OVERALL: EXPOSED → lead with which scanners fired and their counts, then
    list findings worst-severity first, and end with a "do first" ordering by
    severity then confidence. Never call an EXPOSED run "all clear".
  • OVERALL: INCOMPLETE / SCAN_ERROR → say so plainly and name the affected
    scanner(s); partial coverage is not a clean result.
Cite the run dir path once. Do not modify files or run anything that changes
state beyond daily-cycle.sh and report.sh above.
```

The deterministic baseline lives in [`report.sh`](report.sh) and the analysis
conventions in [`triage-guide.md`](triage-guide.md); this prompt layers
tailored judgment and Slack delivery on top of them.
