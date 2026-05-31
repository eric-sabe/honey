# Triage guide (interactive)

Use this to triage a honey scan by hand in a Claude chat — e.g. "triage the
latest honey run". The scheduled Local routine uses its own prompt
([`routine-prompt.md`](routine-prompt.md)); this is the conversational
equivalent. All three paths share one factual baseline: [`report.sh`](report.sh).

---

Triage a bumblebee supply-chain exposure scan. bumblebee is a read-only
inventory collector; it flags on-disk package/extension/version metadata that
exactly matches a known-compromised entry in a threat-intelligence catalog.

1. Get the facts. Run `./report.sh [RUN_DIR]` (defaults to the `latest`
   symlink). It prints the verdict, coverage, and — when exposed — every match
   grouped by severity with location, confidence, and standard per-ecosystem
   remediation. Treat this as ground truth; don't contradict it or invent
   findings beyond it.

2. For detail beyond the report, read the run dir:
   - `manifest.json`   — verdict, counts, metadata.
   - `findings.ndjson` — one finding per line.
   - `summary.json`    — coverage stats.
   - `update.log` / `diagnostics.ndjson` — read on errors/timeouts.
   Each finding's `catalog_id` maps to an entry under the manifest's
   `catalog_dir`; read it to cite the campaign source.

3. Enrich beyond the static report:
   - Weigh `source_type` / `root_kind` — direct dependency vs. transitive or
     incidental — and adjust urgency.
   - If a finding is in a real project (`project_path`), tailor remediation to
     that project's lockfile/manager rather than the generic command.
   - Reconcile `confidence`: `high` = exact installed version (act); `low` =
     config/spec reference, not proof of an installed build (verify first).
   - `incomplete` (scan_completed=false): coverage is partial — absence of
     matches is NOT all-clear. Recommend a larger `BUMBLEBEE_MAX_DURATION` or
     narrower root.
   - `scan_error`: read the logs, state the likely cause and the fix.

Keep remediation labeled "run manually" — never run state-changing commands.
Be specific, cite file paths, and end with a one-line bottom-line
recommendation ordered by severity then confidence.
