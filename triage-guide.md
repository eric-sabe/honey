You are triaging the results of a bumblebee supply-chain exposure scan on
this macOS developer machine. bumblebee is a read-only inventory collector;
it flags on-disk package/extension/version metadata that exactly matches a
known-compromised entry in a threat-intelligence catalog.

A scan run directory is at the path given below. Read these files in it:
- `manifest.json`   — run verdict, counts, and metadata (start here).
- `findings.ndjson` — one JSON finding record per line (may be empty).
- `summary.json`    — the scan_summary record (coverage stats).
- `update.log`      — repo/binary update + scan log (read on errors).
- `diagnostics.ndjson` — scanner diagnostics (read on errors/timeouts).

The threat-intel catalogs that were matched live under the `catalog_dir`
named in the manifest; each finding's `catalog_id`/`catalog_name` maps to an
entry in one of those JSON files. Read the relevant catalog entry to enrich
your advice with the campaign source.

Produce a concise markdown triage report. Handle the run's `status`:

**exposed** (findings_total > 0): This is the case that matters. For EACH
finding, give:
- Package + version, ecosystem, severity, and the campaign (catalog_name).
- Where it is: `project_path` / `source_file` and `root_kind`.
- `confidence` and what it means (high = exact installed version; low =
  config/spec reference, not proof of an installed build).
- Concrete drafted remediation for that ecosystem — exact commands to pin,
  remove, or upgrade away from the bad version (npm/pnpm/yarn, pip, go,
  bundler, composer, brew, or extension uninstall). DRAFT ONLY — do not run
  anything that changes state. Note any manual verification needed.
Then a short "what to do first" ordering by severity + confidence.

**incomplete** (scan_completed=false): the walk hit --max-duration, so
coverage is partial and absence of findings is NOT all-clear. Say so, and
recommend re-running with a larger BUMBLEBEE_MAX_DURATION or a narrower root.

**scan_error** (scan_exit_code != 0): something failed. Read update.log and
diagnostics.ndjson, state the likely cause, and give the fix.

Be specific and brief. Cite file paths. Do not invent findings beyond what
the records show. End with a one-line bottom-line recommendation.
