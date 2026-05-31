#!/usr/bin/env bash
#
# honey/daily-cycle.sh — orchestrates one exposure-scan cycle.
#
#   run-scan.sh : update repo + binary, deep-scan $HOME, write manifest.
#
# This script only collects data (bumblebee is read-only and needs no auth).
# It does not notify or triage. A Claude Local routine runs this, reads the
# results from honey/latest/, and DMs the analysis to Slack — see README.md.
#
# Exit codes (so callers can branch without re-reading state):
#   0 — clean (scan completed, no matches)
#   1 — needs attention: a fresh run with status exposed/incomplete/scan_error
#   2 — cycle failure: no fresh manifest (run-scan didn't complete, or `latest`
#       is stale). Distinct from 1 so a notifier never treats stale data as a
#       real verdict.

set -uo pipefail

HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
CYCLE_LOG="$HONEY/cycle.log"

clog() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$CYCLE_LOG"; }

clog "=== cycle start ==="

# Stamp the cycle start in the same sortable UTC form run-scan uses for run_id.
# After the scan we require manifest.run_id >= this, so an interrupted run that
# left a STALE `latest` (pointing at a previous run) can't be mistaken for a
# fresh result — a false "all clear" is the worst failure for a security tool.
CYCLE_START="$(date -u +%Y%m%dT%H%M%SZ)"

# ---- Scan ------------------------------------------------------------------
"$HONEY/run-scan.sh" >>"$CYCLE_LOG" 2>&1
SCAN_RC=$?
clog "run-scan.sh exit: $SCAN_RC"

RUN_DIR="$(readlink "$HONEY/latest" 2>/dev/null || echo "")"
MANIFEST="$RUN_DIR/manifest.json"
if [ -z "$RUN_DIR" ] || [ ! -f "$MANIFEST" ]; then
  clog "ERROR no manifest after scan; aborting cycle (run-scan exit $SCAN_RC)"
  exit 2
fi

# Freshness guard: the manifest must be from this cycle, not a stale `latest`.
RUN_ID="$(jq -r '.run_id // empty' "$MANIFEST" 2>/dev/null)"
if [ -z "$RUN_ID" ] || [ "$RUN_ID" \< "$CYCLE_START" ]; then
  clog "ERROR latest run ($RUN_ID) predates this cycle ($CYCLE_START) — run-scan did not complete; treating as failure"
  exit 2
fi

STATUS="$(jq -r '.status' "$MANIFEST" 2>/dev/null)"
TOTAL="$(jq -r '.findings_total' "$MANIFEST" 2>/dev/null)"
clog "manifest status=$STATUS findings=$TOTAL run_dir=$RUN_DIR"

clog "=== cycle end (status=$STATUS) ==="
# 0 when clean; 1 when the run needs attention, for the caller to branch on.
[ "$STATUS" = "clean" ] && exit 0 || exit 1
