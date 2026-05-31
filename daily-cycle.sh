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
# Exit code: 0 when clean, 1 when the run needs attention (exposed /
# incomplete / scan_error) so the caller can branch on it.

set -uo pipefail

HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
CYCLE_LOG="$HONEY/cycle.log"

clog() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$CYCLE_LOG"; }

clog "=== cycle start ==="

# ---- Scan ------------------------------------------------------------------
"$HONEY/run-scan.sh" >>"$CYCLE_LOG" 2>&1
clog "run-scan.sh exit: $?"

RUN_DIR="$(readlink "$HONEY/latest" 2>/dev/null || echo "")"
MANIFEST="$RUN_DIR/manifest.json"
if [ -z "$RUN_DIR" ] || [ ! -f "$MANIFEST" ]; then
  clog "ERROR no manifest after scan; aborting cycle"
  exit 1
fi

STATUS="$(jq -r '.status' "$MANIFEST" 2>/dev/null)"
TOTAL="$(jq -r '.findings_total' "$MANIFEST" 2>/dev/null)"
clog "manifest status=$STATUS findings=$TOTAL run_dir=$RUN_DIR"

clog "=== cycle end (status=$STATUS) ==="
# 0 when clean; 1 when the run needs attention, for the caller to branch on.
[ "$STATUS" = "clean" ] && exit 0 || exit 1
