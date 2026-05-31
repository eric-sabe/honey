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

# Load persisted config (e.g. non-default BUMBLEBEE_REPO / HONEY_PROJECT_ROOTS)
# so a bare-env Local routine or cron job picks it up. env var > honey.conf > default.
# shellcheck source=lib/load-config.sh
. "$HONEY/lib/load-config.sh"

# A scheduler / Local routine may hand us a bare PATH. Ensure the dirs that
# hold the scanners are findable BEFORE we invoke run-scan and the lenses —
# otherwise an installed lens (osv-scanner/govulncheck in ~/go/bin,
# skillspector in ~/.local/bin) would silently self-skip as "not installed",
# a false "lens inactive". Mirrors run-scan.sh's PATH plus ~/.local/bin.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

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

# ---- Additional lenses -----------------------------------------------------
# bumblebee (above) is the canonical lens; its status/manifest are untouched.
# Optional lenses in lenses/*.sh run next, each writing lens-<name>.json into
# the run dir (normalized shape) and self-skipping if their tool isn't present.
# An uninstalled lens is fully inert — bash-only users get identical behavior.
# The overall status is the WORST across bumblebee + all non-skipped lenses;
# lenses can only ESCALATE concern, never mask a bumblebee finding.
overall_rank() {  # map a status to a severity rank for "worst wins"
  case "$1" in scan_error) echo 4;; exposed) echo 3;; incomplete) echo 2;; clean) echo 1;; *) echo 0;; esac
}
OVERALL="$STATUS"
if [ -d "$HONEY/lenses" ]; then
  for lens in "$HONEY/lenses"/*.sh; do
    [ -f "$lens" ] || continue   # no lenses installed → loop body never runs
    lname="$(basename "$lens" .sh)"
    "$lens" "$RUN_DIR" >>"$CYCLE_LOG" 2>&1
    LRC=$?
    LJSON="$RUN_DIR/lens-$lname.json"
    # A lens that RAN but produced no parseable verdict is NOT an absent lens —
    # treat it as scan_error so worst-wins escalates, rather than silently
    # ignoring a possible masked finding. (Lenses self-skip with exit 0 + a
    # "skipped" JSON, so this only triggers on a genuine crash.)
    if [ ! -f "$LJSON" ] || ! jq -e '.status' "$LJSON" >/dev/null 2>&1; then
      clog "lens $lname: CRASHED (rc=$LRC, no valid verdict) — escalating to scan_error"
      [ "$(overall_rank scan_error)" -gt "$(overall_rank "$OVERALL")" ] && OVERALL="scan_error"
      continue
    fi
    LSTATUS="$(jq -r '.status' "$LJSON" 2>/dev/null)"
    LTOTAL="$(jq -r '.findings_total' "$LJSON" 2>/dev/null)"
    clog "lens $lname: status=$LSTATUS findings=$LTOTAL"
    [ "$LSTATUS" = "skipped" ] && continue
    [ "$(overall_rank "$LSTATUS")" -gt "$(overall_rank "$OVERALL")" ] && OVERALL="$LSTATUS"
  done
fi

clog "=== cycle end (bumblebee=$STATUS overall=$OVERALL) ==="
# 0 when overall clean; 1 when anything (bumblebee or a lens) needs attention.
[ "$OVERALL" = "clean" ] && exit 0 || exit 1
