#!/usr/bin/env bash
#
# honey/doctor.sh — check that everything honey needs is in place.
#
# Prints a ✓/✗ line per dependency with exact fix-it commands for anything
# missing. Exits 0 if ready to scan, 1 otherwise. Safe to run anytime.

set -uo pipefail
HONEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HONEY_DIR/lib/preflight.sh"
HONEY="${HONEY:-$HONEY_DIR}"
# shellcheck source=lib/baseline.sh
. "$HONEY_DIR/lib/baseline.sh"

echo "honey doctor — checking dependencies"
echo
echo "config:"
printf '  HONEY=%s\n' "$HONEY"
printf '  BUMBLEBEE_REPO=%s\n' "$BUMBLEBEE_REPO"
printf '  BUMBLEBEE_SCAN_ROOT=%s\n' "$BUMBLEBEE_SCAN_ROOT"
echo
echo "checks:"
run_all_checks
fails=$?

# Optional lenses — informational only; never affect the core pass/fail.
# A lens whose tool isn't installed is simply inactive (honey's core path is
# unaffected). This just tells you which extra scanners are live.
if [ -d "$HONEY/lenses" ] && ls "$HONEY"/lenses/*.sh >/dev/null 2>&1; then
  echo
  echo "optional lenses:"
  for lens in "$HONEY"/lenses/*.sh; do
    lname="$(basename "$lens" .sh)"
    case "$lname" in
      skillspector)
        if command -v skillspector >/dev/null 2>&1; then
          ok "lens $lname active ($(skillspector --version 2>/dev/null | head -1))"
        else
          bad "lens $lname inactive — skillspector not installed (optional)"
          hint "agent-skill scanning; install per https://github.com/NVIDIA/skillspector then it activates automatically"
        fi ;;
      osv-scanner)
        if command -v osv-scanner >/dev/null 2>&1; then
          ok "lens $lname active ($(osv-scanner --version 2>/dev/null | head -1))"
        else
          bad "lens $lname inactive — osv-scanner not installed (optional)"
          hint "multi-ecosystem lockfile vuln scanning; install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest"
        fi ;;
      govulncheck)
        if command -v govulncheck >/dev/null 2>&1; then
          ok "lens $lname active ($(govulncheck -version 2>/dev/null | head -1))"
        else
          bad "lens $lname inactive — govulncheck not installed (optional)"
          hint "Go reachability-aware vuln scanning; install: go install golang.org/x/vuln/cmd/govulncheck@latest"
        fi ;;
      *)
        if command -v "$lname" >/dev/null 2>&1; then ok "lens $lname active"; else bad "lens $lname inactive (optional tool '$lname' not installed)"; fi ;;
    esac
  done
fi
# Suppression baseline — informational; never affects pass/fail. Shows how many
# findings you've pinned as reviewed-benign and whether any pins have expired.
BFILE="$(honey_baseline_file)"
echo
echo "suppression baseline:"
if [ -f "$BFILE" ]; then
  BN="$(honey_baseline_entries | jq 'length' 2>/dev/null || echo 0)"
  BEXP="$(honey_baseline_entries | jq --arg t "$(honey_today)" '[.[]|select(.expires!="never" and .expires < $t)]|length' 2>/dev/null || echo 0)"
  ok "baseline present ($BN pin(s)) — $BFILE"
  [ "${BEXP:-0}" -gt 0 ] && hint "$BEXP pin(s) expired; review with ./honey-baseline.sh list --expired, then ./honey-baseline.sh prune"
else
  ok "no baseline yet (all findings active) — create pins with ./honey-baseline.sh add"
fi

echo
if [ "$fails" -eq 0 ]; then
  printf '%sAll checks passed — honey is ready.%s Run:  ./daily-cycle.sh\n' "$C_OK" "$C_OFF"
  printf '%sScanner + threat intel by Perplexity: https://github.com/perplexityai/bumblebee%s\n' "$C_DIM" "$C_OFF"
  exit 0
else
  printf '%s%d check(s) failed.%s Fix the items above, then re-run ./doctor.sh\n' "$C_BAD" "$fails" "$C_OFF"
  printf 'Tip: ./setup.sh can fix most of these automatically.\n'
  exit 1
fi
