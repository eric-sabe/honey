#!/usr/bin/env bash
#
# honey/doctor.sh — check that everything honey needs is in place.
#
# Prints a ✓/✗ line per dependency with exact fix-it commands for anything
# missing. Exits 0 if ready to scan, 1 otherwise. Safe to run anytime.

set -uo pipefail
HONEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HONEY_DIR/lib/preflight.sh"

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
