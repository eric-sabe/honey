#!/usr/bin/env bash
#
# honey/notify-cycle.sh — scan + native desktop notification.
#
# For people who don't use the Claude/Slack routine. Runs daily-cycle.sh and,
# when the run needs attention (exposed / incomplete / scan_error), fires a
# native desktop notification pointing at the run dir. Clean runs are silent.
#
# This is the entry point for the local scheduler (see install-schedule.sh).
# Triage is still manual: open the run dir, or read runs/latest/findings.ndjson.
#
# Notifier resolution: terminal-notifier > osascript (macOS) > notify-send
# (Linux). If none is available it logs and exits without failing the scan.

set -uo pipefail
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
CYCLE_LOG="$HONEY/cycle.log"

# launchd/cron hand a bare PATH; make the usual tool locations findable.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

clog() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] notify: $*" | tee -a "$CYCLE_LOG"; }

# notify TITLE MESSAGE — best-effort, never fails the cycle.
notify() {
  local title="$1" msg="$2"
  if command -v terminal-notifier >/dev/null 2>&1; then
    terminal-notifier -title "$title" -message "$msg" -sound Submarine >/dev/null 2>&1 || true
  elif command -v osascript >/dev/null 2>&1; then
    # Escape embedded double quotes for the AppleScript string literals.
    local t=${title//\"/\\\"} m=${msg//\"/\\\"}
    osascript -e "display notification \"$m\" with title \"$t\" sound name \"Submarine\"" >/dev/null 2>&1 || true
  elif command -v notify-send >/dev/null 2>&1; then
    notify-send "$title" "$msg" >/dev/null 2>&1 || true
  else
    clog "no notifier found (terminal-notifier/osascript/notify-send); message: $title — $msg"
    return 0
  fi
}

# Run the scan cycle (data-only core). Exit codes: 0 clean, 1 needs attention,
# 2 cycle failure (no fresh manifest / stale `latest`). Honor rc=2 directly so
# we never read a manifest daily-cycle already judged stale — no log-grepping.
"$HONEY/daily-cycle.sh"
RC=$?

MANIFEST="$HONEY/latest/manifest.json"
# Only 0 (clean) and 1 (fresh, needs attention) mean a trustworthy manifest.
# Anything else — 2 (stale/no manifest), or 126/127/signal if daily-cycle
# couldn't even run — means do NOT trust `latest`.
if { [ "$RC" -ne 0 ] && [ "$RC" -ne 1 ]; } || [ ! -f "$MANIFEST" ]; then
  notify "🐝 Bumblebee scan FAILED" "No fresh results produced — see $CYCLE_LOG"
  clog "cycle failed / no fresh manifest (daily-cycle rc=$RC)"
  exit 1
fi

STATUS="$(jq -r '.status' "$MANIFEST" 2>/dev/null)"
TOTAL="$(jq -r '.findings_total' "$MANIFEST" 2>/dev/null)"

# Deterministic analysis (no AI) → saved beside the run and appended to the
# cycle log, so a scheduled run leaves a full report behind, not just a ping.
REPORT="$HONEY/latest/report.txt"
if [ "$STATUS" != "clean" ]; then
  TERM=dumb "$HONEY/report.sh" "$HONEY/latest" >"$REPORT" 2>/dev/null || true
  [ -s "$REPORT" ] && { echo "----- report ($STATUS) -----"; cat "$REPORT"; echo "----------------------------"; } >>"$CYCLE_LOG"
fi

case "$STATUS" in
  clean)
    clog "clean — no notification"
    ;;
  exposed)
    notify "🚨 Bumblebee: $TOTAL exposure match(es)" "Report: runs/latest/report.txt"
    clog "notified: exposed ($TOTAL) — report at $REPORT"
    ;;
  incomplete)
    notify "⚠️ Bumblebee scan INCOMPLETE" "Partial coverage — raise BUMBLEBEE_MAX_DURATION"
    clog "notified: incomplete"
    ;;
  scan_error)
    notify "🚨 Bumblebee scan ERROR" "See $CYCLE_LOG and runs/latest/"
    clog "notified: scan_error"
    ;;
  *)
    notify "🐝 Bumblebee: status=$STATUS" "See runs/latest/manifest.json"
    clog "notified: unknown status=$STATUS"
    ;;
esac

exit "$RC"
