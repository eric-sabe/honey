#!/usr/bin/env bash
#
# honey/install-schedule.sh — schedule the notify cycle with the OS scheduler.
#
# For the no-Claude/no-Slack path: runs notify-cycle.sh daily and pops a native
# desktop notification when a scan needs attention.
#
#   ./install-schedule.sh [install|uninstall|status] [HH:MM]
#
# Default action is "install"; default time is 12:00 (local). macOS uses
# launchd (a per-user LaunchAgent); Linux uses a crontab line. Both are
# scoped to the current user and fully reversible with "uninstall".

set -uo pipefail
HONEY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-install}"
WHEN="${2:-12:00}"

die() { echo "error: $*" >&2; exit 1; }

# Parse + validate HH:MM (24h). Reject anything that isn't two colon-separated
# numbers in range, so a typo can't silently schedule the wrong time.
case "$WHEN" in
  *:*) : ;;
  *) die "time must be HH:MM (24-hour), got '$WHEN'" ;;
esac
HOUR="${WHEN%%:*}"; MIN="${WHEN##*:}"
case "$HOUR$MIN" in
  *[!0-9]*|"") die "time must be numeric HH:MM, got '$WHEN'" ;;
esac
HOUR="$((10#$HOUR))"; MIN="$((10#$MIN))"   # strip leading zero, force base-10
{ [ "$HOUR" -ge 0 ] && [ "$HOUR" -le 23 ] && [ "$MIN" -ge 0 ] && [ "$MIN" -le 59 ]; } \
  || die "time out of range (00:00–23:59), got '$WHEN'"

LABEL="com.honey.bumblebee.notify"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
ENTRY="$HONEY/notify-cycle.sh"
CRON_TAG="# honey-bumblebee-notify"
OS="$(uname -s)"

# ---------- macOS (launchd) -------------------------------------------------
mac_install() {
  mkdir -p "$HOME/Library/LaunchAgents"
  cat >"$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>$ENTRY</string></array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MIN</integer></dict>
    <key>RunAtLoad</key><false/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key><string>$HOME</string>
    </dict>
    <key>StandardOutPath</key><string>$HONEY/schedule.out.log</string>
    <key>StandardErrorPath</key><string>$HONEY/schedule.err.log</string>
</dict>
</plist>
PLIST
  plutil -lint "$PLIST" >/dev/null || die "generated plist is invalid"
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null   # replace any existing
  launchctl bootstrap "gui/$(id -u)" "$PLIST" || die "launchctl bootstrap failed"
  printf 'Installed launchd agent %s — runs daily at %02d:%02d (local).\n' "$LABEL" "$HOUR" "$MIN"
  echo "Run now to test:  launchctl kickstart -k gui/$(id -u)/$LABEL"
  echo
  echo "NOTE: macOS may need Full Disk Access for the scan to read protected"
  echo "dirs, and notifications enabled for the running process. See README."
}
mac_uninstall() {
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
  rm -f "$PLIST"
  echo "Removed launchd agent $LABEL."
}
mac_status() {
  if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    echo "launchd agent $LABEL is loaded."
    launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -iE "state =|runs =" | sed 's/^/  /'
  else
    echo "launchd agent $LABEL is NOT loaded."
  fi
}

# ---------- Linux (cron) ----------------------------------------------------
cron_line() { printf '%d %d * * * %s >>%s 2>&1 %s\n' "$MIN" "$HOUR" "$ENTRY" "$HONEY/schedule.log" "$CRON_TAG"; }
cron_install() {
  command -v crontab >/dev/null 2>&1 || die "crontab not found; install cron or schedule $ENTRY yourself"
  local cur; cur="$(crontab -l 2>/dev/null | grep -v "$CRON_TAG" || true)"
  { [ -n "$cur" ] && printf '%s\n' "$cur"; cron_line; } | crontab -
  printf 'Installed cron job — runs daily at %02d:%02d (local).\n' "$HOUR" "$MIN"
  echo "Desktop notifications on Linux need notify-send (libnotify) and an"
  echo "active graphical session; otherwise the run logs instead of popping."
}
cron_uninstall() {
  command -v crontab >/dev/null 2>&1 || { echo "no crontab; nothing to remove"; return 0; }
  crontab -l 2>/dev/null | grep -v "$CRON_TAG" | crontab - 2>/dev/null || true
  echo "Removed honey cron job."
}
cron_status() {
  if crontab -l 2>/dev/null | grep -q "$CRON_TAG"; then
    echo "honey cron job installed:"; crontab -l 2>/dev/null | grep "$CRON_TAG" | sed 's/^/  /'
  else
    echo "no honey cron job installed."
  fi
}

# ---------- dispatch --------------------------------------------------------
[ -x "$ENTRY" ] || chmod +x "$ENTRY" 2>/dev/null
case "$OS" in
  Darwin) case "$ACTION" in
            install)   mac_install ;;
            uninstall) mac_uninstall ;;
            status)    mac_status ;;
            *) die "unknown action '$ACTION' (install|uninstall|status)" ;;
          esac ;;
  Linux)  case "$ACTION" in
            install)   cron_install ;;
            uninstall) cron_uninstall ;;
            status)    cron_status ;;
            *) die "unknown action '$ACTION' (install|uninstall|status)" ;;
          esac ;;
  *) die "unsupported OS '$OS' — schedule $ENTRY with your own scheduler" ;;
esac
