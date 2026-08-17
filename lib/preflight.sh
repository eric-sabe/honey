#!/usr/bin/env bash
#
# honey/lib/preflight.sh — shared dependency checks.
#
# Sourced by doctor.sh (report everything) and run-scan.sh (fail fast before
# a scan). Defines check functions that print a clear ✓/✗ line and, on
# failure, the exact command to fix it. No side effects beyond stdout.
#
# Resolve config the same way the scripts do, so checks reflect real defaults.

HONEY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HONEY_ROOT="$(cd "$HONEY_LIB_DIR/.." && pwd)"

# Load persisted machine-specific config (e.g. a non-default BUMBLEBEE_REPO)
# before applying built-in defaults. Precedence: env var > honey.conf > default.
# shellcheck source=lib/load-config.sh
. "$HONEY_LIB_DIR/load-config.sh"

: "${HONEY:=$HONEY_ROOT}"
: "${BUMBLEBEE_REPO:=$HOME/git/bumblebee}"
: "${BUMBLEBEE_SCAN_ROOT:=$HOME}"
GO_PKG="github.com/perplexityai/bumblebee/cmd/bumblebee@latest"

# Colors only when stdout is a terminal (keeps logs clean under launchd/cron).
if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_DIM=""; C_OFF=""
fi

ok()   { printf '  %s✓%s %s\n'    "$C_OK"  "$C_OFF" "$1"; }
bad()  { printf '  %s✗%s %s\n'    "$C_BAD" "$C_OFF" "$1"; }
hint() { printf '      %s↳ %s%s\n' "$C_DIM" "$1" "$C_OFF"; }

# Each check returns 0 on pass, 1 on fail, and prints its own status line.

check_bash() {
  if [ -n "${BASH_VERSION:-}" ]; then ok "bash ${BASH_VERSION%%(*}"; return 0
  else bad "bash not detected"; hint "run these scripts with bash, not sh"; return 1; fi
}

check_cmd() {  # check_cmd <bin> <install-hint>
  local bin="$1" fix="$2"
  if command -v "$bin" >/dev/null 2>&1; then ok "$bin ($(command -v "$bin"))"; return 0
  else bad "$bin not found on PATH"; hint "$fix"; return 1; fi
}

check_go_version() {  # bumblebee needs Go 1.25+
  command -v go >/dev/null 2>&1 || { bad "go not found"; hint "install Go 1.25+ from https://go.dev/dl/"; return 1; }
  local v; v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  local major minor; major="${v%%.*}"; minor="$(printf '%s' "$v" | cut -d. -f2)"
  if [ "${major:-0}" -gt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge 25 ]; }; then
    ok "go $v (>= 1.25)"; return 0
  else
    bad "go $v is too old (bumblebee needs 1.25+)"; hint "upgrade from https://go.dev/dl/"; return 1
  fi
}

check_gobin_on_path() {  # the dir `go install` drops binaries into must be on PATH
  local gobin; gobin="$(go env GOBIN 2>/dev/null)"; [ -z "$gobin" ] && gobin="$(go env GOPATH 2>/dev/null)/bin"
  case ":$PATH:" in
    *":$gobin:"*) ok "Go bin dir on PATH ($gobin)"; return 0 ;;
    *) bad "Go bin dir not on PATH ($gobin)"
       hint "add to your shell profile:  export PATH=\"$gobin:\$PATH\""; return 1 ;;
  esac
}

check_bumblebee_binary() {
  if command -v bumblebee >/dev/null 2>&1; then
    ok "bumblebee binary ($(bumblebee version 2>/dev/null | head -1))"; return 0
  else
    bad "bumblebee binary not found on PATH"
    hint "build from your checkout (matches its catalogs): (cd \"$BUMBLEBEE_REPO\" && go install ./cmd/bumblebee)"
    hint "or (may lag the catalogs' schema): go install $GO_PKG"; return 1
  fi
}

check_bumblebee_selftest() {
  command -v bumblebee >/dev/null 2>&1 || { bad "bumblebee selftest skipped (no binary)"; return 1; }
  local out
  if out="$(bumblebee selftest 2>&1)"; then
    ok "bumblebee selftest: ${out}"; return 0
  else
    bad "bumblebee selftest FAILED"; hint "$out"
    hint "reinstall from your checkout: (cd \"$BUMBLEBEE_REPO\" && go install ./cmd/bumblebee)"; return 1
  fi
}

check_catalog_checkout() {  # the threat_intel/ catalogs live in a git checkout, NOT the binary
  local cat="$BUMBLEBEE_REPO/threat_intel"
  local jsons=("$cat"/*.json)   # glob; if none match, [0] is the literal pattern
  if [ -d "$cat" ] && [ -e "${jsons[0]}" ]; then
    ok "threat_intel catalogs: ${#jsons[@]} found in $BUMBLEBEE_REPO"; return 0
  else
    bad "no threat_intel catalogs at $BUMBLEBEE_REPO/threat_intel"
    hint "clone the bumblebee repo (needed for catalogs — the binary alone has none):"
    hint "  git clone https://github.com/perplexityai/bumblebee \"$BUMBLEBEE_REPO\""
    hint "or point honey at an existing clone:  export BUMBLEBEE_REPO=/path/to/bumblebee"
    return 1
  fi
}

check_scan_root() {
  if [ -d "$BUMBLEBEE_SCAN_ROOT" ]; then ok "scan root exists ($BUMBLEBEE_SCAN_ROOT)"; return 0
  else bad "scan root does not exist ($BUMBLEBEE_SCAN_ROOT)"; hint "set BUMBLEBEE_SCAN_ROOT to a real directory"; return 1; fi
}

# run_all_checks [--quiet-on-pass]
# Runs every check; returns number of failures (0 = all good).
run_all_checks() {
  local fails=0
  check_bash               || fails=$((fails+1))
  check_cmd git  "install git (https://git-scm.com)"                 || fails=$((fails+1))
  check_cmd jq   "macOS: brew install jq   ·   Debian/Ubuntu: apt-get install jq" || fails=$((fails+1))
  check_go_version         || fails=$((fails+1))
  check_gobin_on_path      || fails=$((fails+1))
  check_bumblebee_binary   || fails=$((fails+1))
  check_bumblebee_selftest || fails=$((fails+1))
  check_catalog_checkout   || fails=$((fails+1))
  check_scan_root          || fails=$((fails+1))
  return $fails
}
