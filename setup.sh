#!/usr/bin/env bash
#
# honey/setup.sh — one-command setup.
#
#   1. Verify the toolchain (bash, git, jq, Go 1.25+).
#   2. Clone the bumblebee repo (for threat_intel catalogs) if absent.
#   3. go install the bumblebee binary.
#   4. Run doctor.sh to confirm everything is ready.
#
# Idempotent: safe to re-run. Installs nothing it can install for you that
# needs a package manager (jq, Go) — it tells you the command instead.

set -uo pipefail
HONEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HONEY_DIR/lib/preflight.sh"

echo "honey setup"
echo

# --- 1. Toolchain we can't auto-install (tell the user, don't guess pkg mgr) -
need_tool=0
check_cmd git "install git: https://git-scm.com"                                  || need_tool=1
check_cmd jq  "macOS: brew install jq   ·   Debian/Ubuntu: sudo apt-get install jq" || need_tool=1
check_go_version                                                                  || need_tool=1
if [ "$need_tool" -ne 0 ]; then
  echo
  printf '%sInstall the tool(s) above, then re-run ./setup.sh%s\n' "$C_BAD" "$C_OFF"
  exit 1
fi

# --- 2. bumblebee checkout (for threat_intel catalogs) ----------------------
CAT="$BUMBLEBEE_REPO/threat_intel"
CAT_JSONS=("$CAT"/*.json)
if [ -d "$CAT" ] && [ -e "${CAT_JSONS[0]}" ]; then
  ok "bumblebee checkout present ($BUMBLEBEE_REPO)"
elif [ -d "$BUMBLEBEE_REPO/.git" ]; then
  echo "  updating bumblebee checkout ($BUMBLEBEE_REPO) ..."
  if git -C "$BUMBLEBEE_REPO" pull --ff-only --quiet; then ok "checkout updated"; else bad "pull failed (continuing)"; fi
else
  echo "  cloning bumblebee into $BUMBLEBEE_REPO ..."
  if git clone --quiet https://github.com/perplexityai/bumblebee "$BUMBLEBEE_REPO"; then
    ok "cloned bumblebee"
  else
    bad "clone failed"
    hint "clone manually, or set BUMBLEBEE_REPO to an existing clone and re-run"
    exit 1
  fi
fi

# --- 3. bumblebee binary ----------------------------------------------------
echo "  installing bumblebee binary (go install $GO_PKG) ..."
if go install "$GO_PKG"; then
  ok "binary installed"
else
  bad "go install failed"; exit 1
fi

# Warn if the freshly-installed binary isn't reachable yet (PATH not updated).
check_gobin_on_path >/dev/null || {
  gobin="$(go env GOBIN 2>/dev/null)"; [ -z "$gobin" ] && gobin="$(go env GOPATH)/bin"
  echo
  printf '%sNote:%s %s is not on your PATH. Add this to your shell profile:\n' "$C_BAD" "$C_OFF" "$gobin"
  # shellcheck disable=SC2016  # $PATH and `source` are literal text shown to the user, not for expansion
  printf '    export PATH="%s:$PATH"\n' "$gobin"
  # shellcheck disable=SC2016
  printf 'then open a new shell (or `source` it) before scanning.\n'
}

# --- 4. Verify --------------------------------------------------------------
echo
echo "running doctor to verify ..."
echo
exec "$HONEY_DIR/doctor.sh"
