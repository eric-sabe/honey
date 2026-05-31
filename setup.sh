#!/usr/bin/env bash
#
# honey/setup.sh — one-command setup.
#
#   1. Verify the toolchain (bash, git, jq, Go 1.25+).
#   2. Clone the bumblebee repo (for threat_intel catalogs) if absent.
#   3. go install the bumblebee binary.
#   4. Offer the optional Go-based vuln lenses (osv-scanner, govulncheck).
#   5. Run doctor.sh to confirm everything is ready.
#
# Idempotent: safe to re-run. Installs nothing it can install for you that
# needs a package manager (jq, Go) — it tells you the command instead. The
# Python-based skillspector lens is pointed to, not auto-installed.
# HONEY_SETUP_INSTALL_LENSES=0 skips the optional-lens step entirely.

set -uo pipefail
HONEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Did the user pin BUMBLEBEE_REPO explicitly (env or honey.conf) BEFORE we apply
# the default in preflight? If so, we respect it and skip the discovery prompt.
[ -n "${BUMBLEBEE_REPO:-}" ] && BUMBLEBEE_REPO_EXPLICIT=1 || BUMBLEBEE_REPO_EXPLICIT=""
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

# Persist a setting to honey.conf so it survives across shells AND bare-env
# Local-routine / cron runs (which don't inherit your interactive environment).
# Written as `export VAR="${VAR:-value}"` to preserve env-var > conf > default.
CONF="$HONEY_DIR/honey.conf"
persist() {  # persist VAR VALUE
  local var="$1" val="$2"
  [ -f "$CONF" ] || { printf '# honey.conf — machine-specific config (gitignored). Written by setup.sh.\n' >"$CONF"; }
  # Drop any prior line for this var, then append the new one.
  grep -v "^export $var=" "$CONF" >"$CONF.tmp" 2>/dev/null || :
  mv "$CONF.tmp" "$CONF"
  # shellcheck disable=SC2016  # the ${VAR:-...} is literal text written to honey.conf, not for expansion here
  printf 'export %s="${%s:-%s}"\n' "$var" "$var" "$val" >>"$CONF"
  ok "persisted $var=$val to honey.conf"
}

# --- 2. bumblebee checkout (for threat_intel catalogs) ----------------------
# If BUMBLEBEE_REPO was already set (env or honey.conf), respect it. Otherwise,
# if an existing clone is found at a non-default path, offer to use it rather
# than cloning a duplicate; fall back to the default location.
bb_has_catalogs() { [ -d "$1/threat_intel" ] && ls "$1"/threat_intel/*.json >/dev/null 2>&1; }

if [ -z "${BUMBLEBEE_REPO_EXPLICIT:-}" ] && [ ! -f "$CONF" ] && ! bb_has_catalogs "$BUMBLEBEE_REPO"; then
  # No persisted/explicit choice yet, and nothing at the default. Look for an
  # existing clone elsewhere so we don't silently create a second copy.
  echo "  looking for an existing bumblebee checkout ..."
  FOUND=""
  while IFS= read -r cand; do
    d="$(dirname "$cand")"; bb_has_catalogs "$d" && { FOUND="$d"; break; }
  done < <(find "$HOME" -maxdepth 6 -type d -name threat_intel -path '*/bumblebee/*' 2>/dev/null)
  if [ -n "$FOUND" ] && [ "$FOUND" != "$BUMBLEBEE_REPO" ]; then
    echo
    echo "  Found an existing bumblebee clone at:"
    echo "    $FOUND"
    echo "  honey's default is: $BUMBLEBEE_REPO"
    if [ -t 0 ]; then
      printf "  Use the existing clone instead of cloning a new one? [Y/n] "
      read -r ans
      case "$ans" in [Nn]*) : ;; *) BUMBLEBEE_REPO="$FOUND"; persist BUMBLEBEE_REPO "$FOUND" ;; esac
    else
      # Non-interactive (CI, piped): prefer the found clone, persist it.
      BUMBLEBEE_REPO="$FOUND"; persist BUMBLEBEE_REPO "$FOUND"
      echo "  (non-interactive: using the existing clone)"
    fi
  fi
fi

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

# --- 4. Optional lenses -----------------------------------------------------
# honey can run additional scanners as "lenses" (see README). They are OPT-IN
# and never required. We offer to install the two lightweight Go-based ones
# here (you already have Go); SkillSpector has a Python stack so we only point
# to it rather than installing it. Set HONEY_SETUP_INSTALL_LENSES=0 to skip.
if [ "${HONEY_SETUP_INSTALL_LENSES:-1}" = "1" ]; then
  echo
  echo "optional vuln-scanning lenses (Go-based — safe to install now):"
  if command -v osv-scanner >/dev/null 2>&1; then
    ok "osv-scanner already installed"
  else
    echo "  installing osv-scanner (multi-ecosystem lockfile vuln scan) ..."
    if go install github.com/google/osv-scanner/cmd/osv-scanner@latest; then ok "osv-scanner installed"; else bad "osv-scanner install failed (optional — continuing)"; fi
  fi
  if command -v govulncheck >/dev/null 2>&1; then
    ok "govulncheck already installed"
  else
    echo "  installing govulncheck (Go reachability-aware vuln scan) ..."
    if go install golang.org/x/vuln/cmd/govulncheck@latest; then ok "govulncheck installed"; else bad "govulncheck install failed (optional — continuing)"; fi
  fi
  echo
  echo "optional agent-skill lens (separate Python install — NOT installed automatically):"
  if command -v skillspector >/dev/null 2>&1; then
    ok "skillspector already installed"
  else
    hint "skillspector scans AI agent skills; install per https://github.com/NVIDIA/skillspector"
    hint "then it activates automatically on the next run."
  fi
fi

# --- 5. Verify --------------------------------------------------------------
echo
echo "running doctor to verify ..."
echo
exec "$HONEY_DIR/doctor.sh"
