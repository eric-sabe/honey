#!/usr/bin/env bash
#
# honey/run-scan.sh — regular bumblebee exposure scan cycle.
#
# 1. Updates the bumblebee repo clone (fresh threat_intel/ catalogs via PR).
# 2. Updates the bumblebee binary — built FROM THAT SAME CHECKOUT, so the
#    binary and the catalogs always come from one commit and can never skew
#    (a released binary that predates the catalogs' schema_version would
#    otherwise abort the scan). Falls back to the module-proxy @latest only
#    if the local build fails.
# 3. Runs a deep exposure scan of $HOME against the threat_intel catalogs.
# 4. Saves timestamped, self-contained results under honey/runs/<ts>/ and
#    points honey/latest at the newest run.
#
# Results live OUTSIDE the repo clone and OUTSIDE ~/go, so neither the
# `git pull` nor the `go install` can delete or overwrite them.
#
# A local Claude routine is expected to read:
#   <HONEY>/latest/manifest.json   (verdict + finding counts)
#   <HONEY>/latest/findings.ndjson (the matched records, if any)
#
# Designed to be safe under cron/launchd: it sets its own PATH and never
# aborts the scan because an update step had a transient failure.

set -uo pipefail

# ----------------------------------------------------------------------------
# Config (override via environment if desired).
# ----------------------------------------------------------------------------
# HONEY defaults to this script's own directory; override to relocate output.
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
# Load persisted config (e.g. a non-default BUMBLEBEE_REPO) before defaults.
# Precedence: env var > honey.conf > built-in default.
# shellcheck source=lib/load-config.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/load-config.sh"
# Path to your local bumblebee checkout (its threat_intel/ catalogs are used).
REPO="${BUMBLEBEE_REPO:-$HOME/git/bumblebee}"
SCAN_ROOT="${BUMBLEBEE_SCAN_ROOT:-$HOME}"
MAX_DURATION="${BUMBLEBEE_MAX_DURATION:-30m}"
GO_PKG="github.com/perplexityai/bumblebee/cmd/bumblebee@latest"

# Cron/launchd start with a bare PATH; make sure go + the binary are findable.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# ----------------------------------------------------------------------------
# Preflight: fail fast (with guidance) on the things we can't self-heal.
# The binary is auto-installed below, so we don't block on it here; but a
# missing jq or absent catalog checkout would silently ruin the run.
# ----------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
  echo "honey: jq not found on PATH — required to build scan results." >&2
  echo "  fix: macOS 'brew install jq' · Debian/Ubuntu 'sudo apt-get install jq'" >&2
  echo "  then re-run. (./doctor.sh checks all dependencies.)" >&2
  exit 1
fi
if [ ! -d "$REPO/threat_intel" ] || ! ls "$REPO"/threat_intel/*.json >/dev/null 2>&1; then
  echo "honey: no threat_intel catalogs at $REPO/threat_intel" >&2
  echo "  the bumblebee binary has no catalogs — you need a git checkout:" >&2
  echo "    git clone https://github.com/perplexityai/bumblebee \"$REPO\"" >&2
  echo "  or set BUMBLEBEE_REPO to an existing clone. (Run ./setup.sh to do this for you.)" >&2
  exit 1
fi

# ----------------------------------------------------------------------------
# Per-run setup.
# ----------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$HONEY/runs/$TS"
mkdir -p "$RUN_DIR"

LOG="$RUN_DIR/update.log"
RECORDS="$RUN_DIR/records.ndjson"
DIAGS="$RUN_DIR/diagnostics.ndjson"
FINDINGS="$RUN_DIR/findings.ndjson"
SUMMARY="$RUN_DIR/summary.json"
MANIFEST="$RUN_DIR/manifest.json"

CATALOG_DIR="$REPO/threat_intel"

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "honey run $TS starting"
log "repo=$REPO  scan_root=$SCAN_ROOT  catalog=$CATALOG_DIR"

# ----------------------------------------------------------------------------
# 1. Update the repo clone (for fresh threat_intel catalogs).
# ----------------------------------------------------------------------------
REPO_UPDATED=false
if git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
  if git -C "$REPO" fetch --quiet origin >>"$LOG" 2>&1 \
     && git -C "$REPO" pull --ff-only --quiet >>"$LOG" 2>&1; then
    REPO_UPDATED=true
    log "repo updated (ff-only pull ok)"
  else
    log "WARN repo update failed (continuing with existing catalogs)"
  fi
else
  log "WARN $REPO is not a git repo (continuing with existing catalogs)"
fi
REPO_COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# ----------------------------------------------------------------------------
# 2. Update the binary — from the checkout, not the module proxy.
#
# The catalogs (step 1) track the repo's HEAD; a proxy @latest binary is only
# as new as the last tagged release and can lag the catalogs' schema_version,
# which aborts the whole scan (seen live: v0.1.2 binary vs 0.2.0 catalogs).
# Building from the same commit the catalogs came from makes skew impossible.
# The proxy install remains as a fallback for a broken checkout — it may still
# skew, but a stale binary that *might* scan beats no fresh binary at all, and
# a mismatch surfaces loudly as scan_error rather than a false clean.
# ----------------------------------------------------------------------------
BINARY_UPDATED=false
if command -v go >/dev/null 2>&1; then
  if (cd "$REPO" && go install ./cmd/bumblebee) >>"$LOG" 2>&1; then
    BINARY_UPDATED=true
    log "binary updated (go install ./cmd/bumblebee @ $REPO_COMMIT — matches catalogs)"
  elif go install "$GO_PKG" >>"$LOG" 2>&1; then
    BINARY_UPDATED=true
    log "WARN local build failed; installed module-proxy $GO_PKG instead — released binary may lag the checkout's catalogs (schema skew => scan_error)"
  else
    log "WARN binary update failed (continuing with existing binary)"
  fi
else
  log "WARN go not found on PATH (continuing with existing binary)"
fi

BIN="$(command -v bumblebee || true)"
if [ -z "$BIN" ]; then
  log "ERROR bumblebee binary not found; aborting"
  printf '{"run_id":"%s","status":"scan_error","error":"bumblebee binary not found"}\n' "$TS" >"$MANIFEST"
  ln -sfn "$RUN_DIR" "$HONEY/latest"
  exit 1
fi
SCANNER_VERSION="$("$BIN" version 2>/dev/null | head -1 | awk '{print $2}')"
log "using binary $BIN ($SCANNER_VERSION)"

# ----------------------------------------------------------------------------
# 3. Run the deep exposure scan.
# ----------------------------------------------------------------------------
log "scanning $SCAN_ROOT (max-duration $MAX_DURATION) ..."
"$BIN" scan \
  --profile deep \
  --root "$SCAN_ROOT" \
  --exposure-catalog "$CATALOG_DIR" \
  --findings-only \
  --max-duration "$MAX_DURATION" \
  >"$RECORDS" 2>"$DIAGS"
SCAN_EXIT=$?
log "scan exit code: $SCAN_EXIT"

# ----------------------------------------------------------------------------
# 4. Split output and build the manifest.
# ----------------------------------------------------------------------------
# stdout carries finding + scan_summary records; with --findings-only a clean
# scan emits only the scan_summary, which is the correct "all clear" signal.
# Parse tolerantly with `fromjson?`: a single malformed/truncated line (e.g. an
# interrupted write on --max-duration kill) must NOT discard the valid findings
# that preceded it. The old `jq … || : >FILE` truncated everything on any bad
# line — turning real findings into a false "clean". `fromjson?` skips only the
# unparseable lines and keeps the rest.
jq -Rc 'fromjson? | select(.record_type=="finding")'      "$RECORDS" >"$FINDINGS" 2>/dev/null
jq -Rc 'fromjson? | select(.record_type=="scan_summary")' "$RECORDS" >"$SUMMARY"  2>/dev/null
[ -f "$FINDINGS" ] || : >"$FINDINGS"
[ -f "$SUMMARY" ]  || : >"$SUMMARY"

# Did the walk finish, or hit --max-duration (=> partial coverage)? Prefer the
# structured scan_summary.timed_out boolean; only fall back to grepping the
# stderr diagnostic prose if that field is somehow absent (older scanner).
SCAN_COMPLETED=true
TIMED_OUT="$(jq -r '.timed_out // empty' "$SUMMARY" 2>/dev/null)"
if [ "$TIMED_OUT" = "true" ]; then
  SCAN_COMPLETED=false
elif [ -z "$TIMED_OUT" ]; then
  grep -q 'timed_out=true' "$DIAGS" 2>/dev/null && SCAN_COMPLETED=false
fi

FINDINGS_TOTAL="$(wc -l <"$FINDINGS" 2>/dev/null | tr -d '[:space:]')"
[ -z "$FINDINGS_TOTAL" ] && FINDINGS_TOTAL=0
BY_SEVERITY="$(jq -s 'group_by(.severity)
  | map({key: (.[0].severity // "unknown"), value: length})
  | from_entries' "$FINDINGS" 2>/dev/null)"
[ -z "$BY_SEVERITY" ] && BY_SEVERITY='{}'

# List catalog files via a glob (handles odd names; no `ls` parsing), and turn
# the array into a JSON array with jq's --args.
CAT_GLOB=("$CATALOG_DIR"/*.json)
[ -e "${CAT_GLOB[0]}" ] || CAT_GLOB=()
CATALOG_FILES="$(jq -n '$ARGS.positional' --args "${CAT_GLOB[@]}" 2>/dev/null)"
[ -z "$CATALOG_FILES" ] && CATALOG_FILES='[]'

if [ "$SCAN_EXIT" -ne 0 ]; then
  STATUS="scan_error"
elif [ "$FINDINGS_TOTAL" -gt 0 ]; then
  STATUS="exposed"
elif [ "$SCAN_COMPLETED" != true ]; then
  STATUS="incomplete"   # likely hit --max-duration; coverage is partial
else
  STATUS="clean"
fi

jq -n \
  --arg run_id        "$TS" \
  --arg host          "$(hostname)" \
  --arg scanner       "${SCANNER_VERSION:-unknown}" \
  --arg repo_commit   "$REPO_COMMIT" \
  --argjson repo_upd  "$REPO_UPDATED" \
  --argjson bin_upd   "$BINARY_UPDATED" \
  --argjson scan_exit "$SCAN_EXIT" \
  --argjson completed "$SCAN_COMPLETED" \
  --arg scan_root     "$SCAN_ROOT" \
  --arg catalog_dir   "$CATALOG_DIR" \
  --argjson catalogs  "$CATALOG_FILES" \
  --argjson total     "$FINDINGS_TOTAL" \
  --argjson by_sev    "$BY_SEVERITY" \
  --arg status        "$STATUS" \
  --arg findings_path "$FINDINGS" \
  --arg summary_path  "$SUMMARY" \
  --arg finished_at   "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    run_id: $run_id,
    finished_at: $finished_at,
    host: $host,
    status: $status,
    scanner_version: $scanner,
    repo_commit: $repo_commit,
    repo_updated: $repo_upd,
    binary_updated: $bin_upd,
    scan_exit_code: $scan_exit,
    scan_completed: $completed,
    scan_root: $scan_root,
    catalog_dir: $catalog_dir,
    catalog_files: $catalogs,
    findings_total: $total,
    findings_by_severity: $by_sev,
    findings_path: $findings_path,
    summary_path: $summary_path
  }' >"$MANIFEST"

# Point latest/ at this run.
ln -sfn "$RUN_DIR" "$HONEY/latest"

log "done: status=$STATUS findings=$FINDINGS_TOTAL -> $RUN_DIR"
echo "----------------------------------------------------------------"
cat "$MANIFEST"

# Exit non-zero when the run needs attention (failed or partial coverage),
# so a runner/routine can alert on it. "exposed" stays exit 0 — findings are
# a successful result; the routine triages them from the manifest.
case "$STATUS" in
  scan_error|incomplete) exit 1 ;;
  *) exit 0 ;;
esac
