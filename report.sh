#!/usr/bin/env bash
#
# honey/report.sh [RUN_DIR] — render a triage report from a scan run, no AI.
#
# Reads manifest.json + findings.ndjson and prints a readable, actionable
# digest to stdout: verdict, coverage, and per-finding detail grouped by
# severity, each with standard remediation steps for its ecosystem. This is
# the analysis for the no-Claude path; the Claude routine produces richer,
# tailored prose, but the facts and standard fixes are all here deterministically.
#
# RUN_DIR defaults to the `latest` symlink. Exit 0 clean / 1 needs attention.

set -uo pipefail
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
RUN_DIR="${1:-$HONEY/latest}"
MANIFEST="$RUN_DIR/manifest.json"
FINDINGS="$RUN_DIR/findings.ndjson"

[ -f "$MANIFEST" ] || { echo "report: no manifest at $MANIFEST" >&2; exit 1; }

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; O=$'\033[0m'
else B=""; D=""; R=""; Y=""; G=""; O=""; fi

j() { jq -r "$1" "$MANIFEST" 2>/dev/null; }
STATUS="$(j '.status')"; TOTAL="$(j '.findings_total')"; HOST="$(j '.host')"
ROOT="$(j '.scan_root')"; VER="$(j '.scanner_version')"; WHEN="$(j '.finished_at')"
COMPLETED="$(j '.scan_completed')"; CATDIR="$(j '.catalog_dir')"
FILES="$(jq -r '.files_considered // "?"' "$RUN_DIR/summary.json" 2>/dev/null)"
[ -z "$FILES" ] && FILES="?"   # summary.json may be empty/absent on scan_error

# Remediation guidance per ecosystem. Generic but correct starting points;
# always "run manually" — honey never changes state.
remediation() {  # ecosystem package version
  case "$1" in
    npm) printf 'Pin or remove in package.json, then reinstall clean:\n      npm uninstall %s   # or pin a known-good version\n      rm -rf node_modules package-lock.json && npm install' "$2" ;;
    pypi) printf 'Uninstall and reinstall a safe version:\n      pip uninstall -y %s   # then pip install "%s!=%s"' "$2" "$2" "$3" ;;
    go) printf 'Bump away from the bad version, then tidy:\n      go get %s@latest && go mod tidy   # verify go.sum no longer lists %s' "$2" "$3" ;;
    rubygems) printf 'Update the gem and lockfile:\n      bundle update %s   # or edit Gemfile to exclude %s' "$2" "$3" ;;
    packagist) printf 'Require a safe version via Composer:\n      composer require %s:^SAFE   # then composer update %s' "$2" "$2" ;;
    homebrew) printf 'Uninstall/upgrade the formula or cask:\n      brew uninstall %s   # or brew upgrade %s' "$2" "$2" ;;
    editor-extension|browser-extension) printf 'Remove the extension from the editor/browser UI (and any synced profile), then reload.' ;;
    mcp) printf 'Remove the server entry from the MCP host config and rotate any credentials it could have read.' ;;
    *) printf 'Remove or pin %s away from version %s for the %s ecosystem; verify nothing else depends on it.' "$2" "$3" "$1" ;;
  esac
}

echo "${B}honey scan report${O}  ${D}($WHEN)${O}"
echo "host: $HOST   scanned: $ROOT   files: $FILES   scanner: $VER"
echo

case "$STATUS" in
  clean)
    echo "${G}✓ CLEAN${O} — scan completed, no exposure matches against the catalogs in $CATDIR."
    exit 0 ;;
  incomplete)
    echo "${Y}⚠ INCOMPLETE${O} — the scan hit its time limit (scan_completed=$COMPLETED), so coverage is PARTIAL."
    echo "Absence of findings is NOT all-clear. Re-run with a larger BUMBLEBEE_MAX_DURATION"
    echo "or a narrower BUMBLEBEE_SCAN_ROOT, then re-check."
    exit 1 ;;
  scan_error)
    echo "${R}✗ SCAN ERROR${O} — the scan failed (scan_exit_code=$(j '.scan_exit_code'))."
    echo "Diagnostics:"; tail -n 5 "$RUN_DIR/diagnostics.ndjson" 2>/dev/null | sed 's/^/  /'
    echo "Full log: $RUN_DIR/update.log"
    exit 1 ;;
esac

# --- exposed ---------------------------------------------------------------
BY_SEV="$(j '.findings_by_severity | to_entries | map("\(.value) \(.key)") | join(", ")')"
echo "${R}🚨 EXPOSED${O} — $TOTAL match(es): $BY_SEV"
echo

# Emit findings worst-severity first. Read each as a TSV line for the shell.
ORDER='{"critical":0,"high":1,"medium":2,"low":3,"unknown":4}'
jq -rs --argjson ord "$ORDER" '
  sort_by($ord[.severity] // 9)[] |
  [.severity,.package_name,.version,.ecosystem,.catalog_name,.source_file,.confidence,.catalog_id]
  | @tsv' "$FINDINGS" 2>/dev/null | while IFS=$'\t' read -r SEV PKG VER_ ECO CAT SRC CONF CID; do
  case "$SEV" in critical|high) C="$R";; medium) C="$Y";; *) C="$D";; esac
  SEV_UC="$(printf '%s' "$SEV" | tr '[:lower:]' '[:upper:]')"  # portable: macOS bash is 3.2, no ${x^^}
  echo "${C}● ${SEV_UC}${O}  ${B}$PKG${O} $VER_  ${D}($ECO)${O}"
  echo "    campaign : $CAT"
  echo "    where    : $SRC"
  case "$CONF" in
    high)   echo "    confidence: high — exact installed version present";;
    medium) echo "    confidence: medium — identity reliable, version/source partial";;
    low)    echo "    confidence: low — config/spec reference, not proof of an installed build";;
    *)      echo "    confidence: $CONF";;
  esac
  echo "    fix      : $(remediation "$ECO" "$PKG" "$VER_")"
  echo "    source   : catalog entry $CID in $CATDIR"
  echo
done

echo "${B}Do first:${O} address ${R}critical/high${O} + high-confidence matches above before lower ones."
echo "Verify each fix manually; honey only reports, it never changes your system."
echo "Raw records: $FINDINGS"
exit 1
