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
# The pin-and-diff suppression baseline (honey.baseline.json) is applied here at
# the report layer: findings pinned as reviewed-benign AND still matching their
# recorded content hash are SUPPRESSED (dropped from the verdict, still counted);
# a pinned file whose content CHANGED resurfaces as MUTATED. Raw run records are
# never modified — suppression is a re-rank, not a deletion. See docs/BASELINE.plan.md.
#
# RUN_DIR defaults to the `latest` symlink. Exit 0 clean / 1 needs attention.

set -uo pipefail
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
RUN_DIR="${1:-$HONEY/latest}"
MANIFEST="$RUN_DIR/manifest.json"
FINDINGS="$RUN_DIR/findings.ndjson"

[ -f "$MANIFEST" ] || { echo "report: no manifest at $MANIFEST" >&2; exit 1; }

# Load honey.conf so persisted settings (verdict floor, trusted patterns,
# HONEY_BASELINE) apply when report.sh is run standalone — the Claude routine
# invokes it as a separate process from daily-cycle.sh, so it can't rely on an
# inherited environment. env var > honey.conf > built-in default.
# shellcheck source=lib/load-config.sh
. "$HONEY/lib/load-config.sh"
# shellcheck source=lib/baseline.sh
. "$HONEY/lib/baseline.sh"

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; Y=$'\033[33m'; G=$'\033[32m'; O=$'\033[0m'
else B=""; D=""; R=""; Y=""; G=""; O=""; fi

j() { jq -r "$1" "$MANIFEST" 2>/dev/null; }
STATUS="$(j '.status')"; TOTAL="$(j '.findings_total')"; HOST="$(j '.host')"
ROOT="$(j '.scan_root')"; VER="$(j '.scanner_version')"; WHEN="$(j '.finished_at')"
COMPLETED="$(j '.scan_completed')"; CATDIR="$(j '.catalog_dir')"
FILES="$(jq -r '.files_considered // "?"' "$RUN_DIR/summary.json" 2>/dev/null)"
[ -z "$FILES" ] && FILES="?"   # summary.json may be empty/absent on scan_error

# Suppression + verdict-policy tallies, accumulated across bumblebee + every
# lens as we render. REV = active findings held below the severity floor.
SUP=0; MUT=0; EXP=0; REV=0

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

# severity → rank, for "worst wins" across bumblebee + every lens.
rank() { case "$1" in scan_error) echo 4;; exposed) echo 3;; incomplete) echo 2;; clean|skipped) echo 1;; *) echo 0;; esac; }

ORDER='{"critical":0,"high":1,"medium":2,"low":3,"unknown":4}'

# A class marker printed before a finding line (mutated/expired resurface loudly).
class_prefix() {  # _class → printed prefix (empty for plain active)
  case "$1" in
    mutated) printf '%s🔁 MUTATED%s ' "$R" "$O" ;;
    expired) printf '%s⌛ EXPIRED-PIN%s ' "$Y" "$O" ;;
    *) : ;;
  esac
}

# render_lenses — print a section per lens-*.json in the run dir, and update
# OVERALL to the worst status seen (AFTER suppression). Lenses are honey's
# additional scanners; absent ones simply don't appear.
OVERALL="$STATUS"
render_lenses() {
  local lj name lstatus ltotal lnote
  for lj in "$RUN_DIR"/lens-*.json; do
    [ -f "$lj" ] || continue
    name="$(jq -r '.lens' "$lj" 2>/dev/null)"
    lstatus="$(jq -r '.status' "$lj" 2>/dev/null)"
    ltotal="$(jq -r '.findings_total' "$lj" 2>/dev/null)"
    lnote="$(jq -r '.note // empty' "$lj" 2>/dev/null)"
    echo
    case "$lstatus" in
      skipped)    echo "${D}— lens ${name}: skipped${O} (${lnote})"; continue ;;
      clean)      echo "${G}✓ lens ${name}: clean${O} (${lnote})"; continue ;;
      scan_error) echo "${R}✗ lens ${name}: scan error${O} (${lnote})"
                  [ "$(rank scan_error)" -gt "$(rank "$OVERALL")" ] && OVERALL="scan_error"; continue ;;
      incomplete) echo "${Y}⚠ lens ${name}: incomplete${O} (${lnote})"
                  [ "$(rank incomplete)" -gt "$(rank "$OVERALL")" ] && OVERALL="incomplete"; continue ;;
    esac

    # exposed → classify against the baseline + verdict policy. Findings split
    # three ways: suppressed (hidden), blocking (escalate OVERALL), and review
    # (active but below the severity floor for their provenance — reported, not
    # blocking). Suppressed ones are counted and summarized, not listed.
    local cls s blk rev
    cls="$(honey_classify_lens "$name" "$lj")"
    s="$(  printf '%s\n' "$cls" | jq -r 'select(._class=="suppressed")|1' 2>/dev/null | grep -c .)"
    blk="$(printf '%s\n' "$cls" | jq -r 'select(._class!="suppressed" and ._blocking=="yes")|1' 2>/dev/null | grep -c .)"
    rev="$(printf '%s\n' "$cls" | jq -r 'select(._class!="suppressed" and ._blocking=="no")|1'  2>/dev/null | grep -c .)"
    SUP=$((SUP+s))
    MUT=$((MUT+$(printf '%s\n' "$cls" | jq -r 'select(._class=="mutated")|1' 2>/dev/null | grep -c .)))
    EXP=$((EXP+$(printf '%s\n' "$cls" | jq -r 'select(._class=="expired")|1' 2>/dev/null | grep -c .)))
    REV=$((REV+rev))

    if [ $((blk+rev)) -eq 0 ]; then
      echo "${G}✓ lens ${name}: clean${O} — all ${ltotal} finding(s) suppressed by baseline. ${D}(${lnote})${O}"
      continue
    fi

    local extras=""
    [ "$s" -gt 0 ] && extras="${extras}  ${D}(+${s} suppressed)${O}"
    [ "$blk" -gt 0 ] && [ "$rev" -gt 0 ] && extras="${extras}  ${D}(+${rev} review)${O}"
    if [ "$blk" -gt 0 ]; then
      [ "$(rank exposed)" -gt "$(rank "$OVERALL")" ] && OVERALL="exposed"
      local by
      by="$(printf '%s\n' "$cls" | jq -rs 'map(select(._class!="suppressed" and ._blocking=="yes")) | group_by(.severity)
        | map("\(length) \(.[0].severity)") | join(", ")' 2>/dev/null)"
      echo "${R}🚨 lens ${name}: ${blk} finding(s)${O} [$by]${extras}  ${D}(${lnote})${O}"
    else
      # No blocking findings — only review-tier (first-party / below floor).
      echo "${Y}● lens ${name}: ${rev} review finding(s)${O} — ${D}non-blocking (first-party or below the severity floor)${O}${extras}  ${D}(${lnote})${O}"
    fi

    # List blocking findings first (prominent), then review (dim), each tagged
    # with provenance and a [review] marker when non-blocking.
    printf '%s\n' "$cls" | jq -rs --argjson ord "$ORDER" '
        map(select(._class!="suppressed"))
        | sort_by([ (if ._blocking=="yes" then 0 else 1 end), ($ord[.severity] // 9) ])[]
        | [.severity,.title,.location,.detail,.ref,._class,._blocking,._provenance] | @tsv' 2>/dev/null \
    | while IFS=$'\t' read -r SEV TITLE LOC DET REF CLASS BLK PROV; do
        SEV_UC="$(printf '%s' "$SEV" | tr '[:lower:]' '[:upper:]')"
        REFSUFFIX=""; [ -n "$REF" ] && REFSUFFIX="  ${D}(${REF})${O}"
        PTAG=""; [ "$PROV" = "first-party" ] && PTAG="  ${D}[1st-party]${O}"
        if [ "$BLK" = "no" ]; then
          echo "  ${D}○ review ${SEV_UC}  ${TITLE}${REFSUFFIX} [non-blocking]${O}"
          echo "      ${D}where : $LOC${O}"
        else
          case "$SEV" in critical|high) C="$R";; medium) C="$Y";; *) C="$D";; esac
          echo "  $(class_prefix "$CLASS")${C}● ${SEV_UC}${O}  ${B}${TITLE}${O}${REFSUFFIX}${PTAG}"
          echo "      where : $LOC"
          [ -n "$DET" ] && echo "      detail: $DET"
          [ "$CLASS" = "mutated" ] && echo "      ${R}note  : content changed since this was pinned reviewed-benign — re-review before re-pinning.${O}"
        fi
      done
  done
}

echo "${B}honey scan report${O}  ${D}($WHEN)${O}"
echo "host: $HOST   scanned: $ROOT   files: $FILES   scanner: $VER"
echo

# --- bumblebee section (canonical lens) ------------------------------------
case "$STATUS" in
  clean)
    echo "${G}✓ bumblebee: CLEAN${O} — no exposure matches against the catalogs in $CATDIR." ;;
  incomplete)
    echo "${Y}⚠ bumblebee: INCOMPLETE${O} — hit the time limit (scan_completed=$COMPLETED); coverage is PARTIAL."
    echo "Absence of matches is NOT all-clear. Re-run with a larger BUMBLEBEE_MAX_DURATION or narrower root." ;;
  scan_error)
    echo "${R}✗ bumblebee: SCAN ERROR${O} (scan_exit_code=$(j '.scan_exit_code'))."
    echo "Diagnostics:"; tail -n 5 "$RUN_DIR/diagnostics.ndjson" 2>/dev/null | sed 's/^/  /'
    echo "Full log: $RUN_DIR/update.log" ;;
  exposed)
    # Classify bumblebee matches against the baseline (pinning a known-
    # compromised match is opt-in and rare, but honored uniformly).
    BCLS="$(honey_classify_bumblebee "$FINDINGS")"
    bs="$(printf '%s\n' "$BCLS" | jq -r 'select(._class=="suppressed")|1' 2>/dev/null | grep -c .)"
    bm="$(printf '%s\n' "$BCLS" | jq -r 'select(._class=="mutated")|1'    2>/dev/null | grep -c .)"
    be="$(printf '%s\n' "$BCLS" | jq -r 'select(._class=="expired")|1'    2>/dev/null | grep -c .)"
    ba="$(printf '%s\n' "$BCLS" | jq -r 'select(._class!="suppressed")|1' 2>/dev/null | grep -c .)"
    SUP=$((SUP+bs)); MUT=$((MUT+bm)); EXP=$((EXP+be))
    if [ "$ba" -eq 0 ]; then
      echo "${G}✓ bumblebee: CLEAN${O} — all $TOTAL match(es) suppressed by baseline (review with ./honey-baseline.sh)."
    else
      [ "$(rank exposed)" -gt "$(rank "$OVERALL")" ] && OVERALL="exposed"
      BY_SEV="$(printf '%s\n' "$BCLS" | jq -rs 'map(select(._class!="suppressed")) | group_by(.severity) | map("\(length) \(.[0].severity)") | join(", ")')"
      SUPN=""; [ "$bs" -gt 0 ] && SUPN="  ${D}(+${bs} suppressed)${O}"
      echo "${R}🚨 bumblebee: EXPOSED${O} — $ba match(es): $BY_SEV${SUPN}"
      echo
      printf '%s\n' "$BCLS" | jq -rs --argjson ord "$ORDER" '
        map(select(._class!="suppressed")) | sort_by($ord[.severity] // 9)[] |
        [.severity,.package_name,.version,.ecosystem,.catalog_name,.source_file,.confidence,.catalog_id,._class]
        | @tsv' 2>/dev/null | while IFS=$'\t' read -r SEV PKG VER_ ECO CAT SRC CONF CID CLASS; do
        case "$SEV" in critical|high) C="$R";; medium) C="$Y";; *) C="$D";; esac
        SEV_UC="$(printf '%s' "$SEV" | tr '[:lower:]' '[:upper:]')"  # portable: macOS bash 3.2, no ${x^^}
        echo "  $(class_prefix "$CLASS")${C}● ${SEV_UC}${O}  ${B}$PKG${O} $VER_  ${D}($ECO)${O}"
        echo "      campaign  : $CAT"
        echo "      where     : $SRC"
        case "$CONF" in
          high)   echo "      confidence: high — exact installed version present";;
          medium) echo "      confidence: medium — identity reliable, version/source partial";;
          low)    echo "      confidence: low — config/spec reference, not proof of an installed build";;
          *)      echo "      confidence: $CONF";;
        esac
        echo "      fix       : $(remediation "$ECO" "$PKG" "$VER_")"
        echo "      source    : catalog entry $CID in $CATDIR"
        [ "$CLASS" = "mutated" ] && echo "      ${R}note      : content changed since this was pinned reviewed-benign — re-review before re-pinning.${O}"
      done
    fi ;;
esac

# --- additional lenses ------------------------------------------------------
render_lenses

# --- suppression / policy summary -------------------------------------------
if [ $((SUP+MUT+EXP+REV)) -gt 0 ]; then
  echo
  echo "${D}baseline: ${SUP} suppressed, ${MUT} mutated, ${EXP} expired — honey.baseline.json. Review: ./honey-baseline.sh status${O}"
  [ "$REV" -gt 0 ] && echo "${D}policy: ${REV} finding(s) held below the severity floor (review tier, non-blocking). Floor: ${HONEY_VERDICT_FLOOR:-none} / trusted ${HONEY_VERDICT_FLOOR_TRUSTED:-${HONEY_VERDICT_FLOOR:-none}}.${O}"
  [ "$MUT" -gt 0 ] && echo "${R}⚠ ${MUT} MUTATED: a file pinned as reviewed-benign has CHANGED. Treat as a possible rug pull and re-review.${O}"
fi

# --- overall verdict --------------------------------------------------------
# Suffix tallies so a suppressed/held run can never read as a bare all-clear.
SUFFIX=""
if [ $((SUP+MUT+EXP+REV)) -gt 0 ]; then
  parts=""
  [ "$SUP" -gt 0 ] && parts="${parts}, ${SUP} suppressed"
  [ "$REV" -gt 0 ] && parts="${parts}, ${REV} review"
  [ "$MUT" -gt 0 ] && parts="${parts}, ${MUT} mutated"
  [ "$EXP" -gt 0 ] && parts="${parts}, ${EXP} expired"
  SUFFIX=" (${parts#, })"
fi

echo
if [ "$OVERALL" = "clean" ]; then
  echo "${G}OVERALL: CLEAN${O}${SUFFIX} across bumblebee and all active lenses."
  exit 0
fi
echo "${B}OVERALL: $(printf '%s' "$OVERALL" | tr '[:lower:]' '[:upper:]')${O}${SUFFIX} — address critical/high + high-confidence items first."
echo "Verify each fix manually; honey only reports, it never changes your system. Raw records under: $RUN_DIR"
exit 1
