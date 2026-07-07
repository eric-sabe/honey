#!/usr/bin/env bash
#
# honey/honey-baseline.sh — manage the pin-and-diff suppression baseline.
#
# A baseline entry acknowledges a reviewed finding by (scanner, rule, location,
# occurrence index) AND a sha256 of the referenced content. A matching finding
# whose content still hashes the same is SUPPRESSED (dropped from the verdict,
# still shown). If the content changes, the finding resurfaces as MUTATED.
# See docs/BASELINE.plan.md.
#
# Commands:
#   status [RUN_DIR]                 dry-run: suppressed/mutated/expired/active tally
#   add    [RUN_DIR] <filter> --reason STR [--expires DAYS|never] [--added-by NAME]
#   list   [--expired|--active]      show entries (flags expired)
#   remove <filter>                  drop matching entries
#   prune                            remove expired entries
#
# <filter> (combinable, AND): --all (excludes bumblebee) | --scanner NAME |
#   --severity SEV | --rule TEXT | --location SUBSTR
#
# This tool NEVER changes system state — it only edits honey.baseline.json,
# which you review and commit. honey only reports; it never fixes for you.

set -uo pipefail
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
# shellcheck source=lib/load-config.sh
. "$HONEY/lib/load-config.sh"
# shellcheck source=lib/baseline.sh
. "$HONEY/lib/baseline.sh"

BASELINE="$(honey_baseline_file)"

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; O=$'\033[0m'
else B=""; D=""; R=""; G=""; O=""; fi

die() { echo "honey-baseline: $*" >&2; exit 2; }
usage() { sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ensure_baseline() {
  [ -f "$BASELINE" ] && return 0
  echo "$D(creating $BASELINE)$O" >&2
  printf '{"version":1,"entries":[]}\n' > "$BASELINE"
}

# Resolve a RUN_DIR argument (or the `latest` symlink) from the head of "$@".
# Sets RUN_DIR and shifts it off if it looked like a path.
RUN_DIR=""
resolve_run_dir() {
  if [ "$#" -gt 0 ] && [ -d "$1" ] && [ -f "$1/manifest.json" ]; then
    RUN_DIR="$1"; return 1   # caller must shift
  fi
  RUN_DIR="$(readlink "$HONEY/latest" 2>/dev/null || echo "$HONEY/latest")"
  [ -d "$RUN_DIR" ] || die "no run dir (pass one, or run a scan so $HONEY/latest exists)"
  return 0
}


# --- commands ---------------------------------------------------------------

cmd_status() {
  local shifted; resolve_run_dir "$@"; shifted=$?
  [ "$shifted" -eq 1 ] && shift
  echo "${B}baseline status${O}  ${D}(run: $RUN_DIR)${O}"
  echo "${D}baseline: $BASELINE  ($(honey_baseline_entries | jq 'length') entr$( [ "$(honey_baseline_entries | jq 'length')" = "1" ] && echo y || echo ies ))${O}"
  local all; all="$(honey_classify_run "$RUN_DIR")"
  local s m e a
  s="$(printf '%s\n' "$all" | jq -r 'select(._class=="suppressed")|1' 2>/dev/null | grep -c .)"
  m="$(printf '%s\n' "$all" | jq -r 'select(._class=="mutated")|1'    2>/dev/null | grep -c .)"
  e="$(printf '%s\n' "$all" | jq -r 'select(._class=="expired")|1'    2>/dev/null | grep -c .)"
  a="$(printf '%s\n' "$all" | jq -r 'select(._class=="active")|1'     2>/dev/null | grep -c .)"
  printf '  %sactive:     %s%s   (contribute to the verdict)\n' "$B" "$a" "$O"
  printf '  suppressed: %s   %s(pinned & unchanged — hidden from the verdict)%s\n' "$s" "$D" "$O"
  printf '  %smutated:    %s%s   %s(pinned content CHANGED — resurfaced, review now)%s\n' "$R" "$m" "$O" "$D" "$O"
  printf '  expired:    %s   %s(pin past its expiry — resurfaced)%s\n' "$e" "$D" "$O"
  [ "$m" -gt 0 ] && echo "${R}⚠ ${m} mutated finding(s): a reviewed file changed since it was pinned.${O}"
}

cmd_list() {
  local flt="."; case "${1:-}" in
    --expired) flt='map(select((.expires!="never") and (.expires < (now|strftime("%Y-%m-%d")))))' ;;
    --active)  flt='map(select((.expires=="never") or (.expires >= (now|strftime("%Y-%m-%d")))))' ;;
    "" ) ;; *) die "list: unknown option $1" ;;
  esac
  local today; today="$(honey_today)"
  honey_baseline_entries | jq -r --arg t "$today" "$flt"' | to_entries[] |
    .key as $i | .value |
    (if (.expires!="never" and .expires < $t) then "EXPIRED " else "        " end) +
    "[\(.scanner)] \(.rule)\n           \(.location)  (index \(.index // 0))\n           reason: \(.reason // "")   added: \(.added // "?")   expires: \(.expires // "never")"' \
    2>/dev/null
  local n; n="$(honey_baseline_entries | jq 'length')"
  echo "${D}${n} entr$( [ "$n" = 1 ] && echo y || echo ies ) in $BASELINE${O}"
}

cmd_prune() {
  ensure_baseline
  local before after today; today="$(honey_today)"
  before="$(honey_baseline_entries | jq 'length')"
  local tmp; tmp="$(mktemp)"
  jq --arg t "$today" '.entries |= map(select(.expires=="never" or .expires >= $t))' "$BASELINE" > "$tmp" && mv "$tmp" "$BASELINE"
  after="$(honey_baseline_entries | jq 'length')"
  echo "pruned $((before-after)) expired entr$( [ "$((before-after))" = 1 ] && echo y || echo ies ); $after remain."
}

# Parse the shared <filter> flags into globals + a jq predicate. Consumes the
# recognized flags from "$@" and leaves the rest via the REST array.
F_ALL=0; F_SCANNER=""; F_SEV=""; F_RULE=""; F_LOC=""
REST=()
parse_filter() {
  F_ALL=0; F_SCANNER=""; F_SEV=""; F_RULE=""; F_LOC=""; REST=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --all)       F_ALL=1; shift ;;
      --scanner)   F_SCANNER="${2:-}"; shift 2 ;;
      --severity)  F_SEV="${2:-}"; shift 2 ;;
      --rule)      F_RULE="${2:-}"; shift 2 ;;
      --location)  F_LOC="${2:-}"; shift 2 ;;
      *)           REST+=("$1"); shift ;;
    esac
  done
}
# Did the user give ANY selector? (guards against an accidental match-all.)
filter_given() { [ "$F_ALL" = 1 ] || [ -n "$F_SCANNER" ] || [ -n "$F_SEV" ] || [ -n "$F_RULE" ] || [ -n "$F_LOC" ]; }

# jq predicate over a classified finding (has ._scanner,.severity,.rule,._loc).
# --all excludes bumblebee (pinning a known-compromised match must be explicit).
# shellcheck disable=SC2016  # this is a jq program; $vars are jq args, not shell
jq_pred='
  ($all==1 and ._scanner=="bumblebee" | not) and
  ($scanner=="" or ._scanner==$scanner) and
  ($sev=="" or (.severity//"")==$sev) and
  ($rule=="" or ((.rule//"")|contains($rule))) and
  ($loc=="" or ((._loc//"")|contains($loc)))'

cmd_add() {
  # RUN_DIR may be the first arg; peel it before parsing flags.
  if [ "$#" -gt 0 ] && [ -d "$1" ] && [ -f "$1/manifest.json" ]; then RUN_DIR="$1"; shift
  else resolve_run_dir; fi
  local reason="" expires_days="90" added_by="${USER:-unknown}" args=()
  # Split honey-baseline-specific flags from the shared filter flags.
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --reason)   reason="${2:-}"; shift 2 ;;
      --expires)  expires_days="${2:-}"; shift 2 ;;
      --added-by) added_by="${2:-}"; shift 2 ;;
      *)          args+=("$1"); shift ;;
    esac
  done
  parse_filter "${args[@]:-}"
  [ -n "$reason" ] || die "add: --reason is required (why is this finding benign?)"
  filter_given     || die "add: refusing to pin with no selector — pass --all or a --scanner/--severity/--rule/--location filter"

  local expires
  if [ "$expires_days" = "never" ]; then expires="never"
  else
    case "$expires_days" in (*[!0-9]*) die "add: --expires must be a number of days or 'never'";; esac
    expires="$(date -u -v +"${expires_days}"d +%Y-%m-%d 2>/dev/null || date -u -d "+${expires_days} days" +%Y-%m-%d 2>/dev/null)"
    [ -n "$expires" ] || die "add: could not compute expiry date"
  fi
  local added; added="$(honey_today)"
  ensure_baseline

  # Select matching findings, compute a content hash for each NOW, emit entries.
  local sel new count
  sel="$(honey_classify_run "$RUN_DIR" \
        | jq -c --argjson all "$F_ALL" --arg scanner "$F_SCANNER" --arg sev "$F_SEV" \
               --arg rule "$F_RULE" --arg loc "$F_LOC" "select($jq_pred)")"
  count="$(printf '%s\n' "$sel" | grep -c .)"
  [ "$count" -gt 0 ] || { echo "add: no findings matched that filter in $RUN_DIR"; return 0; }

  local newfile; newfile="$(mktemp)"
  : > "$newfile"
  printf '%s\n' "$sel" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    local scanner rule loc idx csource chash locfile absfile
    scanner="$(printf '%s' "$f" | jq -r '._scanner')"
    rule="$(printf '%s' "$f" | jq -r '.rule // ""')"
    loc="$(printf '%s' "$f" | jq -r '._loc // ""')"
    idx="$(printf '%s' "$f" | jq -r '._index // 0')"
    locfile="$(honey_loc_file "$loc")"
    absfile="$(honey_untildify "$locfile")"
    if [ -f "$absfile" ]; then
      chash="$(honey_hash_file "$absfile")"; csource="file"
    else
      chash="$(printf '%s' "$f" | jq -Sc 'with_entries(select(.key|startswith("_")|not))' | honey_hash_stdin)"; csource="finding"
    fi
    printf '%s' "$f" | jq -c \
      --arg sc "$scanner" --arg r "$rule" --arg l "$loc" --argjson i "$idx" \
      --arg ch "$chash" --arg cs "$csource" --arg rs "$reason" \
      --arg ad "$added" --arg ex "$expires" --arg by "$added_by" \
      '{scanner:$sc, rule:$r, location:$l, index:$i, content_hash:$ch, content_source:$cs,
        severity:(.severity//"unknown"), reason:$rs, added:$ad, expires:$ex, added_by:$by}' >> "$newfile"
  done

  new="$(jq -sc '.' "$newfile")"; rm -f "$newfile"
  # Merge: new entries replace any existing pin with the same identity key.
  local tmp; tmp="$(mktemp)"
  jq --argjson new "$new" '
    def key: "\(.scanner)\(.rule)\(.location)\(.index // 0)";
    ($new | map(key)) as $nk
    | .entries = ((.entries // []) | map(select((key) as $k | ($nk | index($k) | not))) + $new)
  ' "$BASELINE" > "$tmp" && mv "$tmp" "$BASELINE"
  local bcount; bcount="$(printf '%s' "$new" | jq 'map(select(.scanner=="bumblebee"))|length')"
  echo "${G}pinned ${count} finding(s)${O} into $BASELINE (expires: $expires)."
  [ "$bcount" -gt 0 ] && echo "${R}⚠ ${bcount} of these are bumblebee (known-compromised) matches — make sure that is intended.${O}"
  echo "${D}Review the diff and commit honey.baseline.json.${O}"
}

cmd_remove() {
  ensure_baseline
  parse_filter "$@"
  filter_given || die "remove: pass a selector (--all/--scanner/--severity/--rule/--location)"
  local before after tmp; before="$(honey_baseline_entries | jq 'length')"
  tmp="$(mktemp)"
  # For removal, --all means "every non-bumblebee entry"; reuse the same pred
  # against baseline entries (they carry .scanner/.rule/.location, no ._loc).
  jq --argjson all "$F_ALL" --arg scanner "$F_SCANNER" --arg sev "$F_SEV" \
     --arg rule "$F_RULE" --arg loc "$F_LOC" '
     .entries |= map(select(
       (($all==1 and .scanner=="bumblebee" | not) and
        ($scanner=="" or .scanner==$scanner) and
        ($sev=="" or (.severity//"")==$sev) and
        ($rule=="" or ((.rule//"")|contains($rule))) and
        ($loc=="" or ((.location//"")|contains($loc)))) | not))' \
     "$BASELINE" > "$tmp" && mv "$tmp" "$BASELINE"
  after="$(honey_baseline_entries | jq 'length')"
  echo "removed $((before-after)) entr$( [ "$((before-after))" = 1 ] && echo y || echo ies ); $after remain."
}

# --- dispatch ---------------------------------------------------------------

cmd="${1:-}"; [ "$#" -gt 0 ] && shift || true
case "$cmd" in
  status)        cmd_status "$@" ;;
  add)           cmd_add "$@" ;;
  list)          cmd_list "$@" ;;
  remove|rm)     cmd_remove "$@" ;;
  prune)         cmd_prune ;;
  -h|--help|help|"") usage 0 ;;
  *)             die "unknown command '$cmd' (try: status add list remove prune)" ;;
esac
