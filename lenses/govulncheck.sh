#!/usr/bin/env bash
#
# honey lens: govulncheck — Go reachability-aware vuln scanning
# (https://golang.org/x/vuln/cmd/govulncheck).
#
# Unlike osv-scanner (which flags any vulnerable module in the graph),
# govulncheck reports only vulnerabilities your code actually CALLS — far less
# noise. honey runs it in every Go module under HONEY_PROJECT_ROOTS.
#
# Honey lens contract: lenses/govulncheck.sh <RUN_DIR> -> lens-govulncheck.json
# self-skips inert if govulncheck (or go) isn't installed.
#
# KEY BEHAVIORAL FACTS (verified against the real tool, not docs):
#  - `-format json` streams Message objects; it EXITS 0 even with vulns, so we
#    judge by content, not exit code.
#  - It emits an `osv` message for every vuln in the graph (NOT actionable on
#    its own) and a `finding` message only for reachable ones. We count ONLY
#    findings, joining each to its osv summary. (155 osv / 0 findings is the
#    "clean" case — reporting osv would be 155 false alarms.)

set -uo pipefail
RUN_DIR="${1:?usage: govulncheck.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-govulncheck.json"

DEFAULT_ROOTS="$HOME/git:$HOME/code:$HOME/Developer:$HOME/src"
PROJECT_ROOTS="${HONEY_PROJECT_ROOTS:-$DEFAULT_ROOTS}"

emit() {  # STATUS TOTAL BY_SEV FINDINGS NOTE
  jq -n --arg lens "govulncheck" --arg tv "${GV_VERSION:-unknown}" \
    --arg status "$1" --argjson total "$2" --argjson by_sev "$3" \
    --argjson findings "$4" --arg note "$5" \
    '{lens:$lens,tool_version:$tv,status:$status,findings_total:$total,
      findings_by_severity:$by_sev,findings:$findings,note:$note}' >"$OUT"
}

if ! command -v govulncheck >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "govulncheck not installed — lens skipped. See README (vuln lenses)."
  echo "lens govulncheck: not installed, skipped"; exit 0
fi
command -v go >/dev/null 2>&1 || { emit "skipped" 0 '{}' '[]' "go not installed — govulncheck needs it; skipped."; echo "lens govulncheck: go missing, skipped"; exit 0; }
GV_VERSION="$(govulncheck -version 2>/dev/null | head -1)"

# Discover Go modules (dirs containing go.mod) under the project roots.
modules=()
IFS=':' read -r -a roots <<<"$PROJECT_ROOTS"
for root in "${roots[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r gm; do modules+=("$(dirname "$gm")"); done \
    < <(find "$root" -name go.mod -type f -not -path '*/vendor/*' 2>/dev/null)
done

if [ "${#modules[@]}" -eq 0 ]; then
  emit "clean" 0 '{}' '[]' "no Go modules found under: $PROJECT_ROOTS"
  echo "lens govulncheck: no Go modules"; exit 0
fi

work="$RUN_DIR/.govulncheck"; mkdir -p "$work"
all="[]"; scanned=0; errors=0
for mod in "${modules[@]}"; do
  scanned=$((scanned+1))
  raw="$work/$(echo "$mod" | tr '/ ' '__').json"
  ( cd "$mod" && govulncheck -format json ./... ) >"$raw" 2>>"$work/errors.log"
  # Output is a stream of pretty-printed JSON objects; validate the whole
  # stream with `jq -s` (NOT head -1, which only sees the opening brace).
  if ! jq -es . "$raw" >/dev/null 2>&1; then errors=$((errors+1)); continue; fi
  # Build osv-id -> summary map, then emit one finding per reachable `finding`
  # message (dedup by osv id within this module). Report the top trace frame.
  norm="$(jq -rs --arg mod "$mod" '
    (map(select(.osv) | {(.osv.id): (.osv.summary // .osv.id)}) | add // {}) as $sum
    | [ .[] | select(.finding) | .finding
        | select((.trace // []) | length > 0)
        | select(.osv != null) ]
    | unique_by(.osv)
    | map({
        severity: "unknown",
        title: (.osv + ": " + ($sum[.osv] // "vulnerability")),
        location: ($mod + (if (.trace[0].package // "") != "" then " (" + .trace[0].package + ")" else "" end)),
        detail: ( "reachable in " + (.trace[0].module // "?")
                  + (if .trace[0].function then " via " + (.trace[0].function) else "" end)
                  + (if (.fixed_version // "") != "" then "; fixed in " + .fixed_version else "; no fix available" end) ),
        ref: .osv
      })' "$raw" 2>/dev/null)"
  [ -n "$norm" ] && all="$(jq -s 'add' <(printf '%s' "$all") <(printf '%s' "$norm") 2>/dev/null)"
done

TOTAL="$(printf '%s' "$all" | jq 'length' 2>/dev/null || echo 0)"
# govulncheck JSON has no CVSS; all findings are reachable => treat as high.
all="$(printf '%s' "$all" | jq 'map(.severity = "high")' 2>/dev/null)"
BY_SEV="$(printf '%s' "$all" | jq 'group_by(.severity)|map({key:.[0].severity,value:length})|from_entries' 2>/dev/null)"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="scanned $scanned Go module(s) under $PROJECT_ROOTS; reachable vulns only"
[ "$errors" -gt 0 ] && NOTE="$NOTE; $errors module error(s) — see $work/errors.log"

if [ "$errors" -gt 0 ] && [ "$TOTAL" -eq 0 ]; then emit "scan_error" 0 '{}' '[]' "$NOTE"
elif [ "$TOTAL" -gt 0 ]; then emit "exposed" "$TOTAL" "$BY_SEV" "$all" "$NOTE"
else emit "clean" 0 '{}' '[]' "$NOTE"; fi
echo "lens govulncheck: $TOTAL reachable finding(s) across $scanned module(s) -> $OUT"
exit 0
