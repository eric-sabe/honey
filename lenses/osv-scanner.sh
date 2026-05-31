#!/usr/bin/env bash
#
# honey lens: osv-scanner — scan project lockfiles/manifests across ecosystems
# for known vulnerabilities using Google/OSV osv-scanner
# (https://github.com/google/osv-scanner).
#
# Honey lens contract (see lenses/skillspector.sh): invoked as
#   lenses/osv-scanner.sh <RUN_DIR>
# self-skips inert if osv-scanner isn't installed; otherwise writes
#   <RUN_DIR>/lens-osv-scanner.json  in honey's normalized shape:
#     { lens, tool_version, status, findings_total, findings_by_severity,
#       findings:[{severity,title,location,detail,ref}], note }
#
# Scope: directories in HONEY_PROJECT_ROOTS (colon-separated; default the usual
# project dirs). NOT $HOME — vuln scanning targets your projects, not the world.
# Static DB lookup against OSV.dev; set HONEY_OSV_OFFLINE=1 to use local DBs.

set -uo pipefail
RUN_DIR="${1:?usage: osv-scanner.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-osv-scanner.json"

DEFAULT_ROOTS="$HOME/git:$HOME/code:$HOME/Developer:$HOME/src"
PROJECT_ROOTS="${HONEY_PROJECT_ROOTS:-$DEFAULT_ROOTS}"

emit() {  # STATUS TOTAL BY_SEV FINDINGS NOTE
  jq -n --arg lens "osv-scanner" --arg tv "${OSV_VERSION:-unknown}" \
    --arg status "$1" --argjson total "$2" --argjson by_sev "$3" \
    --argjson findings "$4" --arg note "$5" \
    '{lens:$lens,tool_version:$tv,status:$status,findings_total:$total,
      findings_by_severity:$by_sev,findings:$findings,note:$note}' >"$OUT"
}

if ! command -v osv-scanner >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "osv-scanner not installed — lens skipped. See README (vuln lenses)."
  echo "lens osv-scanner: not installed, skipped"; exit 0
fi

# Refresh the tool to @latest before scanning (default on; HONEY_UPDATE_LENSES=0
# to skip). Non-fatal: on failure (offline, etc.) we keep the existing binary,
# mirroring how run-scan.sh updates the bumblebee binary. The vuln DATA is
# already live (OSV.dev) every scan; this keeps the BINARY current too.
if [ "${HONEY_UPDATE_LENSES:-1}" = "1" ] && command -v go >/dev/null 2>&1; then
  go install github.com/google/osv-scanner/cmd/osv-scanner@latest >/dev/null 2>&1 \
    && echo "lens osv-scanner: updated to @latest" \
    || echo "lens osv-scanner: update skipped/failed — using existing binary"
fi
OSV_VERSION="$(osv-scanner --version 2>/dev/null | head -1)"

OFFLINE=""; [ "${HONEY_OSV_OFFLINE:-0}" = "1" ] && OFFLINE="--offline-vulnerabilities --download-offline-databases"

# Only scan roots that exist.
roots=()
IFS=':' read -r -a want <<<"$PROJECT_ROOTS"
for r in "${want[@]}"; do [ -d "$r" ] && roots+=("$r"); done
if [ "${#roots[@]}" -eq 0 ]; then
  emit "clean" 0 '{}' '[]' "no project roots found among: $PROJECT_ROOTS"
  echo "lens osv-scanner: no project roots"; exit 0
fi

work="$RUN_DIR/.osv-scanner"; mkdir -p "$work"
raw="$work/osv.json"; : >"$raw"
# osv-scanner exits non-zero when it finds vulns OR on usage error; we judge by
# whether it produced parseable JSON, mirroring how we treat govulncheck.
# shellcheck disable=SC2086  # $OFFLINE is an intentional multi-flag word split
osv-scanner scan --format json $OFFLINE -r "${roots[@]}" >"$raw" 2>"$work/errors.log"
if ! jq -e . "$raw" >/dev/null 2>&1; then
  # "No package sources found" = the roots simply contain no lockfiles/manifests
  # to scan. That is CLEAN (nothing to be vulnerable), NOT a scan error.
  if grep -qi "no package sources found" "$work/errors.log" 2>/dev/null; then
    emit "clean" 0 '{}' '[]' "no lockfiles/manifests found under: ${roots[*]}"
    echo "lens osv-scanner: clean (no package sources)"; exit 0
  fi
  emit "scan_error" 0 '{}' '[]' "osv-scanner produced no valid JSON — see $work/errors.log"
  echo "lens osv-scanner: scan_error (no JSON)"; exit 0
fi

# Normalize: one honey finding per (package, vuln group). max_severity is a
# CVSS 0-10 score; bucket it. Title = pkg@version + advisory ids.
#
# We SKIP Go stdlib advisories here: osv-scanner flags every stdlib CVE for the
# module's `go` directive (often dozens, all without CVSS and mostly
# unreachable). The govulncheck lens owns Go reachability and reports only the
# stdlib vulns you actually call — so deferring stdlib to it avoids a flood of
# low-signal "unknown" findings. (Set HONEY_OSV_INCLUDE_GO_STDLIB=1 to keep them.)
KEEP_STDLIB="${HONEY_OSV_INCLUDE_GO_STDLIB:-0}"
FINDINGS="$(jq --arg keep_stdlib "$KEEP_STDLIB" '[
  (.results // [])[] | (.source.path // "") as $src | (.packages // [])[]
  | (.package.name // "?") as $name | (.package.version // "?") as $ver
  | (.package.ecosystem // "?") as $eco
  | select($keep_stdlib == "1" or .package.name != "stdlib")
  | (.groups // [])[]
  | (.max_severity // "" | if . == "" then null else (try tonumber catch null) end) as $cvss
  | {
      severity: ( if   $cvss == null then "unknown"
                  elif $cvss >= 9 then "critical"
                  elif $cvss >= 7 then "high"
                  elif $cvss >= 4 then "medium"
                  else "low" end ),
      title: ($name + "@" + $ver + " (" + $eco + "): " + ((.ids // []) | join(", "))),
      location: $src,
      detail: ("CVSS " + ($cvss|tostring) + "; advisories: " + ((.ids // []) | join(", "))),
      ref: ((.ids // [])[0] // "")
    }
]' "$raw" 2>"$work/normalize.err")"
# Distinguish a jq normalization FAILURE from a genuinely empty result: a
# failure (schema drift, etc.) must surface as scan_error, never silently
# downgrade a populated scan to "clean". (try/catch above already prevents one
# bad CVSS from nuking the array; this guards total normalizer failure.)
if [ -z "$FINDINGS" ]; then
  emit "scan_error" 0 '{}' '[]' "normalization failed — see $work/normalize.err and $work/errors.log"
  echo "lens osv-scanner: scan_error (normalize failed)"; exit 0
fi

TOTAL="$(printf '%s' "$FINDINGS" | jq 'length' 2>/dev/null || echo 0)"
BY_SEV="$(printf '%s' "$FINDINGS" | jq 'group_by(.severity)|map({key:.[0].severity,value:length})|from_entries' 2>/dev/null)"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="scanned ${#roots[@]} project root(s): ${roots[*]}"
[ -n "$OFFLINE" ] && NOTE="$NOTE; offline DB"
[ "$KEEP_STDLIB" != "1" ] && NOTE="$NOTE; Go stdlib advisories deferred to govulncheck"

if [ "$TOTAL" -gt 0 ]; then emit "exposed" "$TOTAL" "$BY_SEV" "$FINDINGS" "$NOTE"
else emit "clean" 0 '{}' '[]' "$NOTE"; fi
echo "lens osv-scanner: $TOTAL finding(s) across ${#roots[@]} root(s) -> $OUT"
exit 0
