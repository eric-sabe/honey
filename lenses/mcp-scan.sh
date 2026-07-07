#!/usr/bin/env bash
#
# honey lens: mcp-scan — wrap Invariant Labs' mcp-scan / Snyk Agent Scan for a
# hybrid (deterministic-rules + calibrated-model) read of MCP servers and agent
# skills: tool poisoning, tool shadowing, toxic flows, prompt injection, etc.
#
# OPT-IN and NOT offline. Unlike honey's other lenses, mcp-scan's default mode
# invokes a CLOUD API (Snyk Agent Scan / Invariant Guardrails) and shares tool
# names + descriptions with the vendor; even --local-only needs an OPENAI key.
# So this lens SELF-SKIPS unless you explicitly opt in with:
#     export HONEY_ENABLE_MCP_SCAN=1
# and it never runs in the default daily cycle otherwise. honey's native `mcp`
# lens (offline manifest diffing) covers the no-phone-home path.
#
# Contract: writes <RUN_DIR>/lens-mcp-scan.json (normalized shape).

set -uo pipefail
RUN_DIR="${1:?usage: mcp-scan.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-mcp-scan.json"
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=lib/load-config.sh
[ -f "$HONEY/lib/load-config.sh" ] && . "$HONEY/lib/load-config.sh"

emit() {  # STATUS TOTAL BY_SEV FINDINGS NOTE
  jq -n --arg lens "mcp-scan" --arg tv "${MCP_SCAN_VERSION:-unknown}" --arg status "$1" \
    --argjson total "$2" --argjson by_sev "$3" --argjson findings "$4" --arg note "$5" \
    '{lens:$lens, tool_version:$tv, status:$status, findings_total:$total,
      findings_by_severity:$by_sev, findings:$findings, note:$note}' >"$OUT"
}

# Opt-in gate: this lens phones home, so it stays inert unless explicitly enabled.
if [ "${HONEY_ENABLE_MCP_SCAN:-0}" != "1" ]; then
  emit "skipped" 0 '{}' '[]' "opt-in lens (cloud/phones home) — set HONEY_ENABLE_MCP_SCAN=1 to enable; honey's native offline 'mcp' lens covers the no-network path."
  echo "lens mcp-scan: not enabled (opt-in), skipped"
  exit 0
fi
if ! command -v mcp-scan >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "HONEY_ENABLE_MCP_SCAN=1 but mcp-scan not installed — see https://github.com/snyk/agent-scan (pip install mcp-scan / uvx mcp-scan)."
  echo "lens mcp-scan: enabled but not installed, skipped"
  exit 0
fi

MCP_SCAN_VERSION="$(mcp-scan --version 2>/dev/null | head -1)"
raw="$RUN_DIR/.mcp-scan-raw.json"
# --local-only keeps the heaviest cloud call off (still needs an OPENAI key per
# the tool's docs); pass extra args via HONEY_MCP_SCAN_ARGS.
# shellcheck disable=SC2086  # intentional word-splitting of the args string
if ! mcp-scan scan --json ${HONEY_MCP_SCAN_ARGS:---local-only} >"$raw" 2>"$RUN_DIR/.mcp-scan.log"; then
  # mcp-scan exits nonzero when it finds issues; only treat non-JSON as an error.
  if ! jq -e . "$raw" >/dev/null 2>&1; then
    emit "scan_error" 0 '{}' '[]' "mcp-scan produced no valid JSON — see $RUN_DIR/.mcp-scan.log (auth? SNYK_TOKEN/OPENAI_API_KEY needed for non-local scans)."
    echo "lens mcp-scan: no valid JSON"; exit 0
  fi
fi

# Normalize defensively: the schema varies across mcp-scan/agent-scan versions,
# so map the common field names and fall back gracefully. Verify on first real
# run and tune via jq if the shape differs.
findings="$(jq -c '
  [ (.. | objects | select((.severity? // .risk? // .level?) and (.title? // .name? // .label? // .issue? // .description?))) ]
  | map({
      severity: ((.severity // .risk // .level // "unknown") | ascii_downcase),
      title:    (.title // .name // .label // .issue // "mcp-scan finding"),
      location: (.location // .path // .server // .tool // .file // ""),
      detail:   (.description // .detail // .message // ""),
      ref:      (.code // .rule // "mcp-scan")
    })
  | unique' "$raw" 2>/dev/null)"
[ -n "$findings" ] || findings='[]'
rm -f "$raw"

TOTAL="$(printf '%s' "$findings" | jq 'length')"
BY_SEV="$(printf '%s' "$findings" | jq 'group_by(.severity) | map({key:(.[0].severity), value:length}) | from_entries')"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="mcp-scan / Snyk Agent Scan (${MCP_SCAN_VERSION:-?}); hybrid rules+model analysis. Args: ${HONEY_MCP_SCAN_ARGS:---local-only}"

if [ "$TOTAL" -gt 0 ]; then
  emit "exposed" "$TOTAL" "$BY_SEV" "$findings" "$NOTE"
else
  emit "clean" 0 '{}' '[]' "$NOTE"
fi
echo "lens mcp-scan: status written to $OUT ($TOTAL finding(s))"
exit 0
