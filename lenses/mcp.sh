#!/usr/bin/env bash
#
# honey lens: mcp — inventory MCP server manifests and detect RUG PULLS by
# hashing each server's definition and diffing it across runs.
#
# This closes honey's biggest blind spot: an MCP server defined by a `.mcp.json`
# / host config with no SKILL.md is invisible to the skillspector lens. The
# canonical defense against a manifest-alteration rug pull (a server that earns
# approval with a benign definition, then silently changes) is exactly this:
# "hash the tool manifest on first sight and diff every subsequent run."
# (Invariant Labs / policylayer.)
#
# Findings:
#   • MCP-DRIFT  (high)   — a known server's definition CHANGED since last run.
#   • MCP-NEW    (low)    — a server appeared that wasn't here before.
#   • MCP-RISKY  (medium) — the launch command fetches-and-executes remote code
#                           (curl|wget … | sh/bash, `bash -c`, `eval`).
#
# The first run SEEDS the state silently (everything is "new" on a fresh box, so
# NEW/DRIFT are only reported once a baseline manifest exists). RISKY is
# content-based and reported every run.
#
# Honey lens contract: writes <RUN_DIR>/lens-mcp.json (normalized shape);
# self-skips only if there are no MCP configs to look at. Offline; jq only.

set -uo pipefail
RUN_DIR="${1:?usage: mcp.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-mcp.json"
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=lib/load-config.sh
[ -f "$HONEY/lib/load-config.sh" ] && . "$HONEY/lib/load-config.sh"

STATE="${HONEY_MCP_STATE:-$HONEY/.mcp-state.json}"

emit() {  # STATUS TOTAL BY_SEV FINDINGS NOTE
  jq -n --arg lens "mcp" --arg tv "1" --arg status "$1" --argjson total "$2" \
    --argjson by_sev "$3" --argjson findings "$4" --arg note "$5" \
    '{lens:$lens, tool_version:$tv, status:$status, findings_total:$total,
      findings_by_severity:$by_sev, findings:$findings, note:$note}' >"$OUT"
}

hash_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
  else openssl dgst -sha256 2>/dev/null | awk '{print $NF}'; fi
}

# --- Discover MCP config files ---------------------------------------------
# Host configs (override via HONEY_MCP_CONFIGS, colon-separated) + every
# .mcp.json / mcp.json under the project roots.
DEFAULT_CONFIGS="$HOME/.claude.json:$HOME/Library/Application Support/Claude/claude_desktop_config.json:$HOME/.config/claude/claude_desktop_config.json:$HOME/.cursor/mcp.json:$HOME/.vscode/mcp.json:$HOME/.codeium/windsurf/mcp_config.json"
CONFIGS="${HONEY_MCP_CONFIGS:-$DEFAULT_CONFIGS}"
PROJECT_ROOTS="${HONEY_PROJECT_ROOTS:-$HOME/git:$HOME/code:$HOME/Developer:$HOME/src}"

configs_file="$RUN_DIR/.mcp-configs"; : >"$configs_file"
IFS=':' read -r -a carr <<<"$CONFIGS"
for c in "${carr[@]}"; do [ -f "$c" ] && printf '%s\n' "$c" >>"$configs_file"; done
IFS=':' read -r -a proots <<<"$PROJECT_ROOTS"
for root in "${proots[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 6 \( -name '.mcp.json' -o -name 'mcp.json' \) -type f 2>/dev/null \
    | grep -vE '/node_modules/|/\.git/|/\.claude/worktrees/' >>"$configs_file" 2>/dev/null || true
done
sort -u "$configs_file" -o "$configs_file"

if [ ! -s "$configs_file" ]; then
  emit "skipped" 0 '{}' '[]' "no MCP configs found (looked at host configs + .mcp.json under $PROJECT_ROOTS)"
  echo "lens mcp: no MCP configs, skipped"; rm -f "$configs_file"; exit 0
fi

# --- Extract servers: cfg <TAB> name <TAB> base64(canonical def) ------------
extract="$RUN_DIR/.mcp-servers"; : >"$extract"
while IFS= read -r cfg; do
  [ -n "$cfg" ] || continue
  jq -r --arg cfg "$cfg" '
    def norm: walk(if type=="object" then to_entries|sort_by(.key)|from_entries else . end);
    ((.mcpServers // {}) + (.servers // {}) + (((.projects // {}) | [.[]?.mcpServers // {}]) | add // {}))
    | to_entries[] | [$cfg, .key, (.value | norm | tojson | @base64)] | @tsv
  ' "$cfg" 2>/dev/null >>"$extract" || true
done <"$configs_file"
rm -f "$configs_file"

SEEDING=0
[ -f "$STATE" ] || SEEDING=1
[ -f "$STATE" ] || echo '{"servers":{}}' >"$STATE"

# --- Diff against state + scan for risky commands --------------------------
findings='[]'
newstate='{"servers":{}}'
today="$(date -u +%Y-%m-%d)"
add_finding() {  # severity title location detail
  findings="$(printf '%s' "$findings" | jq -c --arg s "$1" --arg t "$2" --arg l "$3" --arg d "$4" \
    '. + [{severity:$s,title:$t,location:$l,detail:$d,ref:"mcp-manifest"}]')"
}

while IFS=$'\t' read -r cfg name defb64; do
  [ -n "$name" ] || continue
  canonical="$(printf '%s' "$defb64" | base64 -d 2>/dev/null)"
  h="sha256:$(printf '%s' "$canonical" | hash_stdin)"
  key="$cfg::$name"
  prev="$(jq -r --arg k "$key" '.servers[$k].hash // ""' "$STATE" 2>/dev/null)"
  first="$(jq -r --arg k "$key" '.servers[$k].first_seen // ""' "$STATE" 2>/dev/null)"
  [ -n "$first" ] || first="$today"

  if [ "$SEEDING" -eq 0 ]; then
    if [ -z "$prev" ]; then
      add_finding "low" "New MCP server: $name" "$cfg" "server '$name' appeared since the last run — confirm you added it. Definition: $canonical"
    elif [ "$prev" != "$h" ]; then
      add_finding "high" "MCP manifest changed (possible rug pull): $name" "$cfg" "server '$name' definition CHANGED since last run (was ${prev%%:*}:${prev:7:12}…, now ${h:7:12}…). A server that alters its manifest after approval is the canonical rug-pull vector — re-review. Now: $canonical"
    fi
  fi

  # Content check (every run): launch command fetches-and-executes remote code.
  if printf '%s' "$canonical" | grep -qiE '(curl|wget)[^|]*\|[[:space:]]*(sh|bash)|bash[[:space:]]+-c|(^|[^a-z])sh[[:space:]]+-c|[^a-z]eval[^a-z]'; then
    add_finding "medium" "MCP server runs a fetch-and-exec command: $name" "$cfg" "launch command pipes remote content into a shell or uses bash -c/eval — a code-execution vector. Definition: $canonical"
  fi

  newstate="$(printf '%s' "$newstate" | jq -c --arg k "$key" --arg h "$h" --arg f "$first" --arg l "$today" \
    '.servers[$k] = {hash:$h, first_seen:$f, last_seen:$l}')"
done <"$extract"
srvcount="$(wc -l <"$extract" | tr -d ' ')"
rm -f "$extract"

# Persist the new manifest state (current servers only — a removed server just
# drops out; it is not a finding).
printf '%s' "$newstate" | jq '.' >"$STATE" 2>/dev/null || true

TOTAL="$(printf '%s' "$findings" | jq 'length')"
BY_SEV="$(printf '%s' "$findings" | jq 'group_by(.severity) | map({key:(.[0].severity), value:length}) | from_entries')"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="inventoried $srvcount MCP server(s); manifest hash-and-diff for rug pulls (state: $STATE)"
[ "$SEEDING" -eq 1 ] && NOTE="$NOTE; FIRST RUN seeded the baseline manifest (drift/new detection starts next run)"

if [ "$TOTAL" -gt 0 ]; then
  emit "exposed" "$TOTAL" "$BY_SEV" "$findings" "$NOTE"
else
  emit "clean" 0 '{}' '[]' "$NOTE"
fi
echo "lens mcp: status written to $OUT ($TOTAL finding(s), $srvcount server(s), seeding=$SEEDING)"
exit 0
