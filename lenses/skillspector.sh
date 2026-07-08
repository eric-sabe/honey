#!/usr/bin/env bash
#
# honey lens: skillspector — scan installed AI agent skills for malicious /
# vulnerable patterns using NVIDIA SkillSpector (https://github.com/NVIDIA/skillspector).
#
# Honey lens contract:
#   - invoked as:  lenses/skillspector.sh <RUN_DIR>
#   - if its tool isn't installed, print a skip note and exit 0 (inert — honey's
#     core path is unaffected for users who don't opt in).
#   - otherwise write <RUN_DIR>/lens-skillspector.json in honey's normalized shape:
#       { lens, tool_version, status, findings_total, findings_by_severity,
#         findings: [ {severity,title,location,detail,ref} ], note }
#     status ∈ clean | exposed | scan_error   (exposed = at least one finding)
#
# Defaults to STATIC analysis (--no-llm): deterministic, no API keys, ~offline.
# Set HONEY_SKILLSPECTOR_LLM=1 to enable SkillSpector's own LLM stage (needs a
# provider + key configured per its docs). honey's "centralized Claude analysis"
# happens at the report layer, so the LLM stage stays OFF here by default.

set -uo pipefail
RUN_DIR="${1:?usage: skillspector.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-skillspector.json"

# Where agent skills live (colon-separated; override via HONEY_SKILL_ROOTS).
DEFAULT_ROOTS="$HOME/.claude/skills:$HOME/.claude/plugins:$HOME/.claude/scheduled-tasks:$HOME/.config/claude/skills"
SKILL_ROOTS="${HONEY_SKILL_ROOTS:-$DEFAULT_ROOTS}"

emit() {  # emit STATUS TOTAL BY_SEV_JSON FINDINGS_JSON NOTE
  jq -n \
    --arg lens "skillspector" \
    --arg tv "${SS_VERSION:-unknown}" \
    --arg status "$1" --argjson total "$2" \
    --argjson by_sev "$3" --argjson findings "$4" --arg note "$5" \
    '{lens:$lens, tool_version:$tv, status:$status, findings_total:$total,
      findings_by_severity:$by_sev, findings:$findings, note:$note}' >"$OUT"
}

# --- Skip cleanly if SkillSpector isn't installed --------------------------
if ! command -v skillspector >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "skillspector not installed — lens skipped. See README (Agent-skill lens)."
  echo "lens skillspector: not installed, skipped"
  exit 0
fi
SS_VERSION="$(skillspector --version 2>/dev/null | head -1)"

# NOTE on freshness: unlike the Go lenses (which honey can `go install @latest`)
# and unlike osv-scanner/govulncheck (whose vuln DATA is live), SkillSpector's
# detection PATTERNS are bundled in the installed package — frozen at install.
# honey will not auto-update it because its install method is the user's choice
# (pip / pipx / venv) and honey never mutates Python environments. Refresh it
# yourself periodically per its README to get new patterns. (HONEY_UPDATE_LENSES
# governs the Go lenses; it deliberately does not touch this one.)

LLM_FLAG="--no-llm"
[ "${HONEY_SKILLSPECTOR_LLM:-0}" = "1" ] && LLM_FLAG=""

# --- Discover skills to scan ------------------------------------------------
# Each directory containing a SKILL.md is one skill. Collect them portably.
skills=()
IFS=':' read -r -a roots <<<"$SKILL_ROOTS"
for root in "${roots[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r md; do
    skills+=("$(dirname "$md")")
  done < <(find "$root" -name SKILL.md -type f 2>/dev/null)
done

if [ "${#skills[@]}" -eq 0 ]; then
  emit "clean" 0 '{}' '[]' "no agent skills found under: $SKILL_ROOTS"
  echo "lens skillspector: no skills found"
  exit 0
fi

# --- Scan each skill, collect normalized findings ---------------------------
work="$RUN_DIR/.skillspector"; mkdir -p "$work"
all_findings="[]"; errors=0; scanned=0

for skill in "${skills[@]}"; do
  scanned=$((scanned+1))
  raw="$work/$(echo "$skill" | tr '/ ' '__').json"
  # SkillSpector exits 1 when it FINDS issues — that is success, not an error.
  # So we judge by whether valid JSON was produced, not by the exit code.
  skillspector scan "$skill" $LLM_FLAG --format json --output "$raw" >/dev/null 2>>"$work/errors.log"
  if ! jq -e . "$raw" >/dev/null 2>&1; then
    echo "scan produced no valid JSON for: $skill" >>"$work/errors.log"
    errors=$((errors+1)); continue
  fi
  # Schema guard: honey normalizes the `issues[]` array. If a future SkillSpector
  # renames/drops it, `(.issues // [])` would silently yield ZERO findings — a
  # false "clean". Treat valid-JSON-without-`issues` as a schema-drift ERROR so
  # it surfaces as scan_error (visible), never a silent all-clear.
  if ! jq -e 'has("issues")' "$raw" >/dev/null 2>&1; then
    echo "SCHEMA DRIFT: SkillSpector output for $skill has no top-level .issues (output format changed? re-verify the lens normalizer)" >>"$work/errors.log"
    errors=$((errors+1)); continue
  fi
  # Normalize `issues[]` into honey's finding shape. Schema verified against
  # SkillSpector v2.0.0 and v2.3.11 --format json output (issues[] is the tool's
  # documented "core contract": id/pattern/severity/category/location).
  norm="$(jq --arg skill "$skill" '
    (.issues // []) | map({
      severity: ((.severity // "unknown") | ascii_downcase),
      title: ((.id // "") + (if .pattern then " " + .pattern else "" end) | ltrimstr(" ")),
      location: ($skill + "/" + ((.location.file) // "SKILL.md")
                 + (if .location.start_line then ":" + (.location.start_line|tostring) else "" end)),
      detail: (.explanation // .finding // .intent // ""),
      ref: (.category // "")
    })' "$raw" 2>/dev/null)"
  [ -n "$norm" ] && all_findings="$(jq -s 'add' <(printf '%s' "$all_findings") <(printf '%s' "$norm") 2>/dev/null)"
done

TOTAL="$(printf '%s' "$all_findings" | jq 'length' 2>/dev/null || echo 0)"
BY_SEV="$(printf '%s' "$all_findings" | jq 'group_by(.severity)
  | map({key:(.[0].severity), value:length}) | from_entries' 2>/dev/null)"
[ -z "$BY_SEV" ] && BY_SEV='{}'

NOTE="scanned $scanned skill(s) under $SKILL_ROOTS"
[ "$errors" -gt 0 ] && NOTE="$NOTE; $errors scan error(s) — see $work/errors.log"
[ -z "$LLM_FLAG" ] && NOTE="$NOTE; LLM stage ON"

if [ "$errors" -gt 0 ] && [ "$TOTAL" -eq 0 ]; then
  emit "scan_error" 0 '{}' '[]' "$NOTE"
elif [ "$TOTAL" -gt 0 ]; then
  emit "exposed" "$TOTAL" "$BY_SEV" "$all_findings" "$NOTE"
else
  emit "clean" 0 '{}' '[]' "$NOTE"
fi
echo "lens skillspector: status written to $OUT ($TOTAL finding(s), $scanned skill(s))"
exit 0
