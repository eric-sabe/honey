#!/usr/bin/env bash
#
# honey lens: smuggle — detect scanner-evasion smuggling in agent-skill and
# instruction files that static pattern scanners (incl. skillspector) miss:
#
#   • invisible Unicode  — tag characters U+E0000–E007F carry ASCII instructions
#                          imperceptibly ("ASCII smuggling"); no legit text use.
#   • bidirectional overrides — U+202A–202E / U+2066–2069, the "Trojan Source"
#                          trick that reorders how source/text renders vs. runs.
#   • zero-width          — U+200B/200C/2060 hidden joiners/spaces (excludes the
#                          emoji ZWJ U+200D to avoid false positives).
#   • remote includes     — instructions telling the agent to fetch/read a remote
#                          URL at runtime (content the on-disk scan never sees).
#
# Honey lens contract:
#   - invoked as:  lenses/smuggle.sh <RUN_DIR>
#   - writes <RUN_DIR>/lens-smuggle.json in honey's normalized shape
#       { lens, tool_version, status, findings_total, findings_by_severity,
#         findings: [ {severity,title,location,detail,ref} ], note }
#     status ∈ clean | exposed | scan_error | skipped
#   - self-skips (exit 0 + "skipped") if perl isn't available — honey's core path
#     is unaffected for anyone without it (perl ships on macOS + most Linux).

set -uo pipefail
RUN_DIR="${1:?usage: smuggle.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-smuggle.json"
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=lib/load-config.sh
[ -f "$HONEY/lib/load-config.sh" ] && . "$HONEY/lib/load-config.sh"

emit() {  # emit STATUS TOTAL BY_SEV_JSON FINDINGS_JSON NOTE
  jq -n --arg lens "smuggle" --arg tv "${SMUGGLE_VERSION:-1}" \
    --arg status "$1" --argjson total "$2" --argjson by_sev "$3" \
    --argjson findings "$4" --arg note "$5" \
    '{lens:$lens, tool_version:$tv, status:$status, findings_total:$total,
      findings_by_severity:$by_sev, findings:$findings, note:$note}' >"$OUT"
}

if ! command -v perl >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "perl not found — smuggle lens skipped (install perl to enable Unicode-smuggling detection)."
  echo "lens smuggle: perl not installed, skipped"
  exit 0
fi

# Same surface as skillspector: agent-skill roots (override via HONEY_SKILL_ROOTS)
# plus any MCP manifests. Text-ish files only; skip the run/vendor noise.
DEFAULT_ROOTS="$HOME/.claude/skills:$HOME/.claude/plugins:$HOME/.claude/scheduled-tasks:$HOME/.config/claude/skills"
ROOTS="${HONEY_SKILL_ROOTS:-$DEFAULT_ROOTS}"
EXCLUDE_RE="${HONEY_SMUGGLE_EXCLUDE:-/node_modules/|/\.git/|/vendor/|/\.pnpm/}"

# Collect candidate files (portable; NUL-delimited to survive odd names).
files_nul="$RUN_DIR/.smuggle-files"
: >"$files_nul"
IFS=':' read -r -a roots <<<"$ROOTS"
for root in "${roots[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -type f \( -name '*.md' -o -name '*.markdown' -o -name '*.txt' \
      -o -name '*.json' -o -name '*.mcp.json' -o -name '*.yaml' -o -name '*.yml' \
      -o -name '*.sh' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \
      -o -name '*.html' -o -name 'SKILL.md' \) -print0 2>/dev/null
done | grep -zvE "$EXCLUDE_RE" >>"$files_nul" 2>/dev/null || true

if [ ! -s "$files_nul" ]; then
  emit "clean" 0 '{}' '[]' "no agent-skill/instruction files found under: $ROOTS"
  echo "lens smuggle: no files to scan"
  rm -f "$files_nul"
  exit 0
fi

# --- Scan (perl): emit TSV  severity<TAB>title<TAB>file<TAB>line<TAB>detail ----
# -CSD: treat args/stdin/stdout as UTF-8. `close ARGV if eof` resets $. per file.
# shellcheck disable=SC2016  # this is a perl program; $vars/$. are perl, not shell
tsv="$(xargs -0 perl -CSD -ne '
    BEGIN { $re_tag  = qr/[\x{E0000}-\x{E007F}]/;
            $re_bidi = qr/[\x{202A}-\x{202E}\x{2066}-\x{2069}]/;
            $re_zw   = qr/[\x{200B}\x{200C}\x{2060}\x{180E}]/;
            $re_url  = qr/(?:curl|wget|fetch|download|retrieve|read|load|import|include|open)\b[^\n]{0,60}https?:\/\//i; }
    if (/($re_tag)/)  { printf "high\tInvisible Unicode (tag chars)\t%s\t%d\tASCII-smuggling codepoint U+%04X — carries hidden instructions invisible to humans and byte scanners\n", $ARGV, $., ord($1); }
    if (/($re_bidi)/) { printf "high\tBidirectional override (Trojan Source)\t%s\t%d\tbidi control U+%04X can reorder how text renders vs. is interpreted\n", $ARGV, $., ord($1); }
    if (/($re_zw)/)   { printf "medium\tZero-width character\t%s\t%d\thidden zero-width codepoint U+%04X (possible token smuggling)\n", $ARGV, $., ord($1); }
    if (/$re_url/)    { printf "medium\tRemote include instruction\t%s\t%d\tinstructs the agent to fetch/read a remote URL — content the on-disk scan never sees\n", $ARGV, $.; }
    close ARGV if eof;
  ' <"$files_nul")"

rm -f "$files_nul"

# Build normalized findings JSON from the TSV.
findings='[]'
if [ -n "$tsv" ]; then
  findings="$(printf '%s\n' "$tsv" | jq -Rc 'select(length>0) | split("\t")
    | {severity:.[0], title:.[1], location:(.[2] + ":" + .[3]), detail:.[4], ref:"scanner-evasion"}' \
    | jq -sc '.')"
fi
[ -n "$findings" ] || findings='[]'

TOTAL="$(printf '%s' "$findings" | jq 'length')"
BY_SEV="$(printf '%s' "$findings" | jq 'group_by(.severity) | map({key:(.[0].severity), value:length}) | from_entries')"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="scanned agent-skill/instruction files under $ROOTS for invisible/bidi/zero-width Unicode + remote-include instructions"

if [ "$TOTAL" -gt 0 ]; then
  emit "exposed" "$TOTAL" "$BY_SEV" "$findings" "$NOTE"
else
  emit "clean" 0 '{}' '[]' "$NOTE"
fi
echo "lens smuggle: status written to $OUT ($TOTAL finding(s))"
exit 0
