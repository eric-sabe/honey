#!/usr/bin/env bash
#
# honey lens: ocr — extract text from images bundled in agent skills and flag
# hidden INSTRUCTIONS, the multimodal blind spot ("SkillCamo"): current skill
# scanners read text/manifests but not images, so malicious operational
# instructions rendered into an image evade scanning yet are recovered by a
# multimodal agent at runtime. This lens OCRs the images and scans the text.
#
# Offline: uses tesseract (Apache-2.0). Self-skips (exit 0 + "skipped") if
# tesseract isn't installed — honey's core path is unaffected.
#
# Finding: OCR-INJECT (high) — an image contains instruction/exfil/injection
# text it has no business carrying (agent skills use images for diagrams/logos,
# not instructions).

set -uo pipefail
RUN_DIR="${1:?usage: ocr.sh <RUN_DIR>}"
OUT="$RUN_DIR/lens-ocr.json"
HONEY="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=lib/load-config.sh
[ -f "$HONEY/lib/load-config.sh" ] && . "$HONEY/lib/load-config.sh"

emit() {  # STATUS TOTAL BY_SEV FINDINGS NOTE
  jq -n --arg lens "ocr" --arg tv "${OCR_VERSION:-1}" --arg status "$1" --argjson total "$2" \
    --argjson by_sev "$3" --argjson findings "$4" --arg note "$5" \
    '{lens:$lens, tool_version:$tv, status:$status, findings_total:$total,
      findings_by_severity:$by_sev, findings:$findings, note:$note}' >"$OUT"
}

if ! command -v tesseract >/dev/null 2>&1; then
  emit "skipped" 0 '{}' '[]' "tesseract not found — ocr lens skipped (brew install tesseract / apt-get install tesseract-ocr to enable image-payload detection)."
  echo "lens ocr: tesseract not installed, skipped"; exit 0
fi

DEFAULT_ROOTS="$HOME/.claude/skills:$HOME/.claude/plugins:$HOME/.claude/scheduled-tasks:$HOME/.config/claude/skills"
ROOTS="${HONEY_SKILL_ROOTS:-$DEFAULT_ROOTS}"
MAX="${HONEY_OCR_MAX:-300}"          # cap images scanned (OCR is the slow part)
# Instruction/exfil/injection markers that have no place in a skill image.
INJECT_RE="${HONEY_OCR_PATTERNS:-ignore[[:space:]]+(the[[:space:]]+)?(previous|prior|above|earlier|all)|disregard[[:space:]]+(the|all|any)|system[[:space:]]+prompt|exfiltrat|curl[[:space:]]+[^[:space:]]*http|wget[[:space:]]+[^[:space:]]*http|base64[[:space:]]+-d|~/\.(ssh|aws|config)|do[[:space:]]+not[[:space:]]+(tell|reveal|mention|inform)|override[[:space:]].*instruction|send[[:space:]]+.*(token|secret|credential|key)}"

# Collect images.
imgs="$RUN_DIR/.ocr-imgs"; : >"$imgs"
IFS=':' read -r -a roots <<<"$ROOTS"
for root in "${roots[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \
      -o -iname '*.tif' -o -iname '*.tiff' -o -iname '*.bmp' -o -iname '*.gif' -o -iname '*.webp' \) \
      -print 2>/dev/null
done | head -n "$MAX" >>"$imgs"

if [ ! -s "$imgs" ]; then
  emit "clean" 0 '{}' '[]' "no images found under agent-skill roots: $ROOTS"
  echo "lens ocr: no images to scan"; rm -f "$imgs"; exit 0
fi

findings='[]'; scanned=0
while IFS= read -r img; do
  [ -n "$img" ] || continue
  scanned=$((scanned+1))
  # Feed the image via stdin, not by path: some leptonica builds mis-read certain
  # absolute paths ("Image file cannot be read"); stdin sidesteps path resolution.
  text="$(tesseract stdin stdout <"$img" 2>/dev/null)" || continue
  [ -n "$text" ] || continue
  hit="$(printf '%s' "$text" | grep -ioE "$INJECT_RE" | head -1)"
  if [ -n "$hit" ]; then
    snippet="$(printf '%s' "$text" | tr '\n' ' ' | grep -ioE ".{0,30}${hit}.{0,30}" | head -1)"
    [ -n "$snippet" ] || snippet="$hit"
    findings="$(printf '%s' "$findings" | jq -c --arg l "$img" --arg d "OCR recovered instruction-like text from this image (possible SkillCamo hidden payload): …${snippet}…" \
      '. + [{severity:"high", title:"Instructions hidden in image (possible SkillCamo)", location:$l, detail:$d, ref:"multimodal-evasion"}]')"
  fi
done <"$imgs"
rm -f "$imgs"

TOTAL="$(printf '%s' "$findings" | jq 'length')"
BY_SEV="$(printf '%s' "$findings" | jq 'group_by(.severity) | map({key:(.[0].severity), value:length}) | from_entries')"
[ -z "$BY_SEV" ] && BY_SEV='{}'
NOTE="OCR-scanned $scanned image(s) under $ROOTS for hidden instructions (tesseract $(tesseract --version 2>&1 | head -1 | awk '{print $2}'))"

if [ "$TOTAL" -gt 0 ]; then
  emit "exposed" "$TOTAL" "$BY_SEV" "$findings" "$NOTE"
else
  emit "clean" 0 '{}' '[]' "$NOTE"
fi
echo "lens ocr: status written to $OUT ($TOTAL finding(s), $scanned image(s))"
exit 0
