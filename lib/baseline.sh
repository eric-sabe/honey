#!/usr/bin/env bash
# lib/baseline.sh — honey's pin-and-diff suppression baseline (shared core).
#
# Sourced by report.sh, daily-cycle.sh, and honey-baseline.sh so all three agree
# on one classification. See docs/BASELINE.plan.md for the full design.
#
# The model: a baseline entry pins a finding by (scanner, rule, ~-relative
# location, occurrence index) AND a sha256 of the referenced file's content.
# A live finding that matches a pin AND whose file hash still matches is
# SUPPRESSED (dropped from the verdict, kept in the report). If the file hash
# has CHANGED, the finding is MUTATED - it resurfaces loudly (the rug-pull
# tripwire). An expired pin lets its finding resurface as normal.
#
# Portability: pure bash 3.2 + jq. No associative arrays, no ${x^^}. Occurrence
# indices and path tildify are done in jq (deterministic), not in shell.

# --- config -----------------------------------------------------------------

# Absolute path to the baseline file. Override with HONEY_BASELINE.
honey_baseline_file() {
  if [ -n "${HONEY_BASELINE:-}" ]; then printf '%s' "$HONEY_BASELINE"; return; fi
  local root="${HONEY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  printf '%s/honey.baseline.json' "$root"
}

# Emit the entries array (or [] when the file is absent/empty/malformed).
honey_baseline_entries() {
  local f; f="$(honey_baseline_file)"
  [ -f "$f" ] || { printf '[]'; return; }
  jq -c '.entries // []' "$f" 2>/dev/null || printf '[]'
}

# --- path helpers -----------------------------------------------------------

# ~/foo -> $HOME/foo  (inverse of the jq tildify used during classification).
# The literal ~ is intentional here (we match a stored "~/…" prefix, we are not
# asking the shell to expand a tilde), so SC2088 does not apply.
honey_untildify() {
  local p="$1"
  # shellcheck disable=SC2088  # literal ~ prefixes are matched, not expanded
  case "$p" in
    "~/"*) printf '%s/%s' "$HOME" "${p#"~/"}" ;;
    "~")   printf '%s' "$HOME" ;;
    *)     printf '%s' "$p" ;;
  esac
}

# Split a "file:line" location into its FILE part (LINE dropped). A trailing
# :<digits> is the line; the rest (which may contain a Windows drive colon) is
# the file.
honey_loc_file() {
  case "$1" in
    *:[0-9]*) printf '%s' "${1%:*}" ;;
    *)        printf '%s' "$1" ;;
  esac
}

# --- hashing ----------------------------------------------------------------

# Portable sha256 of a file's raw bytes -> "sha256:HEX" (empty on failure).
# Raw bytes on purpose (docs/BASELINE.plan.md section 7): a smuggled-Unicode
# edit changes the bytes -> hash mismatch -> resurfaces. No NFC folding.
honey_hash_file() {
  local f="$1" h=""
  [ -f "$f" ] && [ -r "$f" ] || { printf ''; return; }
  if command -v sha256sum >/dev/null 2>&1; then
    h="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    h="$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    h="$(openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}')"
  fi
  [ -n "$h" ] && printf 'sha256:%s' "$h" || printf ''
}

# sha256 of a string on stdin -> "sha256:HEX". Used for the finding-JSON
# fallback when a finding's location is not an on-disk file.
honey_hash_stdin() {
  local h=""
  if command -v sha256sum >/dev/null 2>&1; then
    h="$(sha256sum 2>/dev/null | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    h="$(shasum -a 256 2>/dev/null | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    h="$(openssl dgst -sha256 2>/dev/null | awk '{print $NF}')"
  fi
  [ -n "$h" ] && printf 'sha256:%s' "$h" || printf ''
}

# Today (UTC) as YYYY-MM-DD. ISO dates compare correctly as strings.
honey_today() { date -u +%Y-%m-%d; }

# --- classification ---------------------------------------------------------
#
# _honey_classify SCANNER  < findings-array-json  > classified-ndjson
#
# Input on stdin: a JSON ARRAY of finding objects, each carrying `.rule` and
# `._rawloc` (absolute match location) plus whatever original fields the
# renderer needs (including the original `.location` for display).
# Output: one JSON object per line, the input finding plus:
#   _loc     ~-relative match location (portable key; gitleaks lesson)
#   _index   occurrence # among identical (rule,_loc) - deterministic
#   _class   active | suppressed | mutated | expired
#   _reason  the pin's reason, else ""
# One jq pass does tildify + occurrence index; the shell loop only hashes the
# referenced file and looks up the pin.
_honey_classify() {
  local scanner="$1"
  local entries today
  entries="$(honey_baseline_entries)"
  today="$(honey_today)"

  jq -c --arg home "$HOME" '
    def tildify($p):
      if   ($p | startswith($home + "/")) then "~/" + ($p[($home|length)+1:])
      elif ($p == $home)                  then "~"
      else $p end;
    [ .[] | . + {_loc: tildify(._rawloc // "")} | del(._rawloc) ] as $arr
    | reduce range(0; ($arr|length)) as $i ({seen:{}, out:[]};
        (($arr[$i].rule // "") + " " + ($arr[$i]._loc // "")) as $k
        | .seen[$k] = ((.seen[$k] // -1) + 1)
        | .out += [ $arr[$i] + {_index: .seen[$k]} ]
      ) | .out[]' 2>/dev/null \
  | while IFS= read -r finding; do
      [ -n "$finding" ] || continue
      local rule loc idx locfile absfile curhash entry expires csource cmp class reason
      rule="$(printf '%s' "$finding" | jq -r '.rule // ""')"
      loc="$(printf '%s' "$finding" | jq -r '._loc // ""')"
      idx="$(printf '%s' "$finding" | jq -r '._index // 0')"

      entry="$(printf '%s' "$entries" | jq -c --arg s "$scanner" --arg r "$rule" \
                 --arg l "$loc" --argjson i "$idx" \
                 'map(select(.scanner==$s and .rule==$r and .location==$l and ((.index // 0)==$i))) | .[0] // empty' 2>/dev/null)"

      if [ -z "$entry" ]; then
        printf '%s' "$finding" | jq -c '. + {_class:"active",_reason:""}'
        continue
      fi

      # A pin exists. Recompute the content hash the same way `add` captured it.
      csource="$(printf '%s' "$entry" | jq -r '.content_source // "file"')"
      if [ "$csource" = "finding" ]; then
        curhash="$(printf '%s' "$finding" | jq -Sc 'with_entries(select(.key|startswith("_")|not))' | honey_hash_stdin)"
      else
        locfile="$(honey_loc_file "$loc")"
        absfile="$(honey_untildify "$locfile")"
        curhash="$(honey_hash_file "$absfile")"
      fi

      expires="$(printf '%s' "$entry" | jq -r '.expires // "never"')"
      reason="$(printf '%s' "$entry" | jq -r '.reason // ""')"
      cmp="$(printf '%s' "$entry" | jq -r '.content_hash // ""')"

      if [ -n "$curhash" ] && [ "$curhash" = "$cmp" ]; then
        # Hash matches the reviewed content: suppress - unless the pin expired.
        if [ "$expires" != "never" ] && [ "$expires" \< "$today" ]; then
          class="expired"
        else
          class="suppressed"
        fi
      else
        # Content changed since review (or file gone): the tripwire. Resurface.
        class="mutated"
      fi
      printf '%s' "$finding" | jq -c --arg c "$class" --arg r "$reason" '. + {_class:$c,_reason:$r}'
    done
}

# Classify a lens's normalized findings (from lens-<name>.json). rule = title;
# match location = finding.location. Prints classified NDJSON.
honey_classify_lens() {
  local scanner="$1" lensjson="$2"
  [ -f "$lensjson" ] || return 0
  jq -c '[ (.findings // [])[] | . + {rule:(.title // ""), _rawloc:(.location // "")} ]' "$lensjson" 2>/dev/null \
  | _honey_classify "$scanner"
}

# Classify bumblebee findings.ndjson. rule = catalog_id|package; match location
# = source_file. Keeps original record fields for rendering.
honey_classify_bumblebee() {
  local ndjson="$1"
  [ -f "$ndjson" ] || return 0
  jq -sc '[ .[] | . + {rule:((.catalog_id // "") + "|" + (.package_name // "")), _rawloc:(.source_file // "")} ]' "$ndjson" 2>/dev/null \
  | _honey_classify "bumblebee"
}

# Classify EVERY scanner in a run dir, tagging each finding with `_scanner`.
# Emits NDJSON. Used by the management CLI (status/add/remove).
honey_classify_run() {
  local run_dir="$1" lj name
  if [ -f "$run_dir/findings.ndjson" ]; then
    honey_classify_bumblebee "$run_dir/findings.ndjson" \
      | jq -c '. + {_scanner:"bumblebee"}'
  fi
  for lj in "$run_dir"/lens-*.json; do
    [ -f "$lj" ] || continue
    name="$(jq -r '.lens // ""' "$lj" 2>/dev/null)"
    [ -n "$name" ] || continue
    honey_classify_lens "$name" "$lj" \
      | jq -c --arg s "$name" '. + {_scanner:$s}'
  done
}

# --- verdict ----------------------------------------------------------------

# baseline_effective_overall RUN_DIR
# Echoes: "STATUS suppressed=N mutated=M expired=K"
# STATUS is the worst-wins status across bumblebee + lenses AFTER suppression.
# Only `exposed` findings are re-evaluated; incomplete/scan_error/skipped pass
# through untouched (a baseline never downgrades partial coverage or a crash).
baseline_effective_overall() {
  local run_dir="$1"
  local manifest="$run_dir/manifest.json"
  local sup=0 mut=0 exp=0 overall="clean"
  _rank() { case "$1" in scan_error) echo 4;; exposed) echo 3;; incomplete) echo 2;; clean|skipped) echo 1;; *) echo 0;; esac; }
  _worse() { [ "$(_rank "$2")" -gt "$(_rank "$1")" ] && printf '%s' "$2" || printf '%s' "$1"; }
  _cnt() { printf '%s\n' "$1" | jq -r "select(._class==\"$2\")|._class" 2>/dev/null | grep -c . ; }

  # bumblebee
  if [ -f "$manifest" ]; then
    local bst; bst="$(jq -r '.status // "unknown"' "$manifest" 2>/dev/null)"
    if [ "$bst" = "exposed" ] && [ -f "$run_dir/findings.ndjson" ]; then
      local cls s m e a
      cls="$(honey_classify_bumblebee "$run_dir/findings.ndjson")"
      s="$(_cnt "$cls" suppressed)"; m="$(_cnt "$cls" mutated)"; e="$(_cnt "$cls" expired)"
      a="$(printf '%s\n' "$cls" | jq -r 'select(._class!="suppressed")|._class' 2>/dev/null | grep -c .)"
      sup=$((sup+s)); mut=$((mut+m)); exp=$((exp+e))
      [ "$a" -gt 0 ] && overall="$(_worse "$overall" exposed)"
    else
      overall="$(_worse "$overall" "$bst")"
    fi
  fi

  # lenses
  local lj
  for lj in "$run_dir"/lens-*.json; do
    [ -f "$lj" ] || continue
    local name lst
    name="$(jq -r '.lens // ""' "$lj" 2>/dev/null)"
    lst="$(jq -r '.status // "unknown"' "$lj" 2>/dev/null)"
    if [ "$lst" = "exposed" ]; then
      local cls s m e a
      cls="$(honey_classify_lens "$name" "$lj")"
      s="$(_cnt "$cls" suppressed)"; m="$(_cnt "$cls" mutated)"; e="$(_cnt "$cls" expired)"
      a="$(printf '%s\n' "$cls" | jq -r 'select(._class!="suppressed")|._class' 2>/dev/null | grep -c .)"
      sup=$((sup+s)); mut=$((mut+m)); exp=$((exp+e))
      [ "$a" -gt 0 ] && overall="$(_worse "$overall" exposed)"
    else
      overall="$(_worse "$overall" "$lst")"
    fi
  done

  printf '%s suppressed=%s mutated=%s expired=%s' "$overall" "$sup" "$mut" "$exp"
}
