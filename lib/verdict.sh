#!/usr/bin/env bash
# lib/verdict.sh — honey's verdict policy: provenance tier + severity floor.
#
# Sourced by lib/baseline.sh (so every classified finding carries _provenance and
# _blocking) and thus by report.sh / daily-cycle.sh / honey-baseline.sh. See
# docs/VERDICT.plan.md.
#
# Two dials, both applied at the report/verdict layer AFTER suppression:
#   • Provenance: a finding whose location matches HONEY_TRUSTED_PATTERNS is
#     "first-party" (e.g. Anthropic's claude-plugins-official marketplace);
#     everything else is "third-party".
#   • Severity floor: a finding escalates OVERALL only if its severity is at or
#     above the floor for its provenance. Below-floor findings are still
#     REPORTED (a "review" tier) but do not flip the verdict — so a first-party
#     doc-scanner false positive stops screaming without going invisible.
#
# SAFE DEFAULT: floors default to `none` (every finding blocks, exactly as
# before) — a security tool must not silently hide findings by default. Opt in
# with HONEY_VERDICT_FLOOR_TRUSTED=high to quiet first-party low/medium noise.

# ERE matched against a finding's location to mark it first-party. Empty ⇒
# nothing is first-party (everything third-party). Default trusts Anthropic's
# official marketplace, the usual source of the doc-scan false positives.
honey_trusted_patterns() { printf '%s' "${HONEY_TRUSTED_PATTERNS-claude-plugins-official}"; }

# location -> first-party | third-party
honey_provenance() {
  local loc="$1" pat; pat="$(honey_trusted_patterns)"
  if [ -n "$pat" ] && printf '%s' "$loc" | grep -qE "$pat"; then
    printf 'first-party'
  else
    printf 'third-party'
  fi
}

# severity -> numeric rank (higher = worse). none = 0 so a `none` floor blocks all.
honey_sev_rank() {
  case "$1" in
    critical) echo 5;; high) echo 4;; medium) echo 3;; low) echo 2;; unknown) echo 1;; none) echo 0;; *) echo 1;;
  esac
}

# provenance -> the floor severity that applies to it.
#   third-party/unknown → HONEY_VERDICT_FLOOR            (default none)
#   first-party         → HONEY_VERDICT_FLOOR_TRUSTED    (default = HONEY_VERDICT_FLOOR)
honey_floor_for() {
  local base="${HONEY_VERDICT_FLOOR:-none}"
  case "$1" in
    first-party) printf '%s' "${HONEY_VERDICT_FLOOR_TRUSTED:-$base}" ;;
    *)           printf '%s' "$base" ;;
  esac
}

# severity provenance -> yes | no  (does this finding escalate OVERALL?)
honey_is_blocking() {
  local sev="$1" prov="$2" floor; floor="$(honey_floor_for "$prov")"
  [ "$floor" = "none" ] && { printf 'yes'; return; }
  if [ "$(honey_sev_rank "$sev")" -ge "$(honey_sev_rank "$floor")" ]; then printf 'yes'; else printf 'no'; fi
}
