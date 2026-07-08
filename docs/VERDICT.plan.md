# Verdict policy — provenance tier + severity floor — design spec

Status: **implemented** (this branch). Companion to
[`BASELINE.plan.md`](BASELINE.plan.md). Where the baseline pins *specific*
reviewed findings, the verdict policy is the *broad* dial: it decides which
findings escalate `OVERALL` at all.

## 1. Problem

The suppression baseline is surgical — you pin individual reviewed findings. But
the daily noise from a trusted, first-party skill marketplace is *broad*: dozens
of low/medium false positives you don't want to pin one by one, yet don't want
flipping the verdict every day either. And even after the baseline, `OVERALL` is
still a flat worst-wins: a single low finding reads the same as a critical.

## 2. Two dials, applied after suppression

Both operate at the report/verdict layer, on the already-classified findings, so
`report.sh` and `daily-cycle.sh` (and their PowerShell mirrors) agree.

### Provenance
Each finding's location is matched against `HONEY_TRUSTED_PATTERNS` (an ERE,
default `claude-plugins-official` — Anthropic's official marketplace, the usual
source of the doc-scan false positives). A match → **first-party**; otherwise
**third-party**. Provenance is shown in the report (`[1st-party]` tag) and feeds
the floor. Set `HONEY_TRUSTED_PATTERNS=` (empty) to treat everything as
third-party.

### Severity floor
A finding **blocks** (escalates `OVERALL`) only if its severity is at or above
the floor **for its provenance**:

- `HONEY_VERDICT_FLOOR` (default `none`) — floor for third-party/unknown.
- `HONEY_VERDICT_FLOOR_TRUSTED` (default = `HONEY_VERDICT_FLOOR`) — floor for
  first-party.

Values: `none | low | medium | high | critical`. A finding **below** its floor
is **not** dropped — it moves to a **review tier**: still printed (dimmed, marked
`[non-blocking]`), still counted on the verdict line, but it does not flip
`OVERALL`.

## 3. Classification

Every classified finding now also carries `_provenance` and `_blocking`. Three
outcomes for an active (non-suppressed) finding:

| | escalates OVERALL? | shown? |
|---|---|---|
| **blocking** (`_blocking=yes`) | yes | yes, prominent |
| **review** (`_blocking=no`) | no | yes, dimmed `[non-blocking]` |
| suppressed (from the baseline) | no | summarized only |

## 4. Non-negotiable overrides

The floor is a *lens-noise* dial, never a way to mute genuinely dangerous
findings. Regardless of floor:

- **bumblebee always blocks** — it is the known-compromised-package catalog
  scanner; a match is never "review".
- **MUTATED pins always block** — the rug-pull tripwire fires no matter the floor.
- `incomplete` / `scan_error` are untouched (the policy only reclassifies
  `exposed` findings, never partial coverage or a crash).

## 5. Safe default

Floors default to `none`, i.e. **every finding blocks, exactly as before** — a
security tool must not silently hide findings out of the box. Provenance
*labeling* is on by default (informational, safe). To actually quiet first-party
low/medium noise, opt in, e.g. in `honey.conf`:

```
export HONEY_VERDICT_FLOOR_TRUSTED=high     # first-party low/medium -> review; high/critical still block
# or, to demote ALL first-party noise (it's a doc-scan marketplace you trust):
export HONEY_VERDICT_FLOOR_TRUSTED=critical
```

## 6. Verdict line

The tallies are always on the line so a held run can't read as a bare all-clear:

- `OVERALL: CLEAN (123 review)` — nothing blocking; 123 findings held below the
  floor (still listed).
- `OVERALL: EXPOSED (12 suppressed, 65 review)` — real blocking findings drive
  it; 65 first-party lows/mediums demoted, 12 baseline-pinned.

`daily-cycle` exits `0` only when nothing blocks (review-only ⇒ clean).

## 7. How it composes with the baseline

- **Baseline** = "I reviewed *this exact finding* and it's benign" (content-hashed, per-finding).
- **Verdict policy** = "findings from *this source* below *this severity* are background noise, not alarms" (broad, per-provenance).

Together: the marketplace's structural false positives drop to the review tier
via one `HONEY_VERDICT_FLOOR_TRUSTED` setting, and the handful you want to fully
vanish get pinned. A real HIGH in a first-party skill still blocks; a MUTATED pin
still screams.

## 8. Files

- **bash:** `lib/verdict.sh` (provenance + floor helpers), sourced by
  `lib/baseline.sh`; `report.sh` renders blocking vs review; `daily-cycle.sh`
  inherits the review count via `baseline_effective_overall`.
- **win:** `win/lib/Verdict.psm1`, imported by `Baseline.psm1`; `report.ps1`,
  `daily-cycle.ps1` updated.
