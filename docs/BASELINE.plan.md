# Suppression baseline (pin-and-diff) — design spec

Status: **implemented** (this branch). Companion to [`WINDOWS.plan.md`](WINDOWS.plan.md).

## 1. Problem

honey's verdict is worst-wins across bumblebee + every active lens, and a lens
flips to `exposed` on the *first* finding at *any* severity. In practice this
buries the signal: a daily run over first-party, trusted agent skills can emit
100+ static-analysis findings — overwhelmingly false positives against
reference/documentation material (`references/*.md`, `LICENSE.txt`, MCP example
manifests) — and drag `OVERALL` to `EXPOSED` every single day. When every run
screams, the reader stops reading, and a *real* finding (a genuine CVE, a
malicious package) drowns in the noise.

We need a way to acknowledge a finding we've reviewed and judged benign **once**,
so it stops contributing to the daily alarm — *without* going blind to the thing
honey exists to catch: that "trusted" content later turning malicious.

## 2. The core idea: pin, don't mute

A naive allowlist ("ignore skill X" / "trust this path") is the wrong model.
It fails in exactly the case honey defends against — a first-party plugin that
ships a malicious update next week keeps its allowlisted path and goes unseen.
**Trust-by-location is blindness-by-location.**

Instead, honey suppresses by a **content hash** of the reviewed material. A
suppression entry means:

> *"I reviewed this exact content and judged this finding benign. Tell me the
> instant the content changes."*

The same hash that quiets a known-benign finding is a **tripwire**: if the
underlying file mutates, the hash no longer matches, and the finding resurfaces —
loudly, tagged `MUTATED`. This is precisely the recommended industry defense
against MCP **rug pulls** (benign-at-approval, malicious-after): *hash the
manifest on first sight and diff every run.* Suppression and change-detection
are the same mechanism.

This reframes the feature from "mute noise" to "**pin-and-diff**": every
suppressed finding becomes a change detector on the content it vouches for.

### What this design does and does NOT defend

Robust against (the finding was flagged, then content changed):
- Manifest-alteration rug pulls, post-install source swaps, silent edits to a
  previously-reviewed skill/lockfile → **hash mismatch → resurfaces as `MUTATED`.**

Structurally blind to (nothing was ever flagged, so nothing to pin):
- Sleeper payloads (bytes unchanged, behavior triggered at runtime),
  runtime-fetched remote includes, image/multimodal-embedded instructions,
  semantic paraphrase that never tripped a pattern.

The baseline neither helps nor hurts the adversary on that second class — those
evades live *outside the scanned surface*. The design's one hard rule
(§6) is that a suppressed run must **never render as a bare all-clear**: the
counts are always shown so "clean" can't quietly imply "nothing was hidden over
a surface we never fully scanned."

## 3. Fingerprint

A finding is identified by a 4-part key plus a content guard. Modeled on
Semgrep's `(rule, path, syntactic-context, index)` and deliberately *unlike*
gitleaks' location-only fingerprint (which breaks under line/path churn).

| Field | Source (lens finding) | Source (bumblebee) | Notes |
|---|---|---|---|
| `scanner` | lens name | `"bumblebee"` | which scanner produced it |
| `rule` | `title` (+ `ref`) | `catalog_id` + `package_name` | stable rule/campaign identity |
| `location` | `location` (`file:line`) | `source_file` | **stored `~`-relative** for portability |
| `index` | occurrence # among identical `(scanner,rule,location)` | same | disambiguates dup findings (Semgrep lesson) |
| `content_hash` | `sha256(file at location)` | `sha256(source_file)` | the pin-and-diff guard |

- **Location normalization:** an absolute path under `$HOME`/`%USERPROFILE%` is
  stored as `~/...`. This keys on machine-relative paths (never absolute), so a
  baseline survives a home-dir move and reads sanely in a PR diff.
- **Content unit = the whole referenced file.** Coarse on purpose: any edit to a
  reviewed skill file resurfaces *all* its pins for re-review. For "trusted but
  static" content that is the safe direction — and an edit is exactly a rug-pull
  moment. If the location has no on-disk file, honey falls back to hashing the
  finding's own canonical JSON (catches finding-text mutation, not file mutation)
  and marks the entry `content_source: "finding"`.
- Hashing is **raw bytes** (see §7 on Unicode) via a portable helper:
  `sha256sum` → `shasum -a 256` → `openssl dgst -sha256` (bash);
  `Get-FileHash -Algorithm SHA256` (PowerShell).

## 4. Classification

For each **active** finding at report time, honey computes its key and looks up a
matching baseline entry:

| Baseline entry | File hash vs. entry | Result | In verdict? |
|---|---|---|---|
| none | — | `active` | yes (normal) |
| present, not expired | **match** | `suppressed` | **no** (listed in a Suppressed footer) |
| present, not expired | **mismatch** | `mutated` | **yes**, escalated, tagged `MUTATED` |
| present, **expired** | match | `active` | yes, tagged `expired-suppression` |

- `suppressed` findings are removed from the active counts but **retained in the
  report** under a per-scanner "suppressed (N)" note and an optional footer.
  Never deleted from `lens-*.json` / `findings.ndjson` — suppression is a
  **report-layer re-rank**, honey's standing discipline ("never hide data").
- `mutated` findings can never be suppressed; they force the scanner to
  `exposed` and OVERALL away from clean.
- Expiry: default **90 days** from `added` (configurable per entry, or `never`).
  Expired entries resurface so "temporarily accepted" can't silently become
  permanent blindness (trivy/detect-secrets lesson).

## 5. Verdict

OVERALL is recomputed **after** suppression, using the same worst-wins ranking:

- A scanner whose findings are *all* suppressed ranks as `clean` for the verdict,
  but the report prints `✓ … (all N suppressed)` — not a bare clean.
- `incomplete` / `scan_error` / `skipped` are **never** touched by the baseline
  (suppression only removes `exposed` findings; it can't paper over partial
  coverage or a crash).
- The verdict line always carries the tallies when any pin applied:
  - `OVERALL: CLEAN (12 suppressed)` — exit 0.
  - `OVERALL: EXPOSED — … (12 suppressed, 2 mutated)` — exit 1.
  - Any `mutated` > 0 ⇒ cannot be clean.

`report.sh`/`report.ps1` render it; `daily-cycle` uses the same shared
classifier for its exit code so the two never disagree.

## 6. Non-negotiable safety rules

1. **Never a bare all-clear when pins applied.** The suppressed/mutated counts
   are always on the verdict line. "Clean" must never imply "nothing hidden."
2. **Content hash is mandatory** — no location-only suppression. A content swap
   at a pinned location must resurface, never stay quiet.
3. **A scan_error or incomplete lens is never downgraded** by the baseline.
4. **A lens crash never creates or clears baseline state** (Semgrep's baseline
   bug: a per-rule failure must not mass-suppress or mass-resurface).
5. **Deterministic fingerprints.** Stable ordering + occurrence index so benign
   re-scans don't cycle findings in/out (Semgrep flakiness lesson).
6. **bumblebee suppression is opt-in and loud.** `add --all` excludes bumblebee;
   pinning a known-compromised-package match requires an explicit
   `--scanner bumblebee`, and such entries are rendered distinctly.
7. **The baseline file is committed and reviewable.** Baseline edits belong in
   `git diff`/PR review — that auditability is itself an anti-gaming control.

## 7. Unicode / evasion hardening

Static scanners are evaded by invisible Unicode (tag chars U+E0000–E007F),
homoglyphs, and bidi controls. Two consequences for the baseline:

- **Hash raw bytes**, so a smuggled payload — once flagged — is covered by the
  pin and any change to it resurfaces.
- **Do not normalize away invisibles in the match key.** A homoglyph/invisible
  edit changes the file bytes ⇒ hash mismatch ⇒ `mutated`. That is the desired
  behavior; we must not let NFC-folding silently re-suppress a tampered file.

(Detecting smuggled codepoints in the first place is the *lens's* job, tracked
separately in §9; the baseline's contract is only "once flagged, stay pinned to
exact bytes.")

## 8. Baseline file

`honey.baseline.json` at the repo root (override: `HONEY_BASELINE`). Committed,
not gitignored. Starts as `{"version":1,"entries":[]}`.

```json
{
  "version": 1,
  "entries": [
    {
      "scanner": "skillspector",
      "rule": "PE3 Credential Access",
      "location": "~/.claude/plugins/marketplaces/.../auth.md:73",
      "index": 0,
      "content_hash": "sha256:1a2b…",
      "content_source": "file",
      "severity": "high",
      "reason": "first-party Anthropic marketplace reference doc; describes credential-file patterns, not executable",
      "added": "2026-07-07",
      "expires": "2026-10-05",
      "added_by": "eric"
    }
  ]
}
```

## 9. Management CLI — `honey-baseline.sh` / `win/honey-baseline.ps1`

| Command | Purpose |
|---|---|
| `status [RUN_DIR]` | dry-run: how many findings would be suppressed / mutated / expired / active for a run |
| `add [RUN_DIR] <filter> --reason STR [--expires DAYS\|never] [--added-by NAME]` | capture matching findings + current file hashes into the baseline |
| `list [--expired\|--active]` | list entries (flag expired) |
| `remove <filter>` | drop matching entries |
| `prune` | remove expired entries |

`<filter>` for `add`/`remove`: `--all` (excludes bumblebee), `--scanner NAME`,
`--severity SEV`, `--rule 'text'`, `--location 'path-substr'` (combinable, AND).

The CLI is read-mostly and never changes system state — it only edits
`honey.baseline.json`, which the user reviews and commits.

## 10. Files touched

Shared logic lives in one place per platform so `report`, `daily-cycle`, and the
CLI agree:

- **bash:** new `lib/baseline.sh` (hash, normalize, load, classify, filter,
  `baseline_effective_overall`), new `honey-baseline.sh`; edits to `report.sh`,
  `daily-cycle.sh`, `doctor.sh`, `.gitignore`, new empty `honey.baseline.json`.
- **PowerShell:** new `win/lib/Baseline.psm1` (mirror), new
  `win/honey-baseline.ps1`; edits to `win/report.ps1`, `win/daily-cycle.ps1`,
  `win/doctor.ps1`, `win/TESTING.md`.
- **docs:** this file; `README.md`, `triage-guide.md`, `routine-prompt.md`.

## 11. Explicitly out of scope (follow-ups)

- New scanner lenses (Snyk/Invariant `mcp-scan` for the MCP-manifest surface;
  multimodal/OCR lens for image-embedded payloads). The baseline can only
  suppress what a lens flagged; widening the scanned surface is separate work.
- Runtime/behavioral detection of sleeper rug pulls and remote includes.
- Invisible-codepoint detection in the lenses (§7).
