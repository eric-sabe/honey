#!/usr/bin/env bash
# lib/load-config.sh — load optional local config, if present.
#
# Sourced early by every honey entry script (and the lenses). honey.conf holds
# machine-specific settings — most importantly BUMBLEBEE_REPO when your
# bumblebee checkout isn't at the default ~/git/bumblebee. It is gitignored
# (machine-specific) and written as:
#     export VAR="${VAR:-value}"
# so the precedence is: explicit env var (this invocation) > honey.conf >
# each script's built-in default. Default installs need NO honey.conf at all.
#
# honey.conf lives at the repo root; this file is in lib/, so root = lib/..
__honey_conf="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/honey.conf"
# shellcheck disable=SC1090  # honey.conf is machine-specific and optional; path is correct at runtime
[ -f "$__honey_conf" ] && . "$__honey_conf"
unset __honey_conf
