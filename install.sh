#!/bin/sh
# Thin wrapper so `sh harness-evolve/install.sh <repo> [retired ...]` works from a clone.
exec sh "$(dirname "$0")/.claude/skills/harness-evolve/scripts/install.sh" "$@"
