#!/bin/sh
# Install harness-evolve into another agent repo in one command.
#   sh .claude/skills/harness-evolve/scripts/install.sh /path/to/other-repo [retired-project ...]
# Copies the skill, proves it with selfcheck, initialises .harness-evolve/, records retired projects,
# runs the first drift pass, and prints the three lines to add to that repo's harness.
set -eu
TARGET=${1:?usage: install.sh <target-repo> [retired-project ...]}
shift || true
SRC=$(cd "$(dirname "$0")/.." && pwd)
[ -d "$TARGET/.git" ] || { echo "not a git repo: $TARGET" >&2; exit 1; }
mkdir -p "$TARGET/.claude/skills"
rm -rf "$TARGET/.claude/skills/harness-evolve"
cp -R "$SRC" "$TARGET/.claude/skills/harness-evolve"
cd "$TARGET"
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py selfcheck
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py init
if [ "$#" -gt 0 ]; then
  python3 - "$@" <<'EOF'
import json, sys
p = ".harness-evolve/config.json"
c = json.load(open(p)); c["retired"] = sorted(set(c.get("retired", []) + sys.argv[1:]))
json.dump(c, open(p, "w"), indent=2)
print("retired:", c["retired"])
EOF
fi
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py drift || true
cat <<'EOF'

Installed. Add these to the harness and commit .claude/skills/harness-evolve + .harness-evolve:
  1. Router row:  | "evolve the harness" / harness stale / after retiring a project / weekly | `harness-evolve` |
  2. Session start line in CLAUDE.md:  Read .harness-evolve/playbook.md; tag bullets you used.
  3. Before unattended use: set "judge_cmd" and "approvers" in .harness-evolve/config.json, and seed .harness-evolve/evals/.
Then say "evolve the harness" to the agent; SKILL.md Steps 1-6 take it from there.
EOF
