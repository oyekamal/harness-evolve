# Install harness-evolve in any agent repo

Works for any repo that has a CLAUDE.md or `.claude/` directory and git. Python 3.8+, stdlib only, POSIX shell (checks and suites run under `sh`), git ≥ 2.20. The split seed is written to `~/.harness-evolve/<repo-hash>/seed`, outside the repo; back it up with the machine, not the repo.

One command does steps 1 to 4 below:

```bash
sh /path/to/harness-evolve/.claude/skills/harness-evolve/scripts/install.sh <your-repo> old-project-name
```

Or by hand:

```bash
# 1. copy the skill
cp -r /path/to/harness-evolve/.claude/skills/harness-evolve  <your-repo>/.claude/skills/

# 2. prove it works here
cd <your-repo>
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py selfcheck      # prints "selfcheck OK"

# 3. initialise
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py init
#    edit .harness-evolve/config.json:
#      "retired":   ["old-project-name", ...]        <- the day you drop a project, add it here
#      "judge_cmd": "claude -p --model claude-sonnet-5-5"   (or "" to use deterministic checks only)
#      "evals.suites": auto-detected (run-tier1.sh, npm test, make test, pytest); edit if wrong

# 4. first drift pass (free, deterministic)
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py drift -v

# 5. seed eval tasks (at least one per drift cluster, one per failures.jsonl row)
cat > .harness-evolve/evals/no-retired.json <<'EOF'
{"id":"no-retired","cluster":"retired:old-project-name","check":"! grep -rq 'old-project-name' CLAUDE.md .claude/rules"}
EOF

# 6. commit the scaffolding (runs/ and patches/ are gitignored)
git add .claude/skills/harness-evolve .harness-evolve && git commit -m "chore: add harness-evolve"
```

Wire it into the harness itself (three lines):

- **Router row** in your skills router (or CLAUDE.md): `| "evolve the harness" / harness stale / after retiring a project / weekly | \`harness-evolve\` |`
- **Session start**: `Read .harness-evolve/playbook.md; tag bullets you used with harness_evolve.py playbook tag <id> helpful|harmful`.
- **Cron / loop** (optional): daily `drift`, weekly `collect` then the diagnose → propose → gate sequence from SKILL.md Steps 3–6. Tier 0 lands alone; tier ≥1 waits for `--human-approved`.

Hooks are deliberately not installed by this skill. If you want `drift` to run on SessionStart, add it to your own hook; a drift finding is advice to the session, and exit 1 from `drift` must not block anything.

## Removing it

`rm -rf .claude/skills/harness-evolve .harness-evolve` and drop the three lines above. Applied edits live in normal git history under `evolve/*` branches or `evolve(...)` commits; `git log --grep '^evolve('` lists them, `harness_evolve.py rollback <id>` reverts one.
