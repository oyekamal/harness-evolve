# Schemas

## Diagnosis (`diagnose` input)

```json
{
  "run": ".harness-evolve/runs/20261005-113452",
  "clusters": [
    {
      "id": "retired:old-project",
      "cause": "stale_reference",
      "signature": "harness names old-project as live work; project retired 2026-09-06",
      "evidence": ["drift:retired_reference CLAUDE.md:33", "drift:retired_reference .claude/rules/old-project.md:9", "memory:project_pivot"],
      "size": 80,
      "harness_at_fault": true,
      "surfaces": ["claude_md", "rule", "router", "agent"],
      "fix_direction": "mark old-project.md retired, drop CLAUDE.md rule 7 and nav row, retire router rows, point evolution agent fence elsewhere",
      "preserve_note": "rows for active projects must stay"
    },
    {
      "id": "unrouted:gauntlet-loop",
      "cause": "missing_route",
      "signature": "most-used skill (20x/30d) absent from CLAUDE.md; router row contradicts the operator's rule (use on every build)",
      "evidence": ["drift:heavy_skill_not_in_l1", "signals:correction 2026-08-19", "memory:feedback_gauntlet"],
      "size": 20,
      "harness_at_fault": true,
      "surfaces": ["claude_md", "router"]
    },
    {
      "id": "quota:anthropic-429",
      "cause": "infra_failure",
      "signature": "tool_error 429 during job-finder",
      "evidence": ["signals:tool_error x7"],
      "size": 7,
      "harness_at_fault": false,
      "propose": false
    }
  ],
  "preserve": [
    "run-tier1 suite currently fails on personality.md path and 3 missing frontmatters; everything else in it passes",
    "eval-009 bot-mention test passes",
    "router rows for the active projects are correct and used"
  ]
}
```

Closed cause set: `stale_reference, missing_route, wrong_route, missing_rule, rule_contradiction, tool_misuse, premature_termination, verification_skipped, context_bloat, infra_failure, other` (`other` needs `note`).

## Change manifest (`propose` input)

```json
{
  "id": "m-20261005-retire-claude-md",
  "cluster": "retired:old-project",
  "cause": "stale_reference",
  "surface": "claude_md",
  "files": ["CLAUDE.md"],
  "patch": ".harness-evolve/patches/m-20261005-retire-claude-md.diff",
  "evidence": ["drift:retired_reference CLAUDE.md:16", "drift:retired_reference CLAUDE.md:33", "memory:project_pivot 2026-09-06"],
  "fix": "remove rule 7 and the old-project nav row; replace Projects (Active) list with the current projects",
  "predicted_fixes": ["no-retired-rule", "drift:retired_reference:CLAUDE.md"],
  "predicted_regressions": ["eval-003 (rewards routing to the retired rule; it is wrong and should be rewritten by a human, tier 3)"],
  "intended_effect": "a new session no longer treats old-project as live work",
  "producer": "proposer-subagent"
}
```

`surface` ∈ `playbook | rule | router | claude_md | memory | skill | agent | command | hook | settings | eval | secret`. Tier is assigned from it (0 / 1 / 1 / 1 / 1 / 2 / 2 / 2 / 3 / 3 / 3 / 3).

Fields the script adds: `tier, version, created, status (proposed|accepted|rejected|applied|rolled_back), verdict{accepted, reasons[], metrics{}}, commit, branch, approved_by`.

## Eval task

```json
{"id": "string, unique", "cluster": "string, matches diagnosis cluster ids where possible",
 "run": "shell command whose stdout+stderr become $HE_OUTPUT (optional)",
 "check": "shell command, exit 0 = pass; sees $HE_OUTPUT (optional)",
 "judge": {"prompt": "question for the pairwise judge"} ,
 "timeout": 600,
 "input": "the user-facing prompt, if any; used by the leakage check"}
```

A task needs `check` or `judge`. Checks are preferred.
