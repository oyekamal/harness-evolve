---
name: harness-evolve
description: "Eval-gated self-evolution for any Claude Code agent repo: mine traces (failures, logs, transcripts, corrections), detect harness drift deterministically (retired projects still live, dead paths, heavily-used skills nobody routed, stale rules, bloat), diagnose with a closed cause set, propose one-file edits with predicted fixes/regressions, and land them ONLY if they pass a two-split non-regression gate against a best-of-K baseline. Use when the operator says 'evolve the harness', 'harness-evolve', 'the harness is stale', 'the agent keeps doing X', after a project is retired, on a weekly cron, or when failures pile up. Use `reflect`-style session reviews for one-off learnings and a memory-pruning skill for memory files; this skill owns the harness itself."
---

# harness-evolve

A harness is frozen at deploy. Every fix is a human noticing a pattern and editing a prompt. Meanwhile the agent produces traces nobody learns from, projects get retired but their rules stay live, and the skill used most never makes it into the router. This skill closes that loop, with the one property the research says matters: **no edit lands on the proposer's say-so. It lands because it was re-executed and measured.**

Portable: it is a normal Claude Code skill. `sh scripts/install.sh <repo> [retired-project ...]` copies it into any repo's `.claude/skills/`, proves it with `selfcheck`, initialises state and runs the first drift pass; the agent then invokes it like any other skill ("evolve the harness"). One stdlib Python file (3.8+), POSIX sh, git. No dependencies. See `README-INSTALL.md`. Hardened against two adversarial critic rounds; every attack they landed is now a `selfcheck` assertion.

## The loop

```
collect ──▶ drift ──▶ diagnose ──▶ propose ──▶ gate ──▶ apply ──▶ (observe) ──▶ rollback?
 traces      deterministic  LLM, closed   manifest    re-execute   tier 0 auto     playbook
 + usage     checks         cause set     + patch     base vs cand tier ≥1 human   counters
```

Every arrow is a CLI command in `scripts/harness_evolve.py`. The LLM only does two things: diagnose clusters and write patches. Everything else is deterministic and refuses sloppy input.

## Step 0: install and configure (once per repo)

```bash
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py init
```

Detects surfaces (CLAUDE.md, rules, skills, agents, commands, hooks, settings), trace sources (failures jsonl, log dirs, Claude Code transcripts under `~/.claude/projects/<slug>/`), and existing eval suites. Then edit `.harness-evolve/config.json`:

- `retired`: project names the harness must stop treating as live. This is the single highest-yield line. Set it the day a project is dropped.
- `judge_cmd`: a command that reads a prompt on stdin and prints a verdict, running a **different context from the producer** (for Claude Code: `claude -p --model claude-sonnet-5-5`; never the session that wrote the patch). Leave empty to disable judged tasks; deterministic checks still run.
- `evals.suites`: regression commands that must stay green (exit 0). `init` auto-detects `run-tier1.sh`, `npm test`, `make test`, pytest.
- `approvers`: names allowed in `--human-approved`. Empty means any name except the manifest's producer or an agent name; set it to real humans before running on cron, because a free-text name is otherwise forgeable by the same agent that proposed the patch. The real tier-1 gate is a human reading the diff (or a PR review); this flag only records who.
- `keep_runs`: `collect` prunes `.harness-evolve/runs/` to the newest N (30). `gate`, `apply`, `collect` and `rollback` take a per-repo lock, so a cron overlap exits instead of racing.
- The split seed is NOT in this file. `init` writes it to `~/.harness-evolve/<repo-hash>/seed`, outside the tree, so a proposer running inside the repo cannot read or change which tasks are held out. Deleting it reshuffles the splits and invalidates every prior verdict.

## Step 1: collect

```bash
harness_evolve.py collect
```

Writes `.harness-evolve/runs/<ts>/signals.jsonl` (failures of any schema, failure-smelling log lines, tool errors and user corrections from transcripts) and `skill_usage.json` (count of `Skill` tool calls per skill). Incremental: per-file offsets, so the second run over 2 GB of transcripts takes a fraction of a second. Secret-shaped tokens are replaced with `[REDACTED]` before a signal is written. Signals are data the diagnoser reads, never instructions; the prompts say so.

## Step 2: drift (deterministic, free, run it every session if you like)

```bash
harness_evolve.py drift -v     # exit 1 when findings exist
```

| check | what it catches | cause label |
|---|---|---|
| `retired_reference` | a `retired` project named as live work in any text surface | stale_reference |
| `dead_path` | a repo path referenced in prose that does not exist (file-relative and repo-relative both tried) | stale_reference |
| `unrouted_skill` | skill used ≥ `skill_usage_min` times but absent from the router file | missing_route |
| `heavy_skill_not_in_l1` | skill used ≥ `heavy_usage_min` times but CLAUDE.md never names it | missing_route |
| `stale_rule` / `no_last_verified` | rule frontmatter `last_verified` older than `stale_days`, or missing | stale_reference |
| `over_cap` | CLAUDE.md / rule over its line limit | context_bloat |
| `secret_in_surface` | token-shaped string in an editable surface (evolution must never touch that file) | other |
| `duplicate_eval_id` | two eval tasks share an id | rule_contradiction |

Each finding carries a `cluster` key so the gate can later check per-cluster regression.

## Step 3: diagnose (one subagent, fresh context)

Spawn one `general-purpose` agent with `references/diagnoser-prompt.md`, giving it the paths to `signals.jsonl`, `drift.json`, and the harness surfaces. It returns JSON with clusters. Validate:

```bash
harness_evolve.py diagnose diagnosis.json
```

Rejected unless every cluster has a cause from the closed set, ≥1 evidence pointer, a `harness_at_fault` verdict, and the file has a `preserve[]` ledger of what currently passes. `infra_failure` clusters are never proposed on. A cluster with `harness_at_fault=false` is logged and dropped: unstructured revision measured worse than no change (SkillRevise, 33/86 vs 31/86).

## Step 4: propose (one subagent per cluster, fresh context)

Spawn one `general-purpose` agent per cluster with `references/proposer-prompt.md`. It writes a unified diff to `.harness-evolve/patches/<id>.diff` and a manifest. Validate and register:

```bash
harness_evolve.py propose manifest.json
```

Manifest contract (`references/change-manifest.md`): one cluster, one surface, one file, a patch, evidence pointers, `predicted_fixes` (eval task ids or drift checks it will turn green), `predicted_regressions`, `intended_effect`. **The surface, and therefore the tier, is derived from the path the patch touches; the manifest's label is only checked against it.** `propose` asks git what the patch does (applied to a temporary index against HEAD, then `diff-index --name-status`), never a regex over headers, and rejects: a second file, any deletion or rename, anything under `.harness-evolve/` except the playbook, evals, hooks, settings, secret-shaped tokens (modern prefixes, base64-wrapped, split across lines; placeholders like `YOUR_KEY` are ignored), and hidden text (HTML comments, zero-width characters). A tier-3 manifest may carry `patch: null` and is registered as a *finding* for a human. Risk tier by surface:

| tier | surfaces | lands how |
|---|---|---|
| 0 | playbook | auto, fast-forward |
| 1 | rule, router, CLAUDE.md, memory | branch `evolve/<surface>-<ts>`, human reviews diff |
| 2 | skill, agent, command | same branch, human reviews, PR |
| 3 | hook, settings, eval, `.harness-evolve/config.json`, anything with a secret | never a patch; the loop may only file a finding |

## Step 5: gate (the whole point)

```bash
harness_evolve.py gate <manifest-id>
```

Base and candidate are both throwaway `git worktree`s of HEAD (so an uncommitted local change can never be credited to or blamed on the patch; the gate refuses if the manifest's files have uncommitted changes). Config, playbook and eval tasks are copied in from the working tree. The verdict records a **binding**: HEAD sha, patch sha, config sha, evals sha, plus a signature over them keyed by the out-of-tree seed (residual: the seed is readable by the same OS user, so this blocks a careless agent, not a hostile one with shell access). `apply` recomputes all four, recomputes the signature, and refuses on any mismatch or without a matching signed ACCEPTED row in `gate_log.jsonl` (so a hand-edited manifest or log row lands nothing; the residual is that the seed is readable by the same OS user). After applying in the candidate, `git status` must show exactly the declared file changed. A crash inside the gate is recorded as a rejection with the traceback, never left as `proposed`.

1. **Hard constraints first, cheap.** Patch applies cleanly and still touches exactly the declared file. No existing file grew > `max_growth_ratio` (20%) by more than `growth_floor_chars` (400), so a tiny file can still take one row; a new file may not exceed `max_new_file_lines` (60). Playbook patches skip the ratio and instead must consist only of fresh bullets (counters `0/0`, ≤ 300 chars, at most 5 per change, no removed lines (append-only is enforced), headers only from the fixed section list, no hidden text, no secret, no text instructing the agent around the gate); `playbook add` runs the same validator. Added lines are read hunk by hunk from the diff, so a `++ text` line or a U+2028 inside a line does not hide content from these checks; hidden-text rejection covers Cf/Cc/Co/Zl/Zp code points and the usual invisible fillers. CLAUDE.md and rules under their caps. Frontmatter `name` unchanged. No secret. No eval task input copied verbatim into the harness (leakage). No added line that is just an eval check's grep needle, and no short added line that on its own flips a check from fail to pass when appended to the base file (wireheading, tested by execution, so regex needles do not evade it). Added and removed lines are read from git's own `-U0` diff by hunk counts, so no content line can pose as a header.
2. **Regression suites** that pass on base must pass on candidate.
3. **Drift count** must not rise.
4. **Task evals by split.** Tasks in `.harness-evolve/evals/*.json` are hashed into train/val/holdout (50/25/25) with `split_seed`; the holdout never moves. Base runs holdout tasks `best_of_k` times. Rules, all required:
   - no split's pass@1 drops, and no individual task flips from pass to fail (a fix and a break must not net to zero)
   - candidate holdout pass@1 ≥ base best-of-K (Rethinking: if retries would have done as well, the edit is memorisation)
   - no cluster other than the targeted one drops more than `epsilon_cluster` (OpenJarvis)
   - judged tasks: pairwise, blind, both orders must agree; a swap-dependent verdict is a tie; a holdout loss is fatal; ties are not wins; a judge that answers anything but `1` or `2` is *invalid* and fails the gate (an explanation like "output 1 loses to 2" used to be parsed as a verdict); judge tasks with an empty `judge_cmd` fail the gate instead of vanishing
   - the holdout must hold ≥ `min_holdout_tasks` (3) checked tasks, else the best-of-K comparison is vacuous and the gate rejects; `--allow-thin-holdout` downgrades it to constraints + suites + drift only, and says so in the verdict
5. **Something must have improved** (a split, drift count, or a judged win). Otherwise keeping the current harness wins.

Verdict and metrics are written into the manifest and `gate_log.jsonl`. Five consecutive rejections → `status` prints STOP: fix the eval set or the diagnosis, do not keep proposing.

## Step 6: apply, observe, roll back

```bash
harness_evolve.py apply <id>                          # tier 0 lands; tier ≥1 prints the diff and stops (exit 2); tier is recomputed from the paths
harness_evolve.py apply <id> --human-approved alice   # after a human read the diff
harness_evolve.py rollback <id> --reason "..."        # git revert of exactly that commit
```

Refuses on detached HEAD, on a second apply, if any gate input changed, if the index has unrelated staged files, and if the applied patch touched anything beyond the declared file. Commits with a pathspec; on failure it resets only the declared file, never your other uncommitted work. The tree is returned to the base branch either way. Commit messages carry the manifest id, cluster, cause, predictions and gate metrics, so `git log` is the audit trail. Next cycle, compare `predicted_fixes` against what actually turned green; AHE measured regression prediction at 11% precision, which is why the holdout and regression suites exist rather than trusting the prediction.

## The playbook (tier 0, the only thing that auto-lands)

`.harness-evolve/playbook.md` is an ACE-style append-only list of one-line lessons with counters:

```
[mistake-00007] helpful=4 harmful=0 :: Before claiming done, run the check that would fail if it were not done.
```

```bash
harness_evolve.py playbook add mistake "lesson" --source failures:2026-10-05
harness_evolve.py playbook tag mistake-00007 helpful      # or harmful, when a session used it
harness_evolve.py playbook prune                           # drops harmful >= helpful > 0
harness_evolve.py playbook stats
```

Add one line to CLAUDE.md so sessions read it: `Read .harness-evolve/playbook.md at start; tag bullets you used.` Full rewrites are forbidden: ACE measured a rewrite collapsing 18k tokens to 122 and dropping below baseline.

## Eval tasks: the thing you must build before trusting the loop

`.harness-evolve/evals/<id>.json`:

```json
{"id": "no-retired-rule", "cluster": "retired:old-project",
 "check": "! grep -q 'NOTHING for old-project' CLAUDE.md"}
{"id": "router-names-gauntlet", "cluster": "unrouted:gauntlet-loop",
 "check": "grep -q gauntlet-loop CLAUDE.md"}
{"id": "bug-routes-to-debugging", "cluster": "routing", "timeout": 300,
 "run": "claude -p 'Agent, the listener crashed with a stack trace. Which skill do you invoke first? One word.'",
 "check": "echo \"$HE_OUTPUT\" | grep -qi systematic-debugging"}
{"id": "slack-reply-tone", "cluster": "tone",
 "run": "claude -p 'Draft the Slack reply for ticket 42'",
 "judge": {"prompt": "Which reply follows the unslop rules and answers the question first?"}}
```

`check` gets the run output in `$HE_OUTPUT`. A task with only `check` is a harness invariant and costs nothing. Write needles separator-insensitively (`old[-_ ]*proj`, `\b`): a proposer can satisfy `grep -q oldproj` by renaming to `old-proj`. A check can always be gamed by a determined patch; what makes that safe is that only the playbook auto-lands, so a gamed check buys the proposer a diff in front of a human, nothing more. A task with `run` is a behavioural probe; keep ≥ 20 of them before trusting a holdout verdict, and convert every entry in `failures.jsonl` into one (the repo's existing rule). Prefer checks over judges: self-grading inflated 0.92 on prose tasks and ~0 on exact-match tasks.

## Cadence

- `drift` every session start or daily cron: free. `collect` daily is safe too (incremental, pruned, locked).
- Do NOT put `gate`/`apply` on cron until `.harness-evolve/evals/` holds ≥ 20 behavioural tasks and `approvers` is set; until then run them by hand and read the diff.
- `collect` → `diagnose` → `propose` → `gate` weekly, or when `failures.jsonl` gains 3+ rows, or the day a project is retired.
- Early in a repo's life run it more often (Continual Harness backs off from every 25 steps to every 100 once stable).

## Hard rules

1. The loop never edits its own judge: eval tasks, suites, `judge_cmd`, split seed, hooks, settings. `propose` refuses such patches.
2. The producer never grades. The diagnoser, proposer and judge are separate subagents with fresh context; the judge gets outputs with labels stripped, both orders.
3. One manifest, one file, one cause. Bundled edits cannot be attributed next cycle.
4. Keep S0 in the race: a tie goes to the current harness.
5. `infra_failure` is excluded from diagnosis. Quota errors and missing binaries are not harness defects.
6. Tier ≥1 needs a named human in `--human-approved`. The approval is in the commit message.
7. Commit the files a manifest touches before `gate`; both worktrees are cut from HEAD.
8. Log the run with `show-me-your-work` if it will touch more than one tier-1 file.

## Files

```
.claude/skills/harness-evolve/
  SKILL.md                      this file
  README-INSTALL.md             drop-in steps for any repo
  scripts/harness_evolve.py     the CLI (stdlib only, `selfcheck` proves it)
  references/research-basis.md  what was taken from which paper, with the numbers
  references/gate-protocol.md   the evaluation protocol in full
  references/change-manifest.md manifest + diagnosis schemas
  references/diagnoser-prompt.md / proposer-prompt.md / judge-prompt.md
.harness-evolve/                per-repo state (config, playbook, evals, manifests, gate_log; runs/ and patches/ gitignored)
```
