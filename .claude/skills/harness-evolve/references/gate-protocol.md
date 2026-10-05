# Gate protocol

The gate decides whether a proposed harness edit lands. It is written so that a reader can audit any verdict from `gate_log.jsonl` alone.

## Inputs

- Base: a `git worktree` of HEAD. Candidate: a second `git worktree` of HEAD with the manifest's patch applied. Nothing is ever evaluated in the live tree. Config, playbook and eval tasks are copied in from the working tree so untracked eval tasks still count.
- Config: `max_growth_ratio`, `max_new_file_lines`, `line_limit_*`, `epsilon_cluster`, `best_of_k`, `min_holdout_tasks`, `evals.suites`, `judge_cmd`. The split seed is read from `~/.harness-evolve/<repo-hash>/seed`.
- Tasks: `.harness-evolve/evals/*.json`, each `{id, cluster, run?, check?, judge?, timeout?, input?}`.

## Splits

`split = sha256(seed + ":" + task_id) → train 50% / val 25% / holdout 25%`. The split is a pure function of the seed, so a task's split never changes unless the seed does. The seed lives outside the repo so nothing running inside the repo (proposer, hooks, a rogue patch) can read or rewrite it. Gate output and manifests never print a task's split next to its id; only per-split counts are logged.

- train: the proposer may read these task ids and their failures.
- val: used to pick between competing manifests for the same cluster (compare `cand_pass1` on val).
- holdout: the proposer must never be shown these. Reported, never optimised.

## Order of checks (cheap → expensive, first failure stops)

0. Binding: record HEAD, patch sha, config sha, evals sha in the verdict. `apply` refuses if any differ or if no ACCEPTED gate_log row matches.
1. The patch still touches exactly the declared file (as reported by git against a temporary index; deletions and renames are refused), applies cleanly, and after applying the candidate's `git status` shows only that file.
2. Hard constraints per touched file: no secret-shaped token in any added line; existing file growth ≤ `max_growth_ratio`; new file ≤ `max_new_file_lines`; CLAUDE.md ≤ `line_limit_claude_md`; rule ≤ `line_limit_rule`; frontmatter `name` unchanged; no eval task `input` (first 80 chars) copied verbatim into the file (leakage); no added line that is only an eval check's grep needle (wireheading).
3. Regression suites: every suite that exits 0 on base must exit 0 on candidate.
4. Drift count on candidate ≤ drift count on base.
5. Task evals:
   - every task with `check` runs once on candidate; on base it runs once, except holdout tasks run `best_of_k` times (pass@K recorded).
   - judged tasks (no `check`, has `judge`) produce output on base (A) and candidate (B); the judge is asked twice with order swapped; verdict A / B / tie / invalid. `invalid` (stdout not exactly `1` or `2`) fails the gate. If judge tasks exist and `judge_cmd` is empty the gate fails rather than skipping them.
   - fewer than `min_holdout_tasks` checked holdout tasks → reject (vacuous best-of-K), unless `--allow-thin-holdout`.
6. Decision:

```
accept iff
  Δtrain ≥ 0 and Δval ≥ 0 and Δholdout ≥ 0              (non-regression, every split)
  and no task went pass→fail                            (per task, so a fix and a break cannot cancel)
  and holdout cand_pass1 ≥ holdout base_best_of_K      (beats retries)
  and for every cluster c ≠ target: drop(c) ≤ ε         (no collateral)
  and no judged holdout loss
  and (Δtrain > 0 or Δholdout > 0 or drift fell or a judged win)   (something improved)
```

Where Δ is candidate pass@1 minus base pass@1 on that split.

## Reading a verdict

`metrics.splits` gives `n, base_pass1, cand_pass1, base_bestofK` per split. Overfit meter = (Δtrain / n_train) − (Δholdout / n_holdout). If it is positive and holdout is flat, the edit memorised the training failures. Reject even if the rule above would accept, and say so in the manifest's `verdict.reasons`.

## Judge hygiene (when `judge` tasks exist)

- `judge_cmd` runs in a separate process with only the prompt and the two outputs. It never sees the manifest, the diff, the proposer's reasoning, or which output is the candidate.
- Both orders are asked. Disagreement is a tie, not a coin flip.
- Before relying on a judge, give it 10 calibration pairs with a known better answer (5 clear, 5 close). If it gets fewer than 8 right with order-consistency, do not let it gate; add a second judge model and take majority, or convert the task to a `check`.
- Prefer `check`. A `judge` task should exist only where no deterministic predicate is possible (tone, clarity).

## Budget

Deterministic tasks are free. A `run` task costs one agent call per split member per trial; holdout `run` tasks cost `best_of_k` + 1 calls (pure checks run once, they are deterministic). With 20 run-tasks and K=3 a gate costs ~35 agent calls. There is no way to skip tasks: a critic showed that skipping out-of-cluster train tasks let a regression land.

## Stagnation

Five consecutive rejections in `gate_log.jsonl` → `status` prints STOP. The right move is almost never a sixth proposal: the eval set is too small, the diagnosis is wrong, or the harness is already at the model's capability floor (Continual Harness: every variant hurt Flash-Lite).
