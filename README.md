# harness-evolve: a self-evolving, eval-gated harness skill for Claude Code agents

**Let your AI agent learn from its own traces and update its harness (CLAUDE.md, rules, skills, agents) only when an eval gate proves the change helps.** One Claude Code skill, one stdlib Python file, drop it into any repo.

[![selfcheck](https://img.shields.io/badge/selfcheck-passing-brightgreen)](#verify-it-yourself) [![python](https://img.shields.io/badge/python-3.8%2B%20stdlib%20only-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> Keywords: self-improving agent, self-evolving harness, agentic context engineering, Claude Code skill, CLAUDE.md maintenance, agent evals, harness evolution, LLM-as-a-judge hygiene, ACE playbook, prompt drift detection, continual learning for coding agents.

## The problem

Agent harnesses freeze at deploy time. Every fix is a human noticing a pattern and editing a prompt. Meanwhile the agent produces thousands of traces a week that nobody learns from, retired projects stay "live" in the rules for months, and the skill the agent uses most never gets a line in CLAUDE.md.

Recent papers (Self-Harness, HarnessEvolve, ACE at ICLR 2026, Agentic Harness Engineering) claim a small refinement loop over traces beats a static harness. One of them, *Rethinking the Evaluation of Harness Evolution* (arXiv 2607.12227), measured what happens without a proper gate: on held-out tasks the evolved harness gained **+0.0**, and plain best-of-5 retries beat it. Every system that accepted edits on the proposer's say-so regressed somewhere.

So this skill is **eval-first**. No edit lands because an LLM said it was a good idea. It lands because it was re-executed against held-out tasks, beat a best-of-K retry baseline, broke nothing, and a human signed off on anything above the lowest risk tier.

## What it does

```
collect ──▶ drift ──▶ diagnose ──▶ propose ──▶ gate ──▶ apply ──▶ rollback
traces,    deterministic   LLM, closed    manifest +   two worktrees   tier 0 playbook auto
usage,     checks, free    cause set      git-checked  of HEAD, hash   tier 1-2 human-approved
redacted                                  patch        bound verdict   tier 3 finding only
```

- **collect** mines failures (any JSON schema), log lines, Claude Code transcripts (tool errors, user corrections, skill usage). Incremental, secrets redacted.
- **drift** is free and deterministic: retired projects still referenced as live, dead paths, heavily used skills that nobody routed, stale rules, size caps, secrets in editable files, duplicate eval ids.
- **diagnose** runs a fresh-context subagent with a closed cause set; infrastructure failures are never a harness defect.
- **propose** produces one-file manifests with a unified diff, evidence pointers, predicted fixes and predicted regressions. Git decides what the patch touches; the manifest's label is only checked against it.
- **gate** evaluates base and candidate in throwaway worktrees of HEAD: hard constraints (bloat, leakage, wireheading, hidden text, secrets), regression suites, drift count, train/val/holdout evals with the seed stored outside the repo, per-task non-regression, holdout must beat best-of-K, per-cluster epsilon, pairwise judge asked in both orders. The verdict is bound to HEAD, patch, config and eval hashes and signed.
- **apply** lands tier 0 (the playbook) automatically; tier 1 and 2 stop at the diff for a named human; tier 3 (hooks, settings, evals, config) is never patched by the loop. One-command **rollback**.
- **playbook** is an ACE-style append-only list of one-line lessons with helpful/harmful counters, so the harness grows knowledge without context collapse.

## Quick start

```bash
git clone https://github.com/oyekamal/harness-evolve
sh harness-evolve/install.sh /path/to/your-agent-repo old-project-name
```

That copies the skill into `your-agent-repo/.claude/skills/harness-evolve/`, runs the self-check, initialises `.harness-evolve/`, records the retired project, and prints the first drift report. Then tell your agent **"evolve the harness"**. See [INSTALL](.claude/skills/harness-evolve/README-INSTALL.md) for the manual route and configuration.

A real first run on a 130-skill personal agent repo found 88 live references to a project retired a month earlier, the most-used skill (20 uses in 30 days) absent from CLAUDE.md, 10 stale rules and a real API key inside an editable surface. Nothing was auto-applied: those are tier-1 edits, so they waited for a human.

## Why trust the gate

It was built as an adversarial gauntlet. Six independent critic agents attacked it across four rounds and confirmed 46 defects, every one of which is now fixed and pinned by a `selfcheck` assertion. Among the things they landed and that the gate now refuses:

- forging the risk tier through the manifest label
- deleting a hook through a `/dev/null` header or `x/` `y/` diff prefixes
- swapping the patch between gate and apply, hand-editing a manifest to `accepted`, appending a fake gate-log row
- a judge that explains itself ("output 1 loses to 2") being parsed as a verdict
- satisfying a `grep` check by adding the bare needle, a hidden HTML comment, zero-width characters, or a line hidden behind U+2028
- a removed line starting with `-- ` disabling the hunk scanner
- growing a new file past the bloat cap, forging playbook counters, smuggling "ignore previous rules" into a lesson
- a failed commit leaving the patch staged on the main branch

Blind installer critics, given this kit and a well-known open-source self-evolution repo with labels stripped, picked this one twice.

## Verify it yourself

```bash
python3 .claude/skills/harness-evolve/scripts/harness_evolve.py selfcheck
```

Builds a temporary repo, runs every attack above, checks that a legitimate edit is accepted and applied, and prints `selfcheck OK`. Takes about fifteen seconds. Works with `/bin/sh` as dash.

## Research basis

What was taken from each source and what was left behind, with the numbers: [references/research-basis.md](.claude/skills/harness-evolve/references/research-basis.md). Sources: Self-Harness (2606.09498), HarnessEvolve (2609.00829), ACE (2510.04618), Continual Harness (2605.09998), Prime Agent `/refine` (2608.23552), Hermes self-evolution, Rethinking the Evaluation of Harness Evolution (2607.12227), Agentic Harness Engineering (2604.25850), SkillRevise (2606.01139), QM, OpenJarvis spec-search (2605.17172), and the judge-hygiene papers on self-grading inflation (2511.23092) and position bias (2406.07791).

## Layout

```
.claude/skills/harness-evolve/
  SKILL.md                        the skill: when to use it, the loop, hard rules
  README-INSTALL.md               setup for any repo
  scripts/harness_evolve.py       the CLI (init collect drift diagnose propose gate apply rollback playbook status selfcheck)
  scripts/install.sh              one-command installer
  references/research-basis.md    paper-by-paper design notes
  references/gate-protocol.md     the evaluation protocol, auditable from gate_log.jsonl alone
  references/change-manifest.md   diagnosis, manifest and eval-task schemas
  references/*-prompt.md          diagnoser, proposer and judge prompts
examples/evals/                   eval task examples
```

## Requirements

Python 3.8+ (standard library only), git 2.20+, a POSIX shell. Works on any repo that has a `CLAUDE.md` or `.claude/` directory. Nothing is installed with pip.

## Known limits

- A deterministic check can always be gamed by a determined patch. The structural defence is that only the playbook auto-lands; everything else needs a human reading the diff.
- Verdict signatures are keyed by a seed readable by the same OS user. They stop a careless agent, not a hostile process with shell access. Set `approvers` and use PR review for tier 1 and above.
- The holdout and best-of-K rules only mean something with roughly twenty behavioural eval tasks. Build the evals before trusting the loop.

## License

MIT.
