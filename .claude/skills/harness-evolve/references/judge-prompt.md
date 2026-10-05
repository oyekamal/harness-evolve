# Judge prompt

Used by `_judge_pair` for tasks that carry `judge`. The script wraps the task's `judge.prompt` as below and calls `judge_cmd` twice with the outputs swapped. Keep `judge.prompt` to the question only; the wrapper adds the format.

```
{judge.prompt}

You are comparing two candidate outputs. Reply with exactly one token: 1 or 2.

=== OUTPUT 1 ===
{first}

=== OUTPUT 2 ===
{second}

Which is better? Answer 1 or 2.
```

What the judge is never given: the task's cluster, the manifest, the diff, which output came from the candidate harness, how many rounds have run, or any reasoning from the producer. If your `judge_cmd` is `claude -p`, run it from a directory with no CLAUDE.md so no SessionStart hook injects the harness under test into the judge (this repo's hooks inject enough context to contaminate a judge; the self-improving-agent experiment measured ~124 s per contaminated call and unusable verdicts).

Writing a good `judge.prompt`:
- Name the single dimension: "Which reply answers the question in the first sentence?" not "Which is better overall?"
- Binary. Never "rate 1–10"; scores drift upward every round.
- If you can turn the question into a grep, do that instead and drop the judge.

Calibration before trust: make 10 pairs with a known winner (5 obvious, 5 close). The judge must get ≥ 8 right **in both orders**. Below that, the judge gates nothing; use a second model and majority, or a check.
