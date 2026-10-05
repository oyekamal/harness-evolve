# Example eval tasks

Copy any of these into `<your-repo>/.harness-evolve/evals/` and edit the needles.

- Tasks with only `check` are harness invariants: free, deterministic, run on every gate.
- Tasks with `run` call your agent; `check` sees the output in `$HE_OUTPUT`.
- Tasks with `judge` need `judge_cmd` in config, a different model and context from the producer.

Write needles separator-insensitively (`old[-_ ]?project`, `\b`) and prefer `check` over `judge`.
