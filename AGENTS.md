# Repository agent workflow

## Required post-push verification

- **Mandatory command for performance-sensitive changes:** after pushing, run
  `bin/ci/verify-agent-performance <full-commit-sha>`. Do not report completion until it exits 0.
  The canonical cross-agent policy is [`docs/agent-performance-verification.md`](docs/agent-performance-verification.md).
- After every push, wait for the GitHub Actions runs triggered by that push to reach a terminal state. Do not report the task as complete while required jobs are queued or running.
- If a required job fails, inspect the failing step and job log, fix the failure when it is in scope, push the fix, and verify the replacement run.
- For a substantial change, or any change touching SMB transport, framing, codecs, signing, encryption, read/write paths, performance tests, or performance CI, inspect the `Performance` workflow job summary and logs after push.
- Performance-sensitive work is complete only after recording the run URL and comparing the alternating current/previous-master 20-pair medians measured on the same runner. Report effect size, 95% confidence interval, Holm-adjusted p-value, and observed spread; do not infer an improvement from a single raw sample or p-value alone.
- The push-time performance regression gate is mandatory. Do not bypass or weaken its thresholds merely to make a change green. If runner metadata is not comparable and the gate is skipped, state that performance was not verified and run a comparable measurement before claiming completion.
