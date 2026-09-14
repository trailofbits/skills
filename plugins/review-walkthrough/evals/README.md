# Review Walkthrough Evals

The `rate-limit-walkthrough` case builds a throwaway Git repository and grades the
generated `walkthrough.html`. Its seven-file Python rate limiter has a clear
dependency order and an unclamped refill at `ratelimit/bucket.py:26`.

```bash
CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval plugins/review-walkthrough \
  --ablation none \
  --scaffold \
  --allow-tools Bash Write Edit \
  --judge-model sonnet \
  --threshold 1.0 \
  --no-publish \
  --report /tmp/review-walkthrough-report.html
```

`--scaffold` is required: the runner does not execute author-supplied fixture
scripts by default. The fixture creates `origin/main` and `origin/HEAD` locally,
so base discovery needs no network access. The prompt tells the model to report
a missing fixture and stop, preventing an invented repository from earning
partial credit.

The case permits 50 turns and 900 seconds. Its `allowed_tools` grants file reads,
writes, Bash, search, and skill invocation. The command's `--allow-tools` supplies
the outer grant for writes and shell execution. Use a Sonnet judge for the
semantic rubric. `--threshold 1.0` requires every scored grader to pass, and
`--no-publish` keeps the report local. The prompt starts with the slash command
because the skill requires direct user invocation. Calling the Skill tool from
a prose request is refused. This case checks the plugin's behavior; it does not
measure uplift against a baseline without the plugin.

## What Is Checked

| Check | Evidence |
|-------|----------|
| Renderer invocation | Tool calls in the trace |
| Output exists and contains populated data | Generated HTML |
| Definitions precede consumers; tests follow their subjects | Serialized step order |
| A review finding anchors to the bucket implementation | Serialized review objects |
| Explanations name real identifiers and the review finds the refill defect | LLM judge reading the artifact |

The ordering regexes use `b/`-prefixed diff paths, so imports cannot satisfy them.
A `"message":` key separates steps; grouping related files in the same step is
allowed. The first-step hunk check and placeholder check are inexpensive artifact
checks. The renderer validates every file's complete diff, matching it against
the captured patch, and checks line anchors, ranges, and sides.

The semantic judge reads only the explanation and review data. Its rubric excludes
escaping, array alignment, anchors, and ordering, which are handled by code and
deterministic checks. Keeping mechanical criteria out of the LLM rubric avoids
penalizing correct HTML or a legitimate grouping.

The renderer's Python tests and the page's `node:test` suite run under
`make check`. They cover data embedding, diff fidelity, line anchors, and generated
review commands without posting to GitHub. CI also runs `tests/browser-check.mjs`
in Chrome to test HTML sanitization, comment conversion, navigation, and comment
controls against the real DOM. Run it locally with a Chromium executable as its
argument. The model eval measures the explanation and review the skill produces.

## Limits and Troubleshooting

The fixture has no remote or open PR, so the model eval uses `pr_meta: null`.
PR command behavior is covered by deterministic tests; this case does not measure
live GitHub metadata collection or submission. The small, deliberately seeded
fixture measures regressions in this use case; it does not establish review
quality across arbitrary repositories.

A missing artifact can mean the scaffold was omitted or the run exhausted its
turn or time budget. Use `--keep-temp` and inspect the final record of
`<sandbox>/out/trace.jsonl` to distinguish those failures. The LLM judge receives
a bounded view of the artifact; split a growing fixture before its embedded data
exceeds the runner's focus limit.

On 2026-09-14, Claude Code 2.1.263 expanded the direct slash command but its macOS
eval sandbox denied shell writes to both the fixture checkout and its temporary
directory. The run could not reach the renderer. No passing model-eval result is
claimed for this revision. This environment failure does not affect the local
Python, Node, or Chrome tests. The eval CLI is early access; check its local
`--help` if a flag or grader schema changes.
