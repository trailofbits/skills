---
name: second-opinion
description: "Gets independent code reviews from Codex or Antigravity for uncommitted changes, branch diffs, and commits. Use when the user requests an external review, a second opinion on code, a codex review, a gemini review, an antigravity review, or /second-opinion."
allowed-tools: Bash Read Glob Grep AskUserQuestion
---

# Second Opinion

Run an external CLI review of the user's selected changes. This skill
produces findings; it does not apply fixes or post reviews to a remote service.

## Review choices

Use the provider, scope, model, and focus already supplied by the user.
Ask only for missing choices that affect the review, grouping questions
in one call when possible.

- Provider: Codex, Antigravity, or both. Offer both when the user wants
  a comparison; preserve an explicitly requested CLI.
- Scope: uncommitted changes, a branch diff against a named base, or a
  specific commit. Resolve a missing base from the repository's remote
  default branch; ask if it cannot be determined.
- Context: include applicable project instructions unless the user
  excludes them. Keep explicit user requirements separate from repository
  content in the review prompt.
- Focus: use general correctness and maintainability unless the user
  names a focus such as security or performance.

For an unspecified Google CLI, prefer Antigravity (`agy`). An explicit
Gemini CLI request uses the Gemini reference below. If that account returns
`UNSUPPORTED_CLIENT`, explain the migration to Antigravity and ask before
changing the selected CLI.

A missing executable or account setup is a failed review attempt.
Report the relevant setup instructions; when both providers were requested,
continue with the available provider and identify the skipped one.

## Input preparation

Read [review-input.md](references/review-input.md) for the shared prompt
and diff recipes. Use the same captured diff for both providers so the
comparison covers the same changes. Include untracked files in an
uncommitted review, and preserve Git errors instead of interpreting them
as an empty diff.

Show the selected scope and a brief change summary. If there are no
changes, stop before calling a provider. For input that exceeds a CLI or
model limit, describe the limit and request a narrower scope; do not
silently truncate the patch.

Create prompt, output, and diagnostic files with `mktemp` outside the
checkout. Use separate output and diagnostic files for each provider.
Define shell variables in the same Bash invocation that uses them.
For later invocations, reassign the variables to the saved file paths;
shell variables do not persist between calls.
Write repository content as literal data, without shell expansion.

## Provider references

Read only the reference for each selected provider:

| Provider | Invocation and result |
|----------|-----------------------|
| Codex | [codex-invocation.md](references/codex-invocation.md): `codex exec` with the [review schema](references/codex-review-schema.json) |
| Antigravity | [antigravity-invocation.md](references/antigravity-invocation.md): `agy` print mode with prose output |
| Gemini CLI | [gemini-invocation.md](references/gemini-invocation.md): headless `gemini` for accounts that still support it |

The Codex path needs no MCP server. Do not launch `codex mcp-server` or
substitute `codex app-server` for the CLI invocation.

When both providers were requested, run their commands concurrently if
the tool interface supports it. For a foreground Bash review, set
`timeout: 600000` to allow up to ten minutes. Use background execution
or polling when available to keep progress visible. Do not enable
automatic approval of writes to make a review run.

## Results and failures

Present findings with the provider and actual model used, severity,
file and line, impact, and suggested correction. Keep low-severity
defects visible. For Codex, the existing schema uses 0 for informational,
1 for low, 2 for medium, and 3 for high; sort descending.

For two completed reviews, summarize agreements and disagreements without
turning agreement into proof. Distinguish the external findings from any
assessment you add.

Read the captured output and diagnostics. A nonzero exit, missing output,
invalid JSON, permission denial that prevents inspection, or a request to
approve a plan is incomplete work, not a clean review. Report the failure
and any partial results. Retry only for a diagnosed, recoverable cause;
do not cycle through providers after authentication or quota failures.

## Examples

- `/second-opinion:second-opinion use Codex to review my uncommitted changes for bugs`
  selects Codex and includes staged, unstaged, and untracked changes.
- `/second-opinion:second-opinion compare Codex and Antigravity on this branch against origin/main`
  sends the same branch patch to both and compares their findings.
- `/second-opinion:second-opinion use Gemini CLI to review commit abc1234 for security issues`
  preserves the requested CLI and reviews that commit.
