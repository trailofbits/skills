# Codex Invocation

Use `codex exec` with the prepared prompt on stdin. It supports a
custom focus and project context alongside a manually captured diff.
The built-in `codex exec review` scope flags cannot be combined with
its positional prompt, so they do not replace this invocation.

The default remains `gpt-5.6-sol` with `xhigh` reasoning. Preserve an
explicit model or effort supplied by the user. The flags below were
checked with Codex CLI 0.154.0 `--help` on 2026-09-14.

## Command

With `prompt_file`, `output_file`, and `stderr_log` already created
outside the checkout, run from the repository root:

```bash
codex exec \
  -c model='"gpt-5.6-sol"' \
  -c model_reasoning_effort='"xhigh"' \
  --sandbox read-only \
  --ephemeral \
  --output-schema "{baseDir}/references/codex-review-schema.json" \
  -o "$output_file" \
  - < "$prompt_file" \
  > /dev/null 2> "$stderr_log"
```

`-o` saves the final response while diagnostics remain in
`stderr_log`. `--output-schema` requests structured findings.
`--ephemeral` avoids persisting a review session.

These options are documented in OpenAI's
[non-interactive mode guide](https://learn.chatgpt.com/docs/non-interactive-mode).
No MCP server is involved. The
[Codex changelog](https://learn.chatgpt.com/docs/changelog) records removal
of `codex mcp-server` in CLI 0.154.0.

## Result handling

Parse `output_file` as JSON. Use the returned findings, explanation,
and confidence rather than CLI progress messages. An empty findings
array is meaningful only after the invocation completed and returned a
valid review.

The shipped schema uses higher numbers for higher severity:
0 informational, 1 low, 2 medium, 3 high. This is not the P0-critical
convention used by some other review formats. Do not invert it when
presenting findings.

## Failure handling

| Failure | Response |
|---------|----------|
| Executable missing | Report that Codex must be installed and authenticated; installation command: `npm i -g @openai/codex` |
| Authentication or quota error | Report the error and stop this provider; changing models does not repair missing credentials or exhausted quota |
| Default model unavailable | If the user did not pin a model, retry once with `gpt-5.6` and disclose the substitution |
| Explicit model unavailable | Report the failure and ask for a replacement |
| Nonzero exit, empty file, or invalid JSON | Read diagnostics and report an incomplete review |
| Sandbox denied a needed read or command | Report the coverage gap; do not ignore it or remove the sandbox |
| Timeout | Preserve partial output and report the timeout; suggest a narrower scope |

A model reported as "not supported when using Codex with a ChatGPT account"
is a model-entitlement failure. Use the model-unavailable response above:
retry only when the user did not pin a model. This differs from missing
or invalid credentials and exhausted quota, which stop the provider.
