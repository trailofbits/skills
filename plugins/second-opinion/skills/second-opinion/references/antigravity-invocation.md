# Antigravity Invocation

Use `agy` print mode with the prepared prompt as one quoted argument.
Use the slug chosen through the shared model-selection step, which reads
`agy models`; effort is part of that slug. When the listing is
unavailable, the fallback is `gemini-3.1-pro-high`. Preserve a model
explicitly requested by the user.

## Command

With `prompt_file`, `output_file`, and `stderr_log` already created,
and `model` set to the chosen slug:

```bash
PATH="$HOME/.local/bin:$PATH" agy \
  --model "$model" \
  --output-format text \
  --disable-slash-commands \
  -p="$(cat "$prompt_file")" \
  > "$output_file" 2> "$stderr_log"
```

Keep `-p=` attached to its value and place other flags before it.
`--disable-slash-commands` prevents slash-command expansion within
the supplied diff. No review extension is required.

The argument form also works with the previously tested CLI 1.1.21.
Current [headless mode documentation](https://antigravity.google/docs/cli/headless/)
supports stdin and schema enforcement, so the older client's stdin and
JSON limitations should not be treated as current guarantees. Text output
is sufficient for this review comparison.

A prompt passed as an argument can exceed the operating system's argument
size limit. If that occurs, use the installed version's documented stdin
mode or ask for a smaller scope; do not drop files from the patch.

## Permissions and results

Request review findings in the final response. Do not use plan mode or
`--dangerously-skip-permissions`. Preserve the user's permission settings;
headless mode alone does not make the workspace read-only.

Read both output and diagnostics. Current headless mode can exit zero
after denying a tool, so an exit code alone cannot establish that a review
completed. Report missing context or denied inspection as a coverage gap.
A plan artifact or request to proceed is not a completed review.

| Failure | Response |
|---------|----------|
| Executable missing | Check `~/.local/bin`, then report the [installation instructions](https://antigravity.google/docs/cli/getting-started) |
| Empty prompt | Use the attached `-p=` argument form |
| Unknown model | List available models and request a replacement |
| Listed model needs a newer CLI | Offer `agy update` and ask before running it |
| `--effort` conflicts with the model | Drop `--effort`; the suffixed slug already sets it |
| Auth, quota, or timeout error | Report the failure and preserve any partial output |
