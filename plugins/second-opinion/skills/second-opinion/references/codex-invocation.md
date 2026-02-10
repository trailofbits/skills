# Codex CLI Invocation

## Default Configuration

- Model: `gpt-5.3-codex`
- Reasoning effort: `xhigh`

## Base Command

```bash
codex review <scope-flag> \
  -c model='"gpt-5.3-codex"' \
  -c model_reasoning_effort='"xhigh"'
```

Model and reasoning are set via `-c` config overrides (not `-m`).

## Scope Flags

| Scope | Flag |
|-------|------|
| Uncommitted changes | `--uncommitted` (staged + unstaged + untracked) |
| Branch diff | `--base <branch>` |
| Specific commit | `--commit <sha>` |

## Adding a Review Prompt

Assemble the prompt string from the user's choices:

```
<If project context was requested>
Project conventions and standards:
---
<full contents of CLAUDE.md or AGENTS.md>
---

<If focus area was selected or custom text provided>
<focus area instructions>
```

If there is no prompt (general review, no context), run
codex review without a prompt argument.

## Passing the Prompt

`--uncommitted` accepts a positional prompt argument:

```bash
codex review --uncommitted \
  -c model='"gpt-5.3-codex"' \
  -c model_reasoning_effort='"xhigh"' \
  "the assembled prompt"
```

`--base` and `--commit` do NOT accept a custom prompt via any
mechanism. The positional `[PROMPT]` argument is mutually
exclusive with these flags, and there is no stdin option.

**Limitation:** When using `--base` or `--commit`, Codex
cannot receive custom review instructions or project context
via prompt. If an `AGENTS.md` file exists at the repo root,
Codex reads it automatically — but the skill should not
create or modify this file.

For `--uncommitted`, project context and focus instructions
are passed via the positional prompt argument (no limitation).

## Model Fallback

If `gpt-5.3-codex` fails with an auth error (e.g., "not supported
when using Codex with a ChatGPT account"), retry with
`gpt-5.2-codex`. Log the fallback for the user.

## Error Handling

| Error | Action |
|-------|--------|
| `codex: command not found` | Tell user: `npm i -g @openai/codex` |
| Model auth error | Retry with `gpt-5.2-codex` |
| Timeout | Suggest `high` reasoning instead of `xhigh` |
| `EPERM` / sandbox errors | Expected — `codex review` runs sandboxed and cannot execute tests or builds. Ignore these. |

## Parsing Output

Codex review output is verbose. It contains sandbox warnings,
`[thinking]` blocks, `[exec]` blocks showing tool calls and
full file reads, and the actual review findings.

When presenting results to the user:
- **Do NOT dump raw output.** Summarize the findings.
- The review conclusion is typically at the **end** of the
  output, after all thinking and exec blocks.
- Skip sandbox permission warnings (`EPERM`, `xcodebuild`).
- Skip `[thinking]` and `[exec]` block contents unless they
  contain specific findings the user should see.
- If the output is truncated (>30KB), read the persisted
  output file to find the conclusion.
