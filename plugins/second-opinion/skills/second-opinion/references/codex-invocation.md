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

**Workaround:** Place review instructions in an `AGENTS.md`
file at the project root. Codex reads this file automatically
and will apply the instructions to its review.

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
