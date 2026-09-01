# Antigravity CLI (`agy`) Invocation

Antigravity CLI replaced Gemini CLI for individual Google accounts on
2026-06-18. Binary is `agy`. Verified against `agy` 1.1.21.

## Default Configuration

- Model: `gemini-3.1-pro-high`
- Output: `--output-format text`
- Add `--disable-slash-commands` — the prompt embeds an untrusted diff,
  and without this a line in the diff that looks like `/something` can
  be expanded as a slash command

## PATH

`agy` installs to `~/.local/bin`, which is often absent from a
non-interactive shell's PATH. Always prefix:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Models

`agy models` lists what the account can reach. As of testing:

```
gemini-3.7-flash-high / -medium / -low
gemini-3.6-flash-high / -medium / -low
gemini-3.5-flash-high / -medium / -low
gemini-3.1-pro-high
gemini-3.1-pro-low
claude-sonnet-4-6
claude-opus-4-6-thinking
gpt-oss-120b-medium
```

Reasoning effort is part of the model slug — there is no separate
effort flag to set for these (though `--effort low|medium|high` exists
for models that take it). Use `gemini-3.1-pro-high` for code review:
it is the strongest Gemini option exposed.

Do not select `claude-*` slugs for a second opinion — the point is a
different model family from Claude.

## Key Flags

| Flag | Purpose |
|------|---------|
| `-p=<prompt>` / `--print=<prompt>` | Non-interactive (headless) mode |
| `--model <slug>` | Model selection |
| `--mode plan` | Plan mode — **do not use for reviews**, see below |
| `--disable-slash-commands` | Stop diff text from being read as slash commands |
| `--output-format text\|json\|stream-json` | Output shape |
| `--json-schema <file>` | Advisory structured output (see caveat) |
| `--sandbox` | Terminal restrictions |
| `--dangerously-skip-permissions` | Auto-approve tools — **do not use** |

## Two Gotchas That Will Break the Call

### 1. The prompt must be an argument, not stdin

Unlike `codex exec -`, `agy` print mode does **not** read the prompt
from stdin (only `--input-format stream-json` consumes stdin, as
NDJSON). Piping a diff into `agy -p` fails with:

```
Error: Error: empty prompt. Usage: agy --print "your prompt here"
```

Assemble the prompt into a file, then pass its contents:

```bash
agy --model gemini-3.1-pro-high --output-format text \
  --disable-slash-commands -p="$(cat "$prompt_file")"
```

### 2. Use `-p=<value>`, never bare `-p`

Bare `-p` consumes the next token as its prompt value. `agy -p --model x`
takes `--model` as the prompt and discards the real one:

```
Error: -p took "--model" as its prompt, so the intended prompt was left
as an argument and ignored.
```

Always use the `=` form and put other flags before it.

## Prompt Assembly

Same structure as the Codex path. Write to `$prompt_file`:

```
You are reviewing a proposed code change made by another engineer.
Flag only actionable issues introduced by this diff, citing the affected
file and line range. Prioritize correctness, security, performance, and
maintainability over nits. After the findings, give an overall
correctness verdict and a confidence score.
Review the diff text only.

<If project context was requested>
Project conventions and standards:
---
<full contents of CLAUDE.md or AGENTS.md>
---

<If focus area was selected>
Focus: <focus area instructions>

Diff to review:
---
<git diff output for the selected scope>
---
```

## Scope-to-Diff Mapping

`agy` has no built-in scope flags. Map the user's choice:

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` + untracked files (see codex-invocation.md) |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

**For uncommitted scope, use `git diff HEAD`, not bare `git diff`** —
bare `git diff` misses staged changes. Include untracked files too.

## Do Not Use `--mode plan`

`--mode plan` makes `agy` treat the review as a planning task. It
intermittently writes its findings into a plan artifact and returns
only a stub asking for approval that will never come:

```
I have created an implementation plan artifact containing my proposed
code review findings.
Please review the artifact and click "Proceed" if you agree...
```

The same command printed a full review on one run and this stub on the
next, so it is not safely reproducible. Omit `--mode` entirely — plain
print mode does not request tool approvals for a text-only diff review.

## Full Command

```bash
export PATH="$HOME/.local/bin:$PATH"
agy --model gemini-3.1-pro-high \
    --output-format text \
    --disable-slash-commands \
    -p="$(cat "$prompt_file")" \
  > "$output_file" 2>"$stderr_log"
```

Typical wall time for a small diff: 19–34s. Set `timeout: 600000`.

## Structured Output: Prefer Text

`--json-schema <file>` with `--output-format json` runs, but the schema
is advisory, not enforced. Observed with the Codex review schema:

- The findings JSON arrives as an **escaped string** inside a
  `response` field of the outer envelope, requiring a double parse
- `code_location` came back as a string (`"app.py:3-4"`) in one block
  and an object in another, contradicting the schema
- `confidence_score` came back as `100` where the schema says 0–1
- `overall_correctness` came back as `"Needs Work"`, not one of the
  schema's enum values
- The payload was emitted twice in the same response
- Took ~68s versus ~24s for the text path

Use `--output-format text` and present `agy`'s prose review as-is.
Keep the structured-JSON path for Codex only.

## Do Not Pass `--dangerously-skip-permissions`

A text-only diff review needs no tool approvals, and the flag is
blocked outright in permission-restricted environments. Leave it off.

## Extensions / Security Scanning

Antigravity CLI does not carry over the Gemini CLI `code-review` or
`gemini-cli-security` extensions, and has no `/security:scan-deps`
equivalent. For dependency scanning, use a dedicated tool
(`osv-scanner`, `npm audit`, `pip-audit`) rather than routing it
through `agy`.

`agy plugin list` shows what is installed if the user has added
plugins; there is no bundled review plugin to rely on.

## Error Handling

| Error | Action |
|-------|--------|
| `agy: command not found` | Add `~/.local/bin` to PATH; else install from <https://antigravity.google> |
| `-p took "--model" as its prompt` | Use `-p=<value>`, flags before it |
| `empty prompt` | Prompt was on stdin; pass as argument |
| Permission denied on `--dangerously-skip-permissions` | Drop the flag; plain print mode needs no approvals |
| Output is a "plan artifact / click Proceed" stub | `--mode plan` was passed. Remove it |
| Timeout | Inform user, suggest scoping down the diff |
