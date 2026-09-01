---
name: second-opinion
description: "Runs external LLM code reviews (OpenAI Codex or Google Antigravity CLI) on uncommitted changes, branch diffs, or specific commits. Use when the user asks for a second opinion, external review, codex review, gemini review, antigravity review, or mentions /second-opinion."
allowed-tools: Bash Read Glob Grep AskUserQuestion
---

# Second Opinion

Shell out to external LLM CLIs for an independent code review powered by
a separate model. Supports OpenAI Codex CLI (`codex`) and Google
Antigravity CLI (`agy`).

## When to Use

- Getting a second opinion on code changes from a different model
- Reviewing branch diffs before opening a PR
- Checking uncommitted work for issues before committing
- Running a focused review (security, performance, error handling)
- Comparing review output from multiple models

## When NOT to Use

- Neither Codex CLI nor Antigravity CLI is installed
- No API key or subscription configured for either tool
- Reviewing non-code files (documentation, config)
- You want Claude's own review (just ask Claude directly)

## Gemini CLI Is End-of-Life

As of 2026-06-18, `gemini` (Gemini CLI) stopped serving Google AI Pro,
Ultra, and free-tier individual accounts. Those accounts now get
`UNSUPPORTED_CLIENT` on every request, pointing at
<https://antigravity.google>. The replacement is **Antigravity CLI**,
binary `agy`.

Default to `agy`. Only fall back to `gemini` when the user has a Gemini
Code Assist Standard/Enterprise license or a paid Gemini API key
(`GEMINI_API_KEY`) — those still work. See
[references/gemini-invocation.md](references/gemini-invocation.md) for
that legacy path.

## Quick Reference

```
# Codex (headless exec with structured JSON output)
codex exec -c model='"gpt-5.6-sol"' -c model_reasoning_effort='"xhigh"' \
  --sandbox read-only --ephemeral \
  --output-schema codex-review-schema.json \
  -o "$output_file" - < "$prompt_file"

# Antigravity (headless print mode — prompt must be an ARGUMENT, not stdin)
git diff HEAD > /tmp/review-diff.txt
agy --model gemini-3.1-pro-high --output-format text \
  --disable-slash-commands -p="$(cat /tmp/review-prompt.txt)"
```

## Invocation

### 1. Gather context interactively

Use `AskUserQuestion` to collect review parameters in one shot.
Adapt the questions based on what the user already provided
in their invocation (skip questions they already answered).

Combine all applicable questions into a single `AskUserQuestion`
call (max 4 questions).

**Question 1 — Tool** (skip if user already specified):

```
header: "Review tool"
question: "Which tool should run the review?"
options:
  - "Both Codex and Antigravity (Recommended)" → run both in parallel
  - "Codex only"                               → codex exec
  - "Antigravity only"                         → agy print mode
```

If the user says "gemini", treat it as Antigravity unless they
explicitly have a paid Code Assist / API-key setup.

**Question 2 — Scope** (skip if user already specified):

```
header: "Review scope"
question: "What should be reviewed?"
options:
  - "Uncommitted changes" → git diff HEAD + untracked files
  - "Branch diff vs main" → git diff <branch>...HEAD (auto-detect default branch)
  - "Specific commit"     → git diff <sha>~1..<sha> (follow up for SHA)
```

**Question 3 — Project context** (skip if neither CLAUDE.md nor AGENTS.md exists):

Check for CLAUDE.md first, then AGENTS.md in the repo root.
Only show this question if at least one exists.

```
header: "Project context"
question: "Include project conventions file so the review
  checks against your standards?"
options:
  - "Yes, include it"
  - "No, standard review"
```

**Question 4 — Review focus** (always ask):

```
header: "Review focus"
question: "Any specific focus areas for the review?"
options:
  - "General review"    → no custom prompt
  - "Security & auth"   → security-focused prompt
  - "Performance"       → performance-focused prompt
  - "Error handling"    → error handling-focused prompt
```

### 2. Run the tool directly

Do not pre-check tool availability. Run the selected tool
immediately. If the command fails with "command not found" or
an extension is missing, report the install command from the
Error Handling table below and skip that tool (if "Both" was
selected, run only the available one).

`agy` installs to `~/.local/bin`, which is not always on PATH.
Prefix the call with `export PATH="$HOME/.local/bin:$PATH"` before
concluding it is missing.

## Diff Preview

After collecting answers, show the diff stats:

```bash
# For uncommitted (tracked + untracked):
git diff --stat HEAD
git ls-files --others --exclude-standard

# For branch diff:
git diff --stat <branch>...HEAD

# For specific commit:
git diff --stat <sha>~1..<sha>
```

If the diff is empty, stop and tell the user.

If the diff is very large (>2000 lines changed), warn the user
and ask whether to proceed or narrow the scope.

## Auto-detect Default Branch

For branch diff scope, detect the default branch name:

```bash
git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null \
  | sed 's@^refs/remotes/origin/@@' || echo main
```

## Codex Invocation

See [references/codex-invocation.md](references/codex-invocation.md)
for full details on command syntax, prompt assembly, and the
structured output schema.

Summary:
- Uses `codex exec` (not `codex exec review`) for headless operation.
  `codex exec review` has native `--uncommitted` / `--base` /
  `--commit` scope flags, but they are mutually exclusive with a
  custom `[PROMPT]`, so it cannot carry project context or focus
  instructions. Keep the manual prompt-assembly approach.
- Model: `gpt-5.6-sol`, reasoning: `xhigh`
- Uses OpenAI's published code review prompt (fine-tuned into the model)
- Diff is generated manually and piped via stdin with the prompt
- `--output-schema` produces structured JSON findings
- `-o` captures only the final message (no thinking/exec noise)
- All three scopes (uncommitted, branch, commit) support project
  context and focus instructions (no limitations)
- Falls back to `gpt-5.6`, then `gpt-5.4`, on auth errors
- Output is clean JSON — parse and present findings by priority
- Set `timeout: 600000` on the Bash call

## Antigravity Invocation

See [references/antigravity-invocation.md](references/antigravity-invocation.md)
for full details on flags, scope mapping, and model selection.

Summary:
- Model: `gemini-3.1-pro-high` (effort is baked into the model slug)
- **The prompt must be a command-line argument, not stdin.** `agy`
  print mode does not read prompts from stdin unless
  `--input-format stream-json` is used. Assemble the prompt into a
  file, then pass `-p="$(cat "$prompt_file")"`.
- **Use `-p=<value>` with an equals sign.** Bare `-p` swallows the
  next flag as its prompt value and silently discards the real one.
- Add `--disable-slash-commands` so a line in the untrusted diff cannot
  be expanded as a slash command
- Do NOT pass `--mode plan`. It intermittently returns a "plan artifact
  / click Proceed" stub instead of the review. Omit `--mode` entirely
- Do NOT pass `--dangerously-skip-permissions`; it is unnecessary for
  a text-only diff review and will be blocked in restricted environments
- Prefer `--output-format text`. `--json-schema` is advisory, not
  enforced: it emits schema-shaped JSON nested inside a `response`
  string, duplicates the payload, and ran ~3x slower in testing
- Set `timeout: 600000` on the Bash call

**Scope mapping for `git diff`** (Antigravity has no built-in scope flags):

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` + untracked (see codex-invocation.md) |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

## Running Both

When the user picks "Both" (the default):

1. Run Codex and Antigravity in parallel — issue both Bash tool
   calls in a single response. Both commands are read-only
   (they review diffs via external APIs) so there is no
   shared state or git lock contention.
2. Collect both results, then present with clear headers:

```
## Codex Review (gpt-5.6-sol)
<codex output>

## Antigravity Review (gemini-3.1-pro-high)
<agy output>
```

Summarize where the two reviews agree and differ.

## Error Handling

| Error | Action |
|-------|--------|
| `codex: command not found` | Tell user: `npm i -g @openai/codex` |
| `agy: command not found` | Retry with `export PATH="$HOME/.local/bin:$PATH"`. Still missing → tell user to install Antigravity from <https://antigravity.google> |
| `agy` error: `-p took "--model" as its prompt` | Use `-p=<value>` form and move other flags before it |
| `agy` error: `empty prompt` | The prompt was piped on stdin. Pass it as an argument instead |
| `gemini` error: `UNSUPPORTED_CLIENT` / "migrate to the Antigravity suite" | Gemini CLI is EOL for individual tiers. Switch to `agy` |
| Model auth error (Codex) | Retry with `gpt-5.6`, then `gpt-5.4` |
| Empty diff | Tell user there are no changes to review |
| Timeout | Inform user and suggest narrowing the diff scope |
| Tool partially unavailable | Run only the available tool, note the skip |

## Examples

**Both tools (default):**
```
User: /second-opinion
Claude: [asks 4 questions: tool, scope, context, focus]
User: picks "Both", "Branch diff", "Yes include CLAUDE.md", "Security"
Claude: [detects default branch = main]
Claude: [shows diff --stat: 6 files, +103 -15]
Claude: [assembles prompt with review instructions + CLAUDE.md + security focus + diff]
Claude: [runs codex exec and agy in parallel]
Claude: [reads codex output file, parses structured findings]
Claude: [presents both reviews, highlights agreements/differences]
```

**Codex only with inline args:**
```
User: /second-opinion check uncommitted changes for bugs
Claude: [scope known: uncommitted, focus known: custom]
Claude: [asks 2 questions: tool, project context]
User: picks "Codex only", "No context"
Claude: [shows diff --stat: 3 files, +45 -10]
Claude: [writes prompt file with review instructions + diff]
Claude: [runs codex exec, reads structured JSON output]
Claude: [presents findings by priority with file:line refs]
```

**Antigravity only:**
```
User: /second-opinion
Claude: [asks 4 questions]
User: picks "Antigravity only", "Uncommitted", "No", "General"
Claude: [shows diff --stat: 2 files, +20 -5]
Claude: [writes prompt file, runs agy --model gemini-3.1-pro-high -p="$(cat prompt.txt)"]
Claude: [presents review]
```

**Large diff warning:**
```
User: /second-opinion
Claude: [asks questions] → user picks "Both", "Uncommitted", "General"
Claude: [shows diff --stat: 45 files, +3200 -890]
Claude: "Large diff (3200+ lines). Proceed, or narrow the scope?"
User: "proceed"
Claude: [runs both reviews]
```
