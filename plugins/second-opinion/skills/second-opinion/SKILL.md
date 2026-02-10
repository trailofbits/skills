---
name: second-opinion
description: "Runs external LLM code reviews (OpenAI Codex or Google Gemini CLI) on uncommitted changes, branch diffs, or specific commits. Use when the user asks for a second opinion, external review, codex review, gemini review, or mentions /second-opinion."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
  - AskUserQuestion
---

# Second Opinion

Shell out to external LLM CLIs for an independent code review powered by
a separate model. Supports OpenAI Codex CLI and Google Gemini CLI.

## When to Use

- Getting a second opinion on code changes from a different model
- Reviewing branch diffs before opening a PR
- Checking uncommitted work for issues before committing
- Running a focused review (security, performance, error handling)
- Comparing review output from multiple models

## When NOT to Use

- Neither Codex CLI nor Gemini CLI is installed
- No API key or subscription configured for either tool
- Reviewing non-code files (documentation, config)
- You want Claude's own review (just ask Claude directly)

## Safety Note

Gemini CLI is invoked with `--yolo`, which auto-approves all
tool calls without confirmation. This is required for headless
(non-interactive) operation but means Gemini will execute any
tool actions its extensions request without prompting.

## Quick Reference

```
# Codex
codex review --uncommitted
codex review --base <branch>
codex review --commit <sha>

# Gemini (code review extension)
gemini -p "/code-review" --yolo -e code-review
# Gemini (headless with diff — see references/ for full heredoc pattern)
git diff HEAD > /tmp/review-diff.txt
cat <<'PROMPT' | gemini -p - --yolo
Review this diff...
$(cat /tmp/review-diff.txt)
PROMPT
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
  - "Both Codex and Gemini (Recommended)" → run both sequentially
  - "Codex only"                          → codex review
  - "Gemini only"                         → gemini CLI
```

**Question 2 — Scope** (skip if user already specified):

```
header: "Review scope"
question: "What should be reviewed?"
options:
  - "Uncommitted changes" → --uncommitted / git diff HEAD
  - "Branch diff vs main" → --base (auto-detect default branch)
  - "Specific commit"     → --commit (follow up for SHA)
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

## Diff Preview

After collecting answers, show the diff stats:

```bash
# For uncommitted:
git diff --stat HEAD

# For branch diff:
git diff --stat <branch>...HEAD

# For specific commit:
git diff --stat <sha>~1..<sha>
```

If the diff is empty, stop and tell the user.

If the diff is very large (>2000 lines changed), warn the user
that high-effort reasoning on a large diff will be slow and ask
whether to proceed or narrow the scope.

## Auto-detect Default Branch

For branch diff scope, detect the default branch name:

```bash
git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null \
  | sed 's@^refs/remotes/origin/@@' || echo main
```

## Codex Invocation

See [references/codex-invocation.md](references/codex-invocation.md)
for full details on command syntax, prompt passing, and model
fallback.

Summary:
- Model: `gpt-5.3-codex`, reasoning: `xhigh`
- `--uncommitted` takes a positional prompt
- `--base` and `--commit` do NOT accept custom prompts
  (use project `AGENTS.md` for review instructions)
- Falls back to `gpt-5.2-codex` on auth errors
- Set `timeout: 600000` on the Bash call

## Gemini Invocation

See [references/gemini-invocation.md](references/gemini-invocation.md)
for full details on flags, scope mapping, and extension usage.

Summary:
- Model: `gemini-3-pro-preview`, flags: `--yolo`, `-e`, `-m`
- For uncommitted general review: `gemini -p "/code-review" --yolo -e code-review`
- For branch/commit diffs: pipe `git diff` into `gemini -p`
- Security extension name is `gemini-cli-security` (not `security`)
- `/security:analyze` is interactive-only — use `-p` with a
  security prompt instead
- Run `/security:scan-deps` as bonus when security focus selected
- Set `timeout: 600000` on the Bash call

**Scope mapping for `git diff`** (Gemini has no built-in scope flags):

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

## Running Both

When the user picks "Both" (the default):

1. Run Codex and Gemini in parallel — issue both Bash tool
   calls in a single response. Both commands are read-only
   (they review diffs via external APIs) so there is no
   shared state or git lock contention.
2. Collect both results, then present with clear headers:

```
## Codex Review (gpt-5.3-codex)
<codex output>

## Gemini Review (gemini-3-pro-preview)
<gemini output>
```

Summarize where the two reviews agree and differ.

## Error Handling

| Error | Action |
|-------|--------|
| `codex: command not found` | Tell user: `npm i -g @openai/codex` |
| `gemini: command not found` | Tell user: `npm i -g @google/gemini-cli` |
| Gemini `code-review` extension missing | Tell user: `gemini extensions install https://github.com/gemini-cli-extensions/code-review` |
| Gemini `gemini-cli-security` extension missing | Tell user: `gemini extensions install https://github.com/gemini-cli-extensions/security` |
| Model auth error (Codex) | Retry with `gpt-5.2-codex` |
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
Claude: [runs Codex review with security prompt]
Claude: [runs Gemini review with security prompt + dep scan]
Claude: [presents both reviews, highlights agreements/differences]
```

**Codex only with inline args:**
```
User: /second-opinion check uncommitted changes for bugs
Claude: [scope known: uncommitted, focus known: custom]
Claude: [asks 2 questions: tool, project context]
User: picks "Codex only", "No context"
Claude: [shows diff --stat: 3 files, +45 -10]
Claude: [runs codex review --uncommitted with prompt]
Claude: [presents review]
```

**Gemini only:**
```
User: /second-opinion
Claude: [asks 4 questions]
User: picks "Gemini only", "Uncommitted", "No", "General"
Claude: [shows diff --stat: 2 files, +20 -5]
Claude: [runs gemini -p "/code-review" --yolo -e code-review]
Claude: [presents review]
```

**Large diff warning:**
```
User: /second-opinion
Claude: [asks questions] → user picks "Both", "Uncommitted", "General"
Claude: [shows diff --stat: 45 files, +3200 -890]
Claude: "Large diff (3200+ lines). High-effort reasoning will be
  slow. Proceed, or narrow the scope?"
User: "proceed"
Claude: [runs both reviews]
```
