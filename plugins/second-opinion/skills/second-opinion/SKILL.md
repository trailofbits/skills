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
# Codex (headless exec with structured JSON output)
codex exec --sandbox read-only --ephemeral \
  --output-schema codex-review-schema.json \
  -o "$output_file" - < "$prompt_file"

# Gemini (code review extension)
gemini -p "/code-review" --yolo -e code-review
# Gemini (headless with diff — see references/ for full pattern)
git diff HEAD > /tmp/review-diff.txt
{ printf '%s\n\n' 'Review this diff for issues.'; cat /tmp/review-diff.txt; } \
  | gemini -p - --yolo -m gemini-3.1-pro-preview
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
  - "Both Codex and Gemini (Recommended)" → run both in parallel
  - "Codex only"                          → codex exec
  - "Gemini only"                         → gemini CLI
```

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

## Skipping Inapplicable Checks

After determining the diff scope, skip checks that don't apply
to the files actually changed.

### Dependency Scanning

Only run `/security:scan-deps` when the diff touches dependency
manifest files. Check with:

```bash
git diff --name-only <scope> \
  | grep -qiE '(package\.json|package-lock|yarn\.lock|pnpm-lock|Gemfile|\.gemspec|requirements\.txt|setup\.py|setup\.cfg|pyproject\.toml|poetry\.lock|uv\.lock|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum|composer\.json|composer\.lock|Pipfile)'
```

If no dependency files are in the diff, skip the scan even when
security focus is selected. The scan analyzes the entire project's
dependency tree regardless of diff scope, so it adds significant
time for zero value when dependencies weren't touched.

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
- Uses `codex exec` (not `codex review`) for headless operation
- Model: `gpt-5.3-codex`, reasoning: `xhigh`
- Uses OpenAI's published code review prompt (fine-tuned into the model)
- Diff is generated manually and piped via stdin with the prompt
- `--output-schema` produces structured JSON findings
- `-o` captures only the final message (no thinking/exec noise)
- All three scopes (uncommitted, branch, commit) support project
  context and focus instructions (no limitations)
- Falls back to `gpt-5.2-codex` on auth errors
- Output is clean JSON — parse and present findings by priority
- Set `timeout: 600000` on the Bash call

## Gemini Invocation

See [references/gemini-invocation.md](references/gemini-invocation.md)
for full details on flags, scope mapping, and extension usage.

Summary:
- Model: `gemini-3.1-pro-preview`, flags: `--yolo`, `-e`, `-m`
- For uncommitted general review: `gemini -p "/code-review" --yolo -e code-review`
- For branch/commit diffs: pipe `git diff` into `gemini -p`
- Security extension name is `gemini-cli-security` (not `security`)
- `/security:analyze` is interactive-only — use `-p` with a
  security prompt instead
- Run `/security:scan-deps` only when security focus is selected
  AND the diff touches dependency manifest files (see Diff-Aware
  Optimizations)
- Set `timeout: 600000` on the Bash call

**Scope mapping for `git diff`** (Gemini has no built-in scope flags):

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` + untracked (see codex-invocation.md) |
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

## Gemini Review (gemini-3.1-pro-preview)
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
Claude: [assembles prompt with review instructions + CLAUDE.md + security focus + diff]
Claude: [runs codex exec and gemini in parallel]
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
Claude: "Large diff (3200+ lines). Proceed, or narrow the scope?"
User: "proceed"
Claude: [runs both reviews]
```
