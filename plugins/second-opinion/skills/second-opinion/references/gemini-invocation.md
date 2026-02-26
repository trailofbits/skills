# Gemini CLI Invocation

## Default Configuration

- Model: `gemini-3.1-pro-preview`
- Extensions: `code-review`, `gemini-cli-security`

## Key Flags

| Flag | Purpose |
|------|---------|
| `-p <prompt>` | Non-interactive (headless) mode |
| `--yolo` / `-y` | Auto-approve all tool calls |
| `-m <model>` | Model selection |
| `-e <ext>` | Load specific extension(s) |

## Scope-to-Diff Mapping

Gemini does not have built-in scope flags like Codex. Map the
user's scope choice to the correct `git diff` command:

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` (captures both staged and unstaged) |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

**Important:** For uncommitted scope, use `git diff HEAD` not
bare `git diff`. Bare `git diff` misses staged changes.

## Code Review (General, Performance, Error Handling)

For uncommitted changes, the `/code-review` extension
automatically picks up the working tree diff:

```bash
gemini -p "/code-review" \
  --yolo \
  -e code-review \
  -m gemini-3.1-pro-preview
```

For branch diffs or specific commits, pipe the diff with a
prompt header (avoids heredocs — diffs contain `$` and backticks
that break shell expansion):

```bash
git diff <branch>...HEAD > /tmp/review-diff.txt
{ printf '%s\n\n' 'Review this diff for code quality issues. <focus prompt>'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -m gemini-3.1-pro-preview --yolo
```

## Security Review

The `/security:analyze` extension is interactive-only, so use
headless mode with a security-focused prompt instead:

```bash
git diff HEAD > /tmp/review-diff.txt
{ printf '%s\n\n' 'Analyze this diff for security vulnerabilities, including injection, auth bypass, data exposure, and input validation issues. Report each finding with severity, location, and remediation.'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -e gemini-cli-security -m gemini-3.1-pro-preview --yolo
```

When security focus is selected, only run the supply chain scan
if the diff touches dependency manifest files:

```bash
# Check whether dependency files changed before scanning
git diff --name-only <scope> \
  | grep -qiE '(package\.json|package-lock|yarn\.lock|pnpm-lock|Gemfile|\.gemspec|requirements\.txt|setup\.py|setup\.cfg|pyproject\.toml|poetry\.lock|uv\.lock|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum|composer\.json|composer\.lock|Pipfile)' \
  && gemini -p "/security:scan-deps" \
       --yolo \
       -e gemini-cli-security \
       -m gemini-3.1-pro-preview
```

Skip the scan when only non-dependency files changed. The scan
analyzes the entire project's dependency tree regardless of diff
scope, so it adds significant time for no value when dependencies
weren't touched.

## Adding Project Context

If project context was requested, prepend it to the prompt:

```bash
git diff HEAD > /tmp/review-diff.txt
{ printf 'Project conventions:\n---\n'; \
  cat CLAUDE.md; \
  printf '\n---\n\n%s\n\n' '<review instructions and focus>'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -m gemini-3.1-pro-preview --yolo
```

## Error Handling

| Error | Action |
|-------|--------|
| `gemini: command not found` | Tell user: `npm i -g @google/gemini-cli` |
| Extension missing | Tell user: `gemini extensions install <github-url>` |
| `-e security` silently ignored | Use `-e gemini-cli-security` (the actual installed name) |
| Timeout | Inform user, suggest scoping down the diff |

## Extension Install Commands

```bash
gemini extensions install https://github.com/gemini-cli-extensions/code-review
gemini extensions install https://github.com/gemini-cli-extensions/security
```

Note: The security extension installs as `gemini-cli-security`
(not `security`). Always use `-e gemini-cli-security` when
loading it.
