# Gemini CLI Invocation (Legacy — Paid Tiers Only)

> **Gemini CLI is end-of-life for individual accounts.** On 2026-06-18
> Google stopped serving Gemini CLI requests for AI Pro, Ultra, and
> free-tier individual accounts. Those accounts now fail with:
>
> ```
> reasonCode: 'UNSUPPORTED_CLIENT'
> reasonMessage: 'This client is no longer supported for Gemini Code
>   Assist for individuals. To continue using Gemini, please migrate to
>   the Antigravity suite of products: https://antigravity.google'
> ```
>
> This is the shutdown, not a broken install. Reinstalling, clearing
> `~/.gemini`, or signing in with a different personal Google account
> will not fix it.
>
> **Use [antigravity-invocation.md](antigravity-invocation.md) instead.**

## Who Can Still Use This Path

Only these keep working:

- Organizations with **Gemini Code Assist Standard or Enterprise**
  licenses
- Accounts using a **paid Gemini API key** via `GEMINI_API_KEY`
  (AI Studio / Vertex), which bypasses Code Assist tier gating
  entirely
- **Vertex AI** via `GOOGLE_GENAI_USE_VERTEXAI=true`

Check before using this path:

```bash
env | grep -q GEMINI_API_KEY && echo "api-key auth available"
```

If auth is `oauth-personal` (see `~/.gemini/settings.json`) and the
account is an individual tier, this path will fail. Go to Antigravity.

## Default Configuration

- Model: `gemini-3.1-pro-preview`
- Extensions: `code-review`, `gemini-cli-security`

## Key Flags

| Flag | Purpose |
|------|---------|
| `-p <prompt>` | Non-interactive (headless) mode; reads stdin too |
| `--yolo` / `-y` | Auto-approve all tool calls |
| `-m <model>` | Model selection |
| `-e <ext>` | Load specific extension(s) |
| `--skip-trust` | Trust the workspace for this session — **required in headless runs** |

### Trusted-folder gotcha

`--yolo` is **silently downgraded** in an untrusted directory:

```
YOLO mode is enabled. All tool calls will be automatically approved.
Approval mode overridden to "default" because the current folder is not trusted.
Gemini CLI is not running in a trusted directory. To proceed, either use
`--skip-trust`, set the `GEMINI_CLI_TRUST_WORKSPACE=true` environment
variable, or trust this directory in interactive mode.
```

Any headless invocation must add `--skip-trust` (or export
`GEMINI_CLI_TRUST_WORKSPACE=true`), or the extension-driven paths will
stall waiting for approvals that can never arrive.

## Scope-to-Diff Mapping

| Scope | Diff command |
|-------|-------------|
| Uncommitted | `git diff HEAD` (captures both staged and unstaged) |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

**Important:** For uncommitted scope, use `git diff HEAD` not bare
`git diff`. Bare `git diff` misses staged changes.

## Code Review (General, Performance, Error Handling)

For uncommitted changes, the `/code-review` extension automatically
picks up the working tree diff:

```bash
gemini -p "/code-review" \
  --yolo \
  --skip-trust \
  -e code-review \
  -m gemini-3.1-pro-preview
```

For branch diffs or specific commits, pipe the diff with a prompt
header (avoids heredocs — diffs contain `$` and backticks that break
shell expansion):

```bash
git diff <branch>...HEAD > /tmp/review-diff.txt
{ printf '%s\n\n' 'Review this diff for code quality issues. <focus prompt>'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -m gemini-3.1-pro-preview --yolo --skip-trust
```

## Security Review

`/security:analyze` is interactive-only, so use headless mode with a
security-focused prompt instead:

```bash
git diff HEAD > /tmp/review-diff.txt
{ printf '%s\n\n' 'Analyze this diff for security vulnerabilities, including injection, auth bypass, data exposure, and input validation issues. Report each finding with severity, location, and remediation.'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -e gemini-cli-security -m gemini-3.1-pro-preview --yolo --skip-trust
```

Only run the supply chain scan if the diff touches dependency manifests:

```bash
git diff --name-only <scope> \
  | grep -qiE '(package\.json|package-lock|yarn\.lock|pnpm-lock|Gemfile|\.gemspec|requirements\.txt|setup\.py|setup\.cfg|pyproject\.toml|poetry\.lock|uv\.lock|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum|composer\.json|composer\.lock|Pipfile)' \
  && gemini -p "/security:scan-deps" \
       --yolo \
       --skip-trust \
       -e gemini-cli-security \
       -m gemini-3.1-pro-preview
```

The scan analyzes the entire project's dependency tree regardless of
diff scope, so it adds significant time for no value when dependencies
were not touched.

## Adding Project Context

```bash
git diff HEAD > /tmp/review-diff.txt
{ printf 'Project conventions:\n---\n'; \
  cat CLAUDE.md; \
  printf '\n---\n\n%s\n\n' '<review instructions and focus>'; \
  cat /tmp/review-diff.txt; } \
  | gemini -p - -m gemini-3.1-pro-preview --yolo --skip-trust
```

## Error Handling

| Error | Action |
|-------|--------|
| `UNSUPPORTED_CLIENT` / "migrate to the Antigravity suite" | Individual tier is shut off. Switch to `agy` |
| `gemini: command not found` | Tell user: `npm i -g @google/gemini-cli` |
| `not running in a trusted directory` | Add `--skip-trust` |
| Extension missing | Tell user: `gemini extensions install <github-url>` |
| `-e security` silently ignored | Use `-e gemini-cli-security` (the actual installed name) |
| Timeout | Inform user, suggest scoping down the diff |

## Extension Install Commands

```bash
gemini extensions install https://github.com/gemini-cli-extensions/code-review
gemini extensions install https://github.com/gemini-cli-extensions/security
```

The security extension installs as `gemini-cli-security` (not
`security`). Always use `-e gemini-cli-security` when loading it.
