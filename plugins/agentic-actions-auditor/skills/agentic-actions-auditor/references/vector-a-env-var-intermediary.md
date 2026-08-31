# Vector A: Env Var Intermediary

Attacker data flows from GitHub event context into `env:` blocks, and the AI prompt references those env var names -- the AI agent reads the attacker content from environment variables at runtime. The prompt field contains zero `${{ }}` expressions, making this pattern invisible to tools that only scan for direct expression injection.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | Prompt instructs AI to read env vars via `echo "$VAR"` |
| Gemini CLI | Yes | Shell-style `"${VAR}"` interpolation in prompt text |
| OpenAI Codex | Yes | Similar env var reference pattern in prompt instructions |
| GitHub AI Inference | Yes | Prompt text can reference env var names for the runner to resolve |

## Trigger Events

Any event where attacker-controlled body, title, or comment fields are exposed: `issues` (opened, edited), `issue_comment` (created), `pull_request_target`, `discussion`, `discussion_comment`. See [foundations.md](foundations.md) for the complete list of attacker-controlled contexts.

## Data Flow

```
github.event.issue.body
  -> env: ISSUE_BODY: ${{ github.event.issue.body }}   (evaluated BEFORE step runs)
  -> prompt instruction references "ISSUE_BODY"
  -> AI agent reads env var at runtime
  -> attacker content in AI context
```

The `${{ }}` expression is in the `env:` block, not the prompt. By the time the step executes, the env var contains the raw attacker text. The AI agent reads it as a normal environment variable.

## What to Look For

This is a TWO-PART match. Both conditions must be true:

1. **Part A -- Env var with attacker-controlled value:** Find `env:` keys (at workflow, job, or step scope) whose values contain `${{ github.event.* }}` expressions referencing attacker-controlled contexts (see [foundations.md](foundations.md) for the complete list)
2. **Part B -- Prompt references that env var name:** Check if the AI action step's `with.prompt` (or `with.prompt-file`) references those env var names -- by exact name string, `"${VAR}"` shell expansion, `echo "$VAR"` instruction, or text mentioning the variable name

Both parts must be present. An env var with attacker content that is never referenced in the prompt is not this vector. A prompt referencing env vars that contain only safe values is not this vector.

## Where to Look

- `env:` blocks at all three scopes: workflow-level (top of file), job-level (under `jobs.<id>:`), and step-level (on the AI action step itself)
- The `with.prompt` field of the AI action step
- Prior steps in the same job that set env vars via `echo "NAME=value" >> $GITHUB_ENV`

## Why It Matters

This pattern is invisible to naive grep-based tools that only scan for `${{ }}` in prompt fields. GitHub's own security documentation recommends using env vars as an intermediary to prevent script injection in `run:` blocks -- but this recommendation does not account for AI agents that read env vars by name. An attacker's issue body, PR description, or comment text flows into the AI prompt without any visible expression injection.

## Example: Vulnerable Pattern

```yaml
on:
  issues:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        env:
          ISSUE_TITLE: '${{ github.event.issue.title }}'   # attacker-controlled
          ISSUE_BODY: '${{ github.event.issue.body }}'      # attacker-controlled
        with:
          prompt: |
            Review the issue title and body provided in the environment
            variables: "${ISSUE_TITLE}" and "${ISSUE_BODY}".
            # No ${{ }} here -- but attacker data still reaches the AI
```

**Data flow:** `github.event.issue.body` -> `env: ISSUE_BODY` -> prompt instruction `"${ISSUE_BODY}"` -> Gemini reads env var -> attacker content in AI context.

## False Positives

- **Safe context values:** Env vars containing non-attacker-controlled values like `${{ github.repository }}`, `${{ github.run_id }}`, or `${{ secrets.* }}` -- these are NOT attacker-controlled
- **Unreferenced env vars:** Env vars with attacker-controlled values that are NOT referenced in any AI prompt (e.g., used only in non-AI steps like shell scripts or build tools)
- **Explicit untrusted handling:** Env vars where the prompt explicitly treats the content as untrusted with effective input validation (rare in practice -- most workflows pass the content directly)
