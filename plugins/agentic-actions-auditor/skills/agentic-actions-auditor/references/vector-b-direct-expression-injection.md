# Vector B: Direct Expression Injection

Direct `${{ github.event.* }}` expressions embedded in AI prompt fields. The YAML engine evaluates the expression at workflow runtime, embedding the attacker's raw text directly into the prompt string before the AI processes it. This pattern is visually obvious in the YAML -- the `${{ }}` expressions are right there in the prompt field -- but still commonly deployed because workflow authors assume the AI will handle untrusted input responsibly.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | Check `with.prompt` and `with.claude_args` for embedded expressions |
| Gemini CLI | Yes | Check `with.prompt` for direct expressions |
| OpenAI Codex | Yes | Check `with.prompt`, `with.prompt-file` (if resolving to attacker-controlled path), `with.codex-args` |
| GitHub AI Inference | Yes | Check `with.prompt`, `with.system-prompt`, `with.system-prompt-file` |

Check ALL `with:` fields that accept text content, not just `prompt:`. Each action has multiple fields that are injection surfaces.

## Trigger Events

Any event exposing attacker-controlled contexts: `issues` (opened, edited), `issue_comment` (created), `pull_request_target`, `discussion`, `discussion_comment`. See [foundations.md](foundations.md) for the complete list of attacker-controlled contexts.

## Data Flow

```
github.event.issue.body
  -> ${{ github.event.issue.body }} evaluated at YAML parse time
  -> raw attacker text becomes part of the prompt string literal
  -> AI processes the prompt containing attacker content
```

The expression is resolved before any step code executes. The AI action receives a prompt string that already contains the attacker's text as if the workflow author had typed it.

## What to Look For

`${{ github.event.* }}` expressions inside any text-accepting field of an AI action step:

- `with.prompt` -- the primary prompt field (all actions)
- `with.system-prompt` -- system prompt (GitHub AI Inference)
- `with.prompt-file` -- if it resolves to an attacker-controlled path (Codex, AI Inference)
- `with.claude_args` -- may embed expressions as inline instructions (Claude Code Action)
- `with.codex-args` -- may embed expressions (OpenAI Codex)

The expression must reference an attacker-controlled context. See [foundations.md](foundations.md) for the complete list.

Also check multiline `prompt: |` blocks -- expressions can appear on any line within the block scalar.

## Where to Look

The `with:` block of AI action steps. Focus on all fields listed above, not just `prompt:`. Expressions in `env:` blocks are Vector A, not Vector B.

## Why It Matters

While visually obvious, this vector remains common because developers treat AI prompts like natural language rather than code. The `${{ }}` evaluation happens at the YAML level before the AI agent runs, so the attacker's content is indistinguishable from the workflow author's intended prompt text. The AI has no way to tell which parts of its prompt are trusted instructions and which are attacker-injected content.

## Example: Vulnerable Pattern

```yaml
on:
  issues:
    types: [opened]

jobs:
  gather-labels:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@main
        with:
          allow-users: "*"
          prompt: |
            Issue title:
            ${{ github.event.issue.title }}
            Issue body:
            ${{ github.event.issue.body }}
            Analyze this issue and suggest appropriate labels.
            # Attacker content is embedded directly in the prompt at YAML eval time
```

**Data flow:** `github.event.issue.body` -> `${{ }}` evaluation -> prompt string literal -> Codex processes attacker-controlled prompt content.

## False Positives

- **Integer/enum contexts:** `${{ github.event.issue.number }}` -- integers, not attacker-controlled text. `${{ github.event.action }}` -- limited set of values (opened, edited, etc.), not free text
- **Safe contexts:** `${{ github.repository }}`, `${{ github.run_id }}`, `${{ github.actor }}` -- not attacker-controlled free text (though `github.actor` is the username, which has limited character set)
- **Expressions in env: blocks:** Those are Vector A, not Vector B. Vector B is specifically about expressions directly in prompt or other `with:` fields
- **Expressions in non-AI steps:** `${{ }}` expressions in `run:` blocks or non-AI action `with:` blocks are standard GitHub Actions script injection concerns, not specific to this skill's scope
