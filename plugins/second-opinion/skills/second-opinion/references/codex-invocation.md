# Codex CLI Invocation

## Default Configuration

- Model: `gpt-5.3-codex`
- Reasoning effort: `high`

## Approach

Use `codex exec` in headless mode with the published code review
prompt, structured JSON output, and `--output-last-message` to
capture only the final review. This avoids the verbose `[thinking]`
and `[exec]` blocks that `codex review` dumps to stdout.

## Review Prompt

Use this prompt verbatim — GPT-5.2-codex and later received specific
training on it:

```
You are acting as a reviewer for a proposed code change made by another engineer.
Focus on issues that impact correctness, performance, security, maintainability, or developer experience.
Flag only actionable issues introduced by the pull request.
When you flag an issue, provide a short, direct explanation and cite the affected file and line range.
Prioritize severe issues and avoid nit-level comments unless they block understanding of the diff.
After listing findings, produce an overall correctness verdict ("patch is correct" or "patch is incorrect") with a concise justification and a confidence score between 0 and 1.
Ensure that file citations and line numbers are exactly correct using the tools available; if they are incorrect your comments will be rejected.
```

## Prompt Assembly

Write a temp file (`/tmp/codex-review-prompt.md`) with these
sections in order:

```
<review prompt from above>

<If project context was requested>
Project conventions and standards:
---
<full contents of CLAUDE.md or AGENTS.md>
---

<If focus area was selected or custom text provided>
Focus: <focus area instructions>

Diff to review:
---
<git diff output for the selected scope>
---
```

### Generating the diff

| Scope | Command |
|-------|---------|
| Uncommitted | `git diff HEAD` |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

## Base Command

```bash
codex exec \
  -c model='"gpt-5.3-codex"' \
  -c model_reasoning_effort='"high"' \
  --sandbox read-only \
  --ephemeral \
  --output-schema {baseDir}/references/codex-review-schema.json \
  -o /tmp/codex-review-output.json \
  - < /tmp/codex-review-prompt.md \
  > /dev/null 2>&1
```

Then read `/tmp/codex-review-output.json` with the Read tool.

## Output Format

The output is structured JSON matching `codex-review-schema.json`:

```json
{
  "findings": [
    {
      "title": "Short description (max 80 chars)",
      "body": "Detailed explanation",
      "confidence_score": 0.95,
      "priority": 1,
      "code_location": {
        "absolute_file_path": "src/main.rs",
        "line_range": { "start": 42, "end": 48 }
      }
    }
  ],
  "overall_correctness": "patch is correct",
  "overall_explanation": "Summary of the review",
  "overall_confidence_score": 0.9
}
```

Priority levels: 0 = informational, 1 = low, 2 = medium, 3 = high.

### Presenting Results

Parse the JSON and present findings grouped by priority (highest
first). For each finding, show:

- **Title** with file:line reference
- **Body** explanation
- **Confidence** as a percentage

End with the overall verdict and confidence.

If the JSON file is empty or missing, fall back to reading stdout
from the command (remove `> /dev/null 2>&1` on retry).

## Model Fallback

If `gpt-5.3-codex` fails with an auth error (e.g., "not supported
when using Codex with a ChatGPT account"), retry with
`gpt-5.2-codex`. Log the fallback for the user.

## Error Handling

| Error | Action |
|-------|--------|
| `codex: command not found` | Tell user: `npm i -g @openai/codex` |
| Model auth error | Retry with `gpt-5.2-codex` |
| Timeout | Suggest narrowing the diff scope |
| `EPERM` / sandbox errors | Expected — `codex exec` runs sandboxed. Ignore these. |
| Empty/missing output file | Re-run without `> /dev/null 2>&1` and read stdout |
