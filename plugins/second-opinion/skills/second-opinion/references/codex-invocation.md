# Codex CLI Invocation

## Default Configuration

- Model: `gpt-5.3-codex`
- Reasoning effort: `xhigh`

## Approach

Use `codex exec` in headless mode with the published code review
prompt, structured JSON output, and `-o` (`--output-last-message`)
to capture only the final review. This avoids the verbose
`[thinking]` and `[exec]` blocks that `codex review` dumps to
stdout.

## Review Prompt

Use this prompt verbatim — it is from OpenAI's [Build Code Review
with the Codex SDK](https://developers.openai.com/cookbook/examples/codex/build_code_review_with_codex_sdk)
cookbook, and GPT-5.2-codex and later received specific training
on it:

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

Create temp files for the prompt and output:

```bash
prompt_file="$(mktemp)"
output_file="$(mktemp)"
stderr_log="$(mktemp)"
```

Write the prompt file with these sections in order:

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
| Uncommitted (tracked) | `git diff HEAD` |
| Uncommitted (untracked) | `git ls-files --others --exclude-standard` — for each file, append `git diff --no-index /dev/null <file>` |
| Branch diff | `git diff <branch>...HEAD` |
| Specific commit | `git diff <sha>~1..<sha>` |

**Uncommitted scope must include untracked files.** `git diff HEAD`
alone only shows changes to tracked files. New files that haven't
been staged would be silently excluded. Generate the full diff:

```bash
{
  git diff HEAD
  git ls-files --others --exclude-standard | while IFS= read -r f; do
    git diff --no-index /dev/null "$f" 2>/dev/null || true
  done
}
```

## Base Command

```bash
codex exec \
  -c model='"gpt-5.3-codex"' \
  -c model_reasoning_effort='"xhigh"' \
  --sandbox read-only \
  --ephemeral \
  --output-schema {baseDir}/references/codex-review-schema.json \
  -o "$output_file" \
  - < "$prompt_file" \
  > /dev/null 2>"$stderr_log"
```

Then read `$output_file` with the Read tool. If empty or missing,
read `$stderr_log` to diagnose the failure.

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
        "file_path": "src/main.rs",
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

If the output file is empty or missing, read `$stderr_log` to
diagnose the failure.

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
| Empty/missing output file | Read `$stderr_log` to diagnose the failure |
