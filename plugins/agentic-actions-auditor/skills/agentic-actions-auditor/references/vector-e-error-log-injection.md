# Vector E: Error Log Injection

CI error output, build logs, or test failure messages are fed to an AI agent as context. An attacker crafts code that produces prompt injection payloads in compiler errors, test failure output, or log messages. When these logs are passed to the AI prompt, the AI processes attacker-controlled error messages as trusted instructions.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | Confirmed -- PoC 23. Receives CI logs via workflow inputs or step outputs. |
| Gemini CLI | Yes | Applicable if workflow passes build output to prompt. |
| OpenAI Codex | Yes | Applicable if workflow passes error logs to prompt. |
| GitHub AI Inference | Yes | Applicable if captured CI output is included in the prompt. |

Any AI action that receives CI output in its prompt is vulnerable. The attacker does not need direct access to the prompt field -- they control what the CI system outputs by crafting code that produces specific error messages.

## Trigger Events

- `workflow_run` -- triggered after another workflow completes; commonly used for "auto-fix CI failures" bots
- `workflow_dispatch` -- with inputs that carry CI/build output (e.g., `error_logs` input)
- `check_suite` -- triggered on check completion, may carry check results
- Any workflow that captures step outputs or artifacts from build/test steps and passes them to an AI prompt

See [foundations.md](foundations.md) for the full trigger events table and attacker-controlled context list.

## Data Flow

```
Attacker's PR code
  -> CI build/test step fails
  -> Error output contains injection payloads
     (crafted compiler errors, test failure messages with embedded instructions)
  -> Logs passed to AI prompt via:
     - ${{ github.event.inputs.error_logs }}
     - ${{ steps.build.outputs.stderr }}
     - Artifact content downloaded in a later step
  -> AI processes attacker-controlled error messages as context
```

## What to Look For

1. **AI prompt containing `${{ github.event.inputs.* }}`** where inputs carry CI/build output -- especially inputs named `error_logs`, `build_output`, `test_results`, `failure_log`, or similar
2. **AI prompt referencing step outputs** (`${{ steps.*.outputs.* }}`) from build, test, or lint steps -- particularly `stderr`, `stdout`, `output`, or `log` outputs
3. **Prompt instructions telling the AI to fix failures** -- phrases like "fix CI failures", "analyze build errors", "debug test output", "resolve the following errors"
4. **`workflow_run` trigger combined with AI action step** -- common pattern for auto-fix bots that respond to CI failures
5. **Steps that capture stdout/stderr** and pass content to subsequent AI steps -- look for `run:` steps that redirect output to files or environment variables, followed by AI steps that read those values

## Where to Look

1. The `on:` block for `workflow_run` or `workflow_dispatch` triggers
2. `workflow_dispatch` `inputs:` definitions -- check if any input is described as carrying logs or error output
3. The `with.prompt` field for references to step outputs (`${{ steps.*.outputs.* }}`) or workflow inputs (`${{ github.event.inputs.* }}`)
4. Prior steps in the same job that capture build output (e.g., `run: |` blocks that set outputs or write to files)
5. Steps that download artifacts from prior workflow runs and feed content to AI prompts

## Why It Matters

The attacker controls what the CI system outputs by carefully crafting their code. A test file can produce test failure messages containing prompt injection. A source file can trigger specific compiler errors with injection payloads embedded in string literals or identifiers. The AI sees this as "CI output to fix" but the error messages contain the attacker's instructions. Because the logs appear to be legitimate CI output, they bypass any prompt framing that instructs the AI to treat user input as untrusted.

## Example: Vulnerable Pattern

From PoC 23 (Significant-Gravitas/AutoGPT):

```yaml
on:
  workflow_dispatch:
    inputs:
      error_logs:
        type: string                                # CI logs passed as workflow input

jobs:
  auto-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: |
            Error logs:
            ${{ github.event.inputs.error_logs }}   # Attacker-controlled CI output
            Analyze the CI failure logs above and attempt to fix the issues.
```

## False Positives

- **CI output from trusted sources only** -- main branch builds failing due to infrastructure issues (not attacker code) are not exploitable if no external PR code contributed to the output
- **Step outputs containing only structured data** -- exit codes, boolean flags, numeric values, or fixed-format status strings (not free-text error messages) cannot carry meaningful injection payloads
- **Workflows that only summarize CI status** -- reporting "passed" or "failed" without including actual log content does not expose error message content to the AI
- **Build logs that are displayed but not passed to AI prompts** -- if the workflow only posts logs as PR comments without feeding them to an AI action, Vector E does not apply (though the logs may still contain injection if another AI processes the comment via Vector B)
