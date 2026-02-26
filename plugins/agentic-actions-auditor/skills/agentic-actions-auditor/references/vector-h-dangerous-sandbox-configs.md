# Vector H: Dangerous Sandbox Configurations

AI action sandbox or safety configurations are set to values that disable protections entirely, giving the AI agent unrestricted shell access, filesystem access, or approval-free execution. These are configuration-level weaknesses that amplify the impact of any prompt injection vector -- turning "attacker can influence AI text output" into "attacker achieves RCE on the CI runner."

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | `claude_args` with `--allowedTools Bash(*)` disables tool restrictions |
| OpenAI Codex | Yes | `sandbox: danger-full-access` and `safety-strategy: unsafe` disable protections |
| Gemini CLI | Yes | `"sandbox": false` in settings JSON and `--yolo`/`--approval-mode=yolo` disable sandbox and approval |
| GitHub AI Inference | No | Inference-only API with no sandbox/tool configuration -- no shell access to restrict |

## Trigger Events

Any event -- this vector is about the action's configuration, not the trigger. The trigger determines whether attacker input reaches the AI; this vector determines the blast radius if prompt injection succeeds.

## Data Flow

No direct data flow -- this is a configuration weakness. The danger:

```
ANY prompt injection vector (A-F) succeeds
  + sandbox/safety protections disabled (this vector)
  = unrestricted code execution on the runner
```

Without dangerous configs, a successful prompt injection may still be contained by tool restrictions and sandbox boundaries. With dangerous configs, the AI agent has full access to shell, filesystem, environment variables, and network.

## What to Look For

**Claude Code Action (`anthropics/claude-code-action`):**

- `with.claude_args` containing `--allowedTools Bash(*)` or `--allowedTools "Bash(*)"` -- unrestricted shell access, the AI can execute any command
- `with.claude_args` with broad tool patterns combining multiple unrestricted categories (e.g., `Bash(npm:*) Bash(git:*) Bash(curl:*)`)
- `with.settings` pointing to a settings file -- flag for manual review, the file may override tool permissions in ways not visible in the workflow YAML

**OpenAI Codex (`openai/codex-action`):**

- `with.sandbox: danger-full-access` -- disables all filesystem restrictions, the AI can read/write anywhere on the runner
- `with.safety-strategy: unsafe` -- disables safety enforcement for all operations
- Both together represent maximum exposure: unrestricted filesystem + no safety checks

**Gemini CLI (`google-github-actions/run-gemini-cli`, `google-gemini/gemini-cli-action`):**

- `with.settings` JSON containing `"sandbox": false` -- disables the sandbox entirely
- CLI args containing `--yolo` or `--approval-mode=yolo` -- disables approval prompts for all tool calls, meaning the AI executes commands without confirmation
- `with.settings` JSON with broad `coreTools` lists including `run_shell_command` without restrictions (related to Vector F for specific tool analysis)

## Where to Look

The `with:` block of AI action steps:

- **Claude:** Parse `with.claude_args` string for `--allowedTools` patterns. Also check `with.settings` for external config file path
- **Codex:** Check `with.sandbox` and `with.safety-strategy` field values directly
- **Gemini:** Parse `with.settings` JSON string for `"sandbox": false` and approval mode settings. Check any args-style fields for `--yolo` or `--approval-mode=yolo`

## Why It Matters

Dangerous sandbox configs turn prompt injection from a text-influence attack into full remote code execution. Without sandbox restrictions, the AI agent can:

- Execute arbitrary shell commands on the runner
- Read/write all files on the runner filesystem
- Access environment variables including `GITHUB_TOKEN` and repository secrets
- Make outbound network requests (data exfiltration)
- Modify repository contents, create releases, or push code

## Example: Vulnerable Pattern

Three actions with dangerous configurations (from research Example 8):

```yaml
# Claude Code Action -- unrestricted shell
- uses: anthropics/claude-code-action@v1
  with:
    claude_args: "--allowedTools Bash(*)"
    prompt: "Review this issue and fix the code"

# OpenAI Codex -- unrestricted filesystem + no safety
- uses: openai/codex-action@v1
  with:
    sandbox: danger-full-access
    safety-strategy: unsafe
    prompt: "Fix the bug described in this issue"

# Gemini CLI -- sandbox disabled
- uses: google-github-actions/run-gemini-cli@v1
  with:
    settings: |
      {"sandbox": false}
    prompt: "Analyze and fix this issue"
```

## False Positives

- **Specific restricted tool patterns** in Claude: `--allowedTools "Bash(npm test:*)"` or `--allowedTools "Bash(echo:*)"` -- these are restrictive, not dangerous (though they may be exploitable via Vector F for subshell expansion)
- **Codex workspace-scoped sandbox:** `sandbox: workspace-write` allows writes but within a workspace boundary, not full system access
- **Gemini specific tool lists:** `coreTools` containing specific tools but NOT `run_shell_command` -- tool-specific restrictions, not full sandbox disable
- **Default configurations:** Actions without explicit sandbox/safety config fields -- defaults are generally safe (Claude defaults to restricted tools, Codex defaults to `sandbox: workspace-write`, Gemini defaults to sandbox enabled)
- **Claude `--allowedTools` with narrow patterns:** e.g., `--allowedTools "Read(*) Grep(*)"` -- read-only tools pose minimal risk

See [foundations.md](foundations.md) for AI action field mappings.
