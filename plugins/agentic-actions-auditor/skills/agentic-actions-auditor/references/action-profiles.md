# Action Security Profiles

Security-relevant configuration fields, default behaviors, dangerous configuration patterns, and remediation guidance for each supported AI action. Referenced by SKILL.md Step 5 for action-specific remediation.

## Claude Code Action

### Default Security Posture

- Bash tool disabled by default; commands must be explicitly allowed via `--allowedTools` in `claude_args`
- Only users with repository write access can trigger (default when `allowed_non_write_users` is omitted)
- GitHub Apps and bots blocked by default (when `allowed_bots` is omitted)
- Commits to new branch, does NOT auto-create PRs (requires human review)
- Built-in prompt sanitization strips HTML comments, invisible characters, markdown image alt text, hidden HTML attributes, HTML entities
- `show_full_output: false` by default (prevents secret leakage in workflow logs)

### Dangerous Configurations

| Configuration | Risk |
|--------------|------|
| `claude_args: "--allowedTools Bash(*)"` | Unrestricted shell access; any prompt injection achieves full RCE |
| `allowed_non_write_users: "*"` | Any GitHub user can trigger the action, including external contributors and attackers |
| `allowed_bots: "*"` | Any bot can trigger, enables automated attack chains via bot-to-bot escalation |
| `show_full_output: true` (in public repos) | Exposes full conversation including potential secrets in workflow logs |
| `prompt` containing `${{ github.event.* }}` | Direct expression injection of attacker-controlled content into AI prompt |

### Remediation Patterns

**Restrict shell access:** Replace `Bash(*)` with specific tool patterns:

```yaml
claude_args: '--allowedTools "Bash(npm test:*) Bash(git diff:*)"'
```

**Restrict user access:** Remove wildcard allowlists or replace with explicit user lists:

```yaml
allowed_non_write_users: "trusted-user1,trusted-user2"
```

**Restrict bot access:** Remove `allowed_bots: "*"` or list specific trusted bots:

```yaml
allowed_bots: "dependabot[bot],renovate[bot]"
```

**Prevent prompt injection:** Never pass attacker-controlled event data (issue body, PR title, comment body) to the `prompt` field via env vars or direct `${{ }}` expressions. Validate and sanitize input in a prior step.

**Protect log output:** Keep `show_full_output: false` (default) in public repositories.

## OpenAI Codex

### Default Security Posture

- Sandbox defaults to `workspace-write` (read/edit in workspace, run commands locally, no network)
- Safety strategy defaults to `drop-sudo` (removes sudo privileges before running Codex)
- Empty `allow-users` permits only write-access repository members (default)
- `allow-bots: false` by default
- Network off by default (must be explicitly enabled)
- Protected paths: `.git`, `.agents/`, `.codex/` directories are read-only even in writable sandbox

### Dangerous Configurations

| Configuration | Risk |
|--------------|------|
| `sandbox: danger-full-access` | No sandbox, no approvals, unrestricted filesystem and network access |
| `safety-strategy: unsafe` | Disables all safety enforcement including sudo restrictions |
| `allow-users: "*"` | Any GitHub user can trigger the action |
| `allow-bots: true` | Any bot can trigger, enables automated attack chains |
| `danger-full-access` + `unsafe` combined | Maximum exposure: no sandbox, no safety, full system access |

### Remediation Patterns

**Restrict sandbox:** Use the default or a more restrictive mode:

```yaml
sandbox: workspace-write    # default: workspace access only, no network
sandbox: read-only          # for analysis-only tasks
```

**Restrict safety strategy:** Use the default or a stricter option:

```yaml
safety-strategy: drop-sudo          # default: removes sudo privileges
safety-strategy: unprivileged-user  # stronger: runs as unprivileged user
```

**Restrict user access:** Remove wildcard or replace with explicit user list:

```yaml
allow-users: "maintainer1,maintainer2"
```

**Restrict bot access:** Keep `allow-bots: false` (default) unless specific trusted bots need access.

**Organization-level enforcement:** Use `requirements.toml` to block `danger-full-access` at the organization level, preventing individual repos from weakening sandbox policy.

## Gemini CLI

### Default Security Posture

- Sandbox off by default for the GitHub Action (no `--sandbox` flag set)
- When sandbox is enabled, default profile is `permissive-open` (restricts writes outside project directory)
- Default approval mode requires confirmation for tool calls
- When `--yolo` is used, sandbox is enabled automatically (safety measure)
- Tool restriction via `tools.core` allowlist in settings JSON (e.g., `["run_shell_command(echo)"]`)
- No built-in user allowlist field -- access controlled by workflow trigger permissions only

### Dangerous Configurations

| Configuration | Risk |
|--------------|------|
| `settings: '{"sandbox": false}'` | Explicitly disables sandbox (note: JSON inside YAML string) |
| `--yolo` or `--approval-mode=yolo` in CLI args | Disables approval prompts for all tool calls |
| `tools.core` containing `run_shell_command(echo)` | Enables subshell expansion bypass -- confirmed RCE vector (Vector F) |
| `tools.allowed: ["*"]` | Bypasses confirmation for all tools |

### Remediation Patterns

**Enable sandbox:** Add sandbox configuration to the settings JSON:

```yaml
settings: '{"sandbox": true}'
```

Or pass the `--sandbox` flag in CLI arguments.

**Remove dangerous approval modes:** Remove `--yolo` and `--approval-mode=yolo` from CLI args. Use the default approval mode that requires confirmation for tool calls.

**Restrict tool lists:** Remove `run_shell_command(echo)` and other expandable commands from `tools.core`. Use specific non-shell tools only:

```json
{
  "tools": {
    "core": ["read_file", "write_file", "list_directory"]
  }
}
```

**Container-based sandboxing:** If shell access is required, use container-based sandboxing to limit blast radius rather than relying on the built-in sandbox profile alone.

## GitHub AI Inference

### Default Security Posture

- Inference-only API call -- no shell access, no filesystem access, no sandbox to configure
- Access controlled by GitHub token scope
- Primary risks: prompt injection via untrusted event data (Vector B), and AI output flowing to `eval` in subsequent workflow steps (Vector G)

### Dangerous Configurations

| Configuration | Risk |
|--------------|------|
| `prompt` containing `${{ github.event.* }}` | Attacker-controlled event contexts injected directly into AI prompt (Vector B) |
| Overly scoped `token` parameter | Grants more permissions than needed, expanding blast radius of any exploitation |
| AI output consumed by `eval`/`exec` in subsequent steps | Converts inference-only action into code execution vector (Vector G) |

### Remediation Patterns

**Sanitize prompt inputs:** Validate and sanitize event data before including in prompts. Do not pass raw `${{ github.event.issue.body }}` or similar attacker-controlled fields.

**Minimize token scope:** Use minimum-scope tokens following the principle of least privilege. Only grant permissions the inference call actually needs.

**Protect AI output consumption:** Never pass AI output through `eval`, `exec`, or unquoted `$()` in subsequent workflow steps:

```yaml
# DANGEROUS: AI output executed as code
- run: eval "${{ steps.inference.outputs.result }}"

# SAFE: AI output stored and validated before use
- run: |
    RESULT='${{ steps.inference.outputs.result }}'
    echo "$RESULT"  # display only, no execution
```

**Validate structured output:** If structured output (JSON) is needed from the AI, validate against a schema before using in shell commands.

## Per-Action Remediation Quick Reference

| Remediation Need | Claude Code Action | OpenAI Codex | Gemini CLI | GitHub AI Inference |
|-----------------|-------------------|--------------|------------|-------------------|
| Restrict shell access | `--allowedTools "Bash(specific:*)"` | `sandbox: workspace-write` | Remove expandable commands from `tools.core` | N/A (no shell) |
| Restrict user access | `allowed_non_write_users: "user1,user2"` | `allow-users: "user1,user2"` | Control via workflow trigger permissions | Control via token scope |
| Disable dangerous mode | Remove `Bash(*)` from `claude_args` | Remove `danger-full-access` from `sandbox` | Remove `--yolo` from CLI args | N/A |
| Sandbox enforcement | N/A (tool-level restriction) | `sandbox: read-only` | `"sandbox": true` in settings JSON | N/A (no execution) |
| Block bot triggers | Remove `allowed_bots: "*"` | Set `allow-bots: false` | Control via workflow trigger conditions | Control via token scope |
| Protect output/logs | Keep `show_full_output: false` | N/A | N/A | Never `eval` AI output |
