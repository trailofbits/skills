# Gemini CLI Invocation

Retain this path for an explicit Gemini CLI request or an account using
Gemini Code Assist Standard/Enterprise, a paid Gemini API key, or Vertex
AI. Use the account's configured authentication; do not print credentials.

If the service returns `UNSUPPORTED_CLIENT` and directs the user to
Antigravity, report that this account no longer supports Gemini CLI.
Reinstallation does not resolve that response. Ask before changing the
requested CLI.

## Command

The default remains `gemini-3.1-pro-preview`. Preserve an explicit model.
With the shared prompt already written to `prompt_file`:

```bash
gemini \
  --model gemini-3.1-pro-preview \
  --approval-mode default \
  --output-format text \
  --prompt "Review the supplied changes and return the findings." \
  < "$prompt_file" > "$output_file" 2> "$stderr_log"
```

The prompt flag selects headless mode and stdin supplies the captured
patch, focus, and project context. These flags were checked against
Gemini CLI 0.53.0 on 2026-09-14. See the
[headless mode reference](https://geminicli.com/docs/cli/headless/).

A plain prompt supports general, security, performance, and error-handling
reviews without installing extensions. The shared diff preparation
includes untracked files and supports branch and commit scopes.

## Permissions and results

Keep `--approval-mode default`. Do not use `--yolo` or automatically
trust a directory to get past an unattended approval failure. If the
workspace requires trust, explain the error so the user can establish
trust through their normal setup.

Existing user-installed extensions may still load according to the
CLI's configuration. This invocation does not install extensions, run
dependency scans, or change that configuration.

Read the prose response and diagnostics. Report a failed invocation,
empty output, or denied inspection as an incomplete review. Do not
reinterpret those outcomes as an absence of findings.

| Failure | Response |
|---------|----------|
| Executable missing | Report the installation command: `npm i -g @google/gemini-cli` |
| `UNSUPPORTED_CLIENT` | Explain the account migration and offer Antigravity |
| Workspace trust or tool approval required | Report the blocked operation without enabling automatic approvals |
| Auth, quota, model, or timeout error | Report the error and retain any partial findings |
