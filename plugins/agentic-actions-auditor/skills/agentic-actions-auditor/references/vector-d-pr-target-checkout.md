# Vector D: pull_request_target + PR Head Checkout

An attacker opens a fork pull request against a repository that uses `pull_request_target` to trigger an AI agent workflow. Because `pull_request_target` runs the workflow definition from the **base branch** (not the fork), the workflow has access to repository secrets. If the workflow then checks out the PR head commit, the AI agent reads attacker-modified files from disk while running with those secrets. This combines trusted execution context with untrusted code.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | Confirmed -- PoC 18. Reads files from checked-out working directory. |
| Gemini CLI | Yes | Applicable if used with `pull_request_target`. Same filesystem read behavior. |
| OpenAI Codex | Yes | Applicable. Reads files from working directory for code analysis. |
| GitHub AI Inference | Possible | Less common, but applicable if the prompt instructs the model to read file contents from disk. |

The key requirement is any AI action that reads files from the checked-out working directory. The attacker embeds prompt injection payloads in code comments, README files, configuration files, or any file the AI is likely to read during review.

## Trigger Events

`pull_request_target` specifically. This trigger runs the workflow from the base branch (with repository secrets) but is activated by external pull requests.

Regular `pull_request` from forks does NOT have this issue because fork PRs do not receive repository secrets. The `pull_request` trigger is safe from a secrets-exfiltration perspective (though code execution may still be a concern in other contexts).

See [foundations.md](foundations.md) for the full trigger events table.

## Data Flow

```
Attacker opens fork PR
  -> pull_request_target runs workflow from base branch (has secrets)
  -> actions/checkout with ref: PR head fetches attacker's code to disk
  -> AI agent reads files from working directory
  -> Attacker-modified code processed with access to repository secrets
```

## What to Look For

**TWO-STEP detection -- BOTH conditions must be true:**

1. **FIRST:** Check the `on:` block for `pull_request_target` trigger
2. **SECOND:** Look for a checkout step that fetches the PR head:
   - `actions/checkout` (any version) with `ref:` set to one of:
     - `${{ github.event.pull_request.head.sha }}`
     - `${{ github.event.pull_request.head.ref }}`
     - `${{ github.head_ref }}`
   - `git checkout` or `git fetch` commands in `run:` steps that fetch the PR head branch or commit

**`pull_request_target` alone is NOT a finding.** Without a checkout of the PR head, the AI agent only sees base branch code, which is trusted. The checkout is what makes the code attacker-controlled.

## Where to Look

1. The `on:` block at the top of the workflow file for `pull_request_target`
2. All `steps:` in all jobs for `actions/checkout` steps with a `ref:` or `with.ref` field
3. `run:` steps containing `git checkout`, `git fetch`, or `git switch` commands that reference the PR head
4. Note: `actions/checkout` WITHOUT a `ref:` field defaults to the base branch (safe under `pull_request_target`)

## Why It Matters

The AI agent runs with base branch secrets -- potentially including `GITHUB_TOKEN` with write permissions, deployment keys, API credentials, and any secrets configured in the repository. But it processes attacker-modified files. The attacker can embed prompt injection payloads in any file the AI is likely to read: code comments, README files, configuration files, test files, or documentation. If the injection succeeds, the AI executes attacker instructions with access to those secrets.

## Example: Vulnerable Pattern

From PoC 18 (frankbria/ralph-claude-code):

```yaml
on:
  pull_request_target:                              # Step 1: Runs in base branch context
    types: [opened, synchronize]

jobs:
  claude-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Step 2: Checks out ATTACKER's code
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: |
            Please review this pull request and provide feedback
            # AI reads attacker-modified files from disk with base repo secrets available
```

## False Positives

- **`pull_request_target` WITHOUT any checkout of the PR head** -- the AI only sees base branch code, which is trusted. This is the most common false positive.
- **`pull_request_target` with `actions/checkout` but NO `ref:` field** -- defaults to the base branch, which is safe.
- **Regular `pull_request` trigger with checkout of PR head** -- fork PRs do not receive secrets, so secret exfiltration is not possible (though code execution in the runner is still a separate concern).
- **`pull_request_target` used only for labeling, commenting, or status checks** without running an AI agent on the code -- no AI processing means no prompt injection surface.
- **`pull_request_target` with `ref:` pointing to the base branch explicitly** (e.g., `ref: ${{ github.event.pull_request.base.sha }}`) -- this checks out trusted code.
