# Vector I: Wildcard User Allowlists

Nothing restricts which GitHub users can trigger the AI agent, so any user -- including external contributors, anonymous users, and potential attackers -- can reach it via issues or comments. This removes the last line of defense that user-based gating would otherwise provide.

That happens two ways, and the second is easy to miss because there is no wildcard to grep for:

1. **A user allowlist field set to `"*"`** -- `allowed_non_write_users`, `allow-users`, `allowed_bots`. The classic form, on the two actions that have such a field.
2. **No allowlist field at all, and no `if:` condition either.** Gemini CLI, GitHub AI Inference, `claude-code-base-action` and every CLI agent invoked from a `run:` block expose no allowlist input, so the step or job `if:` is the entire gate. Absent, on an externally triggerable event, the step is as open as an explicit `"*"` -- the difference is only that one is written down.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | `allowed_non_write_users: "*"` and `allowed_bots: "*"` confirmed in many PoCs |
| OpenAI Codex | Yes | `allow-users: "*"` and `allow-bots: "*"` confirmed in PoCs |
| Gemini CLI | Yes, via `if:` | No allowlist field, so the step or job `if:` is the whole gate |
| GitHub AI Inference | Yes, via `if:` | No allowlist field, so the step or job `if:` is the whole gate |
| Claude Code Action (base) | Yes, via `if:` | `claude-code-base-action` exposes no allowlist input |
| CLI-invoked (`run:`) | Yes, via `if:` | No allowlist input exists for a CLI agent |

Every row is in scope. The column says which gate to read, not whether to check the vector: where no
allowlist input exists, an absent `if:` on an externally triggerable event is itself the finding.

## Trigger Events

Most relevant with events that external users can trigger:

- `issues` (opened, edited) -- any GitHub user can open an issue on public repos
- `issue_comment` (created) -- any GitHub user can comment on public issues
- `pull_request_target` -- external users can open PRs from forks

Wildcard allowlists on `push`-triggered workflows are less concerning because `push` requires write access to the repository.

## Data Flow

No direct data flow -- this is an access control weakness.

```
any GitHub user (no repo access required)
  -> opens issue or comments (triggers workflow)
  -> wildcard allowlist permits the interaction
  -> AI agent processes attacker-controlled content
```

The wildcard removes the user-based gate that would otherwise restrict which users can trigger the AI agent response.

## What to Look For

**Claude Code Action (`anthropics/claude-code-action`):**

- `with.allowed_non_write_users: "*"` -- allows any user, even those without repository write access, to trigger the AI agent
- `with.allowed_bots: "*"` -- allows any bot account to trigger the action

**OpenAI Codex (`openai/codex-action`):**

- `with.allow-users: "*"` -- allows any user to trigger the AI agent
- `with.allow-bots: "*"` -- allows any bot account to trigger the action

**General pattern:** Any `with:` field containing a user or bot allowlist with value `"*"` or that resolves to unrestricted access -- **or** a step with no allowlist input available to it and no step- or job-level `if:`, on a trigger an external user can fire. Both leave the agent reachable by anyone; only the first leaves a wildcard to grep for.

## Where to Look

The `with:` block of AI action steps. Check for the exact field names listed above with string values of `"*"`.

For the rows with no allowlist input -- Gemini CLI, AI Inference, `claude-code-base-action`, and any CLI agent from a `run:` block -- read the step's `if:` and the job's `if:` instead. That condition is the whole gate, so no `if:` on an externally triggerable event is the finding.

## Why It Matters

Without user-based gating, any GitHub user can open an issue or comment to trigger the AI agent. The attacker needs no write access, no collaborator status, no special permissions -- just a GitHub account. Combined with Vectors A/B/C (attacker content in prompts), wildcard allowlists create an attack surface accessible to anyone on the internet.

For public repositories, this means any of the billions of GitHub users can interact with the AI agent. For private repositories, the risk is lower since issue creation requires repository access.

## Example: Vulnerable Pattern

From research Example 9 -- both actions with wildcard allowlists:

```yaml
# Claude Code Action -- any user can trigger
- uses: anthropics/claude-code-action@v1
  with:
    allowed_non_write_users: "*"
    prompt: |
      Review this issue: ${{ github.event.issue.body }}

# OpenAI Codex -- any user can trigger
- uses: openai/codex-action@v1
  with:
    allow-users: "*"
    prompt: |
      Fix the issue: ${{ github.event.issue.body }}
```

## False Positives

- **No allowlist field present:** This applies to `anthropics/claude-code-action`, which does default to write-access-only users. It does NOT apply where no allowlist input exists at all -- `run-gemini-cli`, `actions/ai-inference` and `claude-code-base-action` per the table above, or a CLI agent invoked from a `run:` block. For those the gate is the step or job `if:` condition; none, on an externally triggerable event, is a finding rather than a safe default
- **Explicit user lists:** `allowed_non_write_users: "user1,user2"` or `allow-users: "dependabot[bot],renovate[bot]"` -- restricted to specific users, not wildcard
- **Bot-only wildcard:** `allowed_bots: "*"` without a wildcard on the user allowlist -- lower risk since bots typically do not open issues with attacker-crafted content, though this should still be noted as a secondary concern
- **Push-only workflows:** Workflows triggered only by `push` events with wildcard allowlists -- push requires write access anyway, so the allowlist is redundant but not dangerous

See [foundations.md](foundations.md) for AI action field mappings and trigger event details.
