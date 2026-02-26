# Vector I: Wildcard User Allowlists

User allowlist fields are set to wildcard values (`"*"`) that permit ANY GitHub user -- including external contributors, anonymous users, and potential attackers -- to trigger the AI agent. This removes the last line of defense (user-based gating) that might prevent an external attacker from triggering the AI agent via issues or comments.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | `allowed_non_write_users: "*"` and `allowed_bots: "*"` confirmed in many PoCs |
| OpenAI Codex | Yes | `allow-users: "*"` and `allow-bots: "*"` confirmed in PoCs |
| Gemini CLI | No | No equivalent user allowlist field -- any user who can trigger the workflow event can interact |
| GitHub AI Inference | No | No equivalent user allowlist field -- access controlled by workflow trigger permissions only |

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

**General pattern:** Any `with:` field containing a user or bot allowlist with value `"*"` or that resolves to unrestricted access.

## Where to Look

The `with:` block of AI action steps. Check for the exact field names listed above with string values of `"*"`.

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

- **No allowlist field present:** Actions without any user allowlist field typically default to write-access-only users (safe default behavior) -- the absence of the field is not a finding
- **Explicit user lists:** `allowed_non_write_users: "user1,user2"` or `allow-users: "dependabot[bot],renovate[bot]"` -- restricted to specific users, not wildcard
- **Bot-only wildcard:** `allowed_bots: "*"` without a wildcard on the user allowlist -- lower risk since bots typically do not open issues with attacker-crafted content, though this should still be noted as a secondary concern
- **Push-only workflows:** Workflows triggered only by `push` events with wildcard allowlists -- push requires write access anyway, so the allowlist is redundant but not dangerous

See [foundations.md](foundations.md) for AI action field mappings and trigger event details.
