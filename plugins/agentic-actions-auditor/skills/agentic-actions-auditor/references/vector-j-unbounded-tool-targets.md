# Vector J: Unbounded Tool Targets

A tool restriction list scopes a command to its **verb** but not to its **target**. `Bash(gh issue edit:*)` reads as narrow -- "the agent may edit issues" -- but it matches *any* issue number, so an injection that reaches the agent can redirect the tool at an object the attacker chooses. The restriction is real; the reach is not.

This is the boundary between Vector H and the false positives it excludes. Vector H covers `Bash(*)`, an obviously unrestricted grant. Vector H's false-positive list treats a specific pattern like `Bash(npm test:*)` as "restrictive, not dangerous". That is usually right and not always: **specific-in-verb is not bounded-in-target**, and nothing in the pattern reports which it is.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | `--allowedTools` entries are command prefixes ending at the `:*` wildcard, so the prefix is the grant. Confirmed: CVE-2026-44246 is this vector. |
| OpenAI Codex | Likely | `codex-args` accepts tool configuration with a comparable shape. Not verified against the action's implementation. |
| Gemini CLI | Partial | `coreTools` restricts by tool name rather than by command prefix, so the target is not scoped either way. See Vector F for the different failure mode there. |
| GitHub AI Inference | No | No tool list -- the action calls a model API rather than exposing tools. |

## Trigger Events

Any trigger that an attacker can cause, combined with any injection path (A, B, or C) that reaches the agent. The vector is about the **grant**, not the trigger: the trigger decides whether attacker text arrives, and this decides what the agent can do with it once it has been steered.

Wildcard allowlists (Vector I) make the first half easier by admitting users without write access, which is why the two frequently appear together.

## Data Flow

```
attacker-controlled text reaches the agent  (Vector A, B or C)
  -> agent is steered toward a different object
  -> the tool pattern permits it, because it names the verb and not the target
  -> the agent acts on an issue, pull request or ref of the attacker's choosing
     using the workflow's token
```

## What to Look For

Parse `with.claude_args` for `--allowedTools` entries of the form `Bash(<command>:*)`, and check whether `<command>` names a target.

| Pattern | Reach |
|---|---|
| `Bash(gh issue edit:*)` | any issue in the repository |
| `Bash(gh issue comment:*)` | any issue or pull request |
| `Bash(gh pr review:*)` | any pull request |
| `Bash(git push:*)` | any ref the token allows |
| `Bash(git push origin:*)` | **still any ref** -- `origin` is the remote, not a refspec |
| `Bash(gh api:*)` | any REST endpoint the token allows |
| `Bash(gh api --method POST:*)` | **still any endpoint** -- `--method` is a flag, not a path |

The last two rows are the ones a quick read gets wrong: an argument is present in both, and in neither is it a target.

Bounded for comparison:

| Pattern | Bound |
|---|---|
| `Bash(gh issue edit 1234:*)` | issue 1234 |
| `Bash(gh issue edit ${{ github.event.issue.number }}:*)` | the triggering issue |
| `Bash(git push origin fix/issue-1:*)` | one ref on one remote |
| `Bash(gh api repos/o/r/issues/1:*)` | one endpoint |

Mutating verbs worth checking: `gh issue`/`gh pr` `comment`, `edit`, `close`, `reopen`, `merge`, `delete`, `create`, `add`, `remove`, `transfer`, `lock`, `review`, `ready`; plus `gh api` and `git push`. Read commands (`gh issue view`, `gh pr diff`, `gh search`, `git log`) are not findings -- they are what a hardened configuration still needs.

## Where to Look

`with.claude_args` on Claude Code Action steps, and the equivalent tool configuration on other actions. Also check `with.allowed_tools` on pre-v1 Claude workflows, which is the same string on a plain input.

## Why It Matters

This is the vector behind **CVE-2026-44246** (nnU-Net, agentic workflow injection). The workflow set `allowed_non_write_users: ${{ github.event.issue.user.login }}` so any logged-in user could trigger it, and granted `Bash(gh issue comment:*)` and `Bash(gh issue edit:*)`. Untrusted issue text reached the agent, and the agent's reach was every issue in the repository rather than the one that triggered the run.

The published case also shows why this is worth a dedicated check. The repository's fix arrived in two commits, and the commit whose message is *"hardened issue and PR agents"* removed `gh issue edit` and moved labelling into a wrapper script -- **but kept `gh issue comment`**. The grant was still unbounded after the commit everyone would call the fix. Only a later commit removed that too.

A scan that treats before and after as a binary marks the middle revision fixed. Comparing the three revisions with a check for this vector gives:

| revision | `--allowedTools` | verdict |
|---|---|---|
| `94300b49` | `gh issue comment`, `gh issue edit` | unbounded |
| `4e4770b0` ("hardened") | `gh issue comment` | **still unbounded** |
| `11bd8746` | neither | bounded |

## Example: Vulnerable Pattern

```yaml
on:
  issues:
    types: [opened]        # any GitHub user can open an issue

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          # The prompt says to triage this issue. The grant says any issue.
          claude_args: --allowedTools "Read,Bash(gh issue comment:*),Bash(gh issue edit:*)"
```

## Example: Bounded Pattern

```yaml
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: --allowedTools "Read,Bash(gh issue comment ${{ github.event.issue.number }}:*),Bash(gh issue edit ${{ github.event.issue.number }} --add-label:*)"
```

The target is the value the attacker already controls -- the issue they opened -- so naming it costs the workflow nothing and removes their choice.

Where the target genuinely cannot be known in advance, take it out of the model's reach instead: have the agent write its output to a file and let a later step post it with the number taken from `github.event.issue.number`.

## False Positives

- **Target named by expression or literal:** `Bash(gh issue edit ${{ github.event.issue.number }}:*)`, `Bash(gh issue edit 1234:*)` -- bounded, not a finding
- **Read-only commands:** `Bash(gh issue view:*)`, `Bash(gh pr diff:*)`, `Bash(git log:*)` -- no state change to redirect
- **Trusted triggers:** the same pattern on `workflow_dispatch` or `push` is not reachable by an attacker choosing the target
- **No injection path:** if the agent cannot be reached by attacker text (no A/B/C and no open trigger), the grant has nothing to steer it
- **An argument is present:** this is the trap rather than the rule. Check whether the argument is a *target*: `git push origin:*` and `gh api --method POST:*` both have one, and neither is bounded.

Note that this vector is a *scope* finding: it does not make the pattern unsafe on its own, it makes the pattern wider than the prompt implies. Report it with the injection path that reaches the agent, and grade it by what the tool can reach.

See [foundations.md](foundations.md) for the attacker-controlled input model and [vector-h-dangerous-sandbox-configs.md](vector-h-dangerous-sandbox-configs.md) for the unrestricted end of the same axis.
