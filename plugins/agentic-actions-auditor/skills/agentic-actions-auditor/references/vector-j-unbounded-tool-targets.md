# Vector J: Unbounded Tool Targets

A tool restriction list scopes a command to its **verb** but not to its **target**. `Bash(gh issue edit:*)` reads as narrow -- "the agent may edit issues" -- but it matches *any* issue number, so an injection that reaches the agent can redirect the tool at an object the attacker chooses. The restriction is real; the reach is not.

This is the boundary between Vector H and the false positives it excludes. Vector H covers `Bash(*)`, an obviously unrestricted grant. Vector H's false-positive list treats a specific pattern like `Bash(npm test:*)` as "restrictive, not dangerous". That is usually right and not always: **specific-in-verb is not bounded-in-target**, and nothing in the pattern reports which it is.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | `--allowedTools` entries are command prefixes ending at the `:*` wildcard, so the prefix is the grant. Confirmed: CVE-2026-44246 is this vector. |
| OpenAI Codex | No | `codex-args` exposes no command-prefix allowlist of the `Bash(<prefix>:*)` shape. Without a prefix grant there is no verb-grant to widen, so this mechanism does not apply. Its tool configuration is not comparable to Claude's. |
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

### A prefix bounds the prefix, not the arguments

`Bash(<prefix>:*)` is a **prefix match**: the pattern requires the command to *start with*
`<prefix>`, and permits anything to follow it. Naming a target inside the prefix therefore
does not stop a later argument from adding to it or replacing it. Each row below reads as
bounded and is not:

| Pattern | Reachable anyway, because |
|---|---|
| `Bash(gh issue edit 1234:*)` | `gh issue edit 1234 --repo other/repo` -- `--repo` follows the prefix and retargets the repository |
| `Bash(gh issue edit ${{ github.event.issue.number }}:*)` | the same: the issue number is pinned, the `--repo` that decides *which* repository is not |
| `Bash(git push origin fix/issue-1:*)` | `git push origin fix/issue-1 attacker:main` -- a refspec argument is a **list**, so naming one ref does not bound the push |
| `Bash(gh api repos/o/r/issues/1:*)` | `gh api repos/o/r/issues/1 --method DELETE` -- the path is pinned, the method and any `--field` are not |

The rule is narrower than "the pattern names a target", and worth stating precisely:

- **A prefix bounds nothing that can be supplied after it.** It is only a bound when the
  command cannot accept a further target or a retargeting flag in its remainder.
- `git push` takes a *list* of refspecs, so no single-ref prefix bounds it.
- `gh` subcommands accept `--repo`, `--method`, `--field` and similar *after* the prefix,
  so a prefix naming an object does not bound that object's owner or the operation applied.
- Adding flags to the prefix narrows the match without closing it: the command still only
  has to *start* with the longer prefix, so `Bash(gh issue edit 1234 --add-label:*)` still
  admits `... --add-label x --repo other/repo`.

**What is genuinely bounded is a command that reads no target from its arguments.** The
robust form is a wrapper script that takes the object from the triggering event and ignores
everything else, shown under *Example: Bounded Pattern* below. Anything else is **reduced
reach, not a bound**, and should be reported as a scope finding with the residual reach
stated rather than cleared.

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

## Example: Narrowed Pattern (an improvement, not a bound)

```yaml
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: --allowedTools "Read,Bash(gh issue comment ${{ github.event.issue.number }}:*),Bash(gh issue edit ${{ github.event.issue.number }} --add-label:*)"
```

This is a real improvement on `Bash(gh issue edit:*)` -- the number is pinned and the edit path is narrowed to `--add-label`, so the agent can no longer close, reopen or transfer anything. **It is still not bounded**, because the command only has to *start* with the prefix: `gh issue edit <n> --add-label x --repo other/repo` matches and mutates a repository outside this one. Report it as reduced reach with the residual reach named, not as clear.

## Example: Bounded Pattern

A bound means the command has **no path to a different target**, which is achieved by taking
the target out of the model's reach rather than by naming it in the prefix. Two things have to
hold, and the second is the one that is easy to miss: the object must come from the event, **and
the agent must not be able to rewrite the enforcement code itself.**

A wrapper script that lives in the repository only bounds the agent if the agent cannot write
to it. If the same grant includes `Write` -- or any other capability that can reach the
script's path -- the agent can replace the wrapper with one that edits an arbitrary issue, and
the prefix that looked like a bound now bounds nothing. The bound is on the *capability set*,
not on the prefix.

So the wrapper is provisioned **outside the model's writable tree** by a step that runs first,
and the agent's tool grant carries no write at all:

```yaml
      - name: Provision the triage wrapper outside the agent's writable tree
        env:
          TRIAGE_LABEL_SH: ${{ runner.temp }}/triage-label.sh
        run: |
          cat > "$TRIAGE_LABEL_SH" <<'WRAPPER'
          #!/usr/bin/env bash
          # The object comes from the event, never from the model.
          set -euo pipefail
          gh issue edit "$ISSUE_NUMBER" --add-label "$1"
          WRAPPER
          chmod 0555 "$TRIAGE_LABEL_SH"

      - uses: anthropics/claude-code-action@v1
        env:
          ISSUE_NUMBER: ${{ github.event.issue.number }}
          TRIAGE_LABEL_SH: ${{ runner.temp }}/triage-label.sh
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: --allowedTools "Read,Bash(${{ runner.temp }}/triage-label.sh:*)"
```

The grant is `Read` plus one runner-temp prefix -- **no `Write`**, so there is no path by which
the model can replace the wrapper. The script itself reads one label and nothing else, so no
argument the model supplies can change which issue is edited or which repository it lives in.
The prefix is a bound here because the remainder has no target in it *and* the code behind it
is fixed -- which is the property to check for, and the one the prefix-names-a-target patterns
above do not have.

## False Positives

- **Target named by expression or literal -- reduced reach, not a bound.** `Bash(gh issue edit ${{ github.event.issue.number }}:*)` and `Bash(gh issue edit 1234:*)` both pin the issue and leave `--repo other/repo` admissible after the prefix. Clear them only when the command cannot take a further target (see *A prefix bounds the prefix, not the arguments*); otherwise report them as scope findings with the residual reach named.
- **Read-only commands:** `Bash(gh issue view:*)`, `Bash(gh pr diff:*)`, `Bash(git log:*)` -- no state change to redirect
- **Trusted triggers:** the same pattern on `workflow_dispatch` or `push` is not reachable by an attacker choosing the target
- **No injection path:** if the agent cannot be reached by attacker text (no A/B/C and no open trigger), the grant has nothing to steer it
- **An argument is present:** this is the trap rather than the rule. Check whether the argument is a *target*: `git push origin:*` and `gh api --method POST:*` both have one, and neither is bounded.

Note that this vector is a *scope* finding: it does not make the pattern unsafe on its own, it makes the pattern wider than the prompt implies. Report it with the injection path that reaches the agent, and grade it by what the tool can reach.

See [foundations.md](foundations.md) for the attacker-controlled input model and [vector-h-dangerous-sandbox-configs.md](vector-h-dangerous-sandbox-configs.md) for the unrestricted end of the same axis.
