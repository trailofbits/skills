# Shared Foundations: Attacker-Controlled Input Model

This reference documents cross-cutting concepts that all 9 attack vector detection heuristics depend on. Read this before analyzing individual vectors.

## Attacker-Controlled GitHub Context Expressions

These `github.event.*` expressions resolve to content an external attacker can influence. Dangerous contexts typically end with: `body`, `default_branch`, `email`, `head_ref`, `label`, `message`, `name`, `page_name`, `ref`, `title`.

**High-frequency (seen across PoC workflows):**

- `github.event.issue.body` -- issue body text
- `github.event.issue.title` -- issue title
- `github.event.comment.body` -- comment text on issues or PRs
- `github.event.pull_request.body` -- PR description
- `github.event.pull_request.title` -- PR title
- `github.event.pull_request.head.ref` -- PR source branch name
- `github.event.pull_request.head.sha` -- PR commit SHA (used in checkout)

**Lower-frequency but still dangerous:**

- `github.event.review.body` -- review comment text
- `github.event.discussion.body`, `github.event.discussion.title`
- `github.event.pages.*.page_name` -- wiki page name
- `github.event.commits.*.message`, `github.event.commits.*.author.email`, `github.event.commits.*.author.name`
- `github.event.head_commit.message`, `github.event.head_commit.author.email`, `github.event.head_commit.author.name`
- `github.head_ref` -- branch name (attacker-controlled in fork PRs)

Any `${{ }}` expression referencing these contexts carries attacker-controlled content into whatever consumes the resolved value.

## How env: Blocks Work in GitHub Actions

Environment variables can be set at three scopes:

1. **Workflow-level** `env:` (top of file) -- inherited by all jobs and steps
2. **Job-level** `env:` (under `jobs.<id>:`) -- inherited by all steps in that job
3. **Step-level** `env:` (under a step) -- available only to that step

Narrower scopes override broader ones. Critically, `${{ }}` expressions in `env:` values are evaluated BEFORE the step runs. The step only sees the resolved string value, never the expression. This is the mechanism behind Vector A: the AI agent receives attacker content through an env var without any `${{ }}` expression appearing in the prompt field itself.

```
env:
  ISSUE_BODY: ${{ github.event.issue.body }}   # evaluated at workflow parse time
# By the time the step runs, ISSUE_BODY contains the raw attacker text
```

## Security-Relevant Trigger Events

These `on:` events expose workflows to external attacker-controlled input:

| Trigger | Attacker-Controlled Data | Risk Level |
|---------|-------------------------|------------|
| `issues` (opened, edited) | Issue title, body | External users can create issues |
| `issue_comment` (created) | Comment body | External users can comment |
| `pull_request_target` | PR title, body, head ref, head SHA | Runs in base branch context WITH secrets |
| `pull_request` | Head ref, head SHA | Typically no secrets from forks, but ref is controlled |
| `discussion` / `discussion_comment` | Discussion title, body, comment body | External users can create discussions |
| `workflow_dispatch` | Input values | Triggering user controls all inputs |

Note: `push` events from the default branch and `pull_request` events that do not grant secrets to forks are generally lower risk for prompt injection because the attacker cannot influence the content that reaches the AI agent without already having write access.

## Data Flow Model

Attacker input reaches AI agents through three distinct paths:

**Path 1 -- Direct expression interpolation:**
```
github.event.*.body  ->  ${{ }} in prompt field  ->  AI processes attacker text
```

**Path 2 -- Env var intermediary:**
```
github.event.*.body  ->  env: VAR: ${{ }}  ->  prompt reads $VAR  ->  AI processes attacker text
```

**Path 3 -- Runtime fetch:**
```
github.event.*.number  ->  gh issue view N  ->  API returns attacker body  ->  AI processes attacker text
```

Path 2 requires extra attention because the prompt field contains zero `${{ }}` expressions, making the injection invisible in the prompt itself. Path 3 is missed because the attacker content is not present in the workflow YAML at all -- it is fetched at runtime.

## AI Action Prompt Field Names

Where each supported action receives prompt content that could carry attacker input:

| Action | Prompt Fields | Notes |
|--------|--------------|-------|
| `anthropics/claude-code-action` | `with.prompt`, `with.direct_prompt`, `with.override_prompt` | The last two are the pre-v1 names; also check `with.claude_args` for embedded instructions |
| `google-github-actions/run-gemini-cli` | `with.prompt` | Shell-style env var interpolation in prompt text |
| `google-gemini/gemini-cli-action` | `with.prompt` | Legacy/archived Gemini action reference |
| `openai/codex-action` | `with.prompt`, `with.prompt-file` | `prompt-file` may point to attacker-controlled file |
| `actions/ai-inference` | `with.prompt`, `with.system-prompt`, `with.system-prompt-file` | System prompt is also an injection surface |

When checking for attacker-controlled content in prompts, examine ALL fields listed for the relevant action, not just the primary `prompt` field.

### Claude Code Action Renamed Its Inputs at v1

`claude-code-action` replaced its input surface at v1. The v0.x names are absent from the v1 `action.yml` and the v1 names are absent from v0.x, so a signature written against one set silently matches nothing in the other. The action's [migration guide](https://github.com/anthropics/claude-code-action/blob/main/docs/migration-guide.md) gives the mapping; these are the security-relevant rows:

| v0.x, including the `@beta` tag | v1 and later | Why it matters |
|---------------------------------|--------------|----------------|
| `direct_prompt` | `prompt` | Prompt sink |
| `override_prompt` | `prompt` | Prompt sink |
| `custom_instructions` | `claude_args: --append-system-prompt` | System prompt sink |
| `allowed_tools` | `claude_args: --allowedTools` | Tool allowlist, Vectors F and H |
| `disallowed_tools` | `claude_args: --disallowedTools` | Tool denylist |

Both sets appear in the wild, so match on either. The ref after `@` does not identify the set: `@beta` carries the v0.x names, and files pinned at `@v1` or a commit SHA still carry `direct_prompt`. Read the field names present in the file, not the ref.

The tool lists also separate differently. `claude_args: '--allowedTools "Bash(a:*) Bash(b:*)"'` separates on spaces; the v0.x `allowed_tools: "Bash(a:*),Bash(b:*)"` separates on commas. A matcher that splits one way reads the other as a single entry.
