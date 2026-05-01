# Vector C: CLI Data Fetch

The prompt instructs the AI agent to fetch attacker-controlled content at runtime using `gh` CLI commands. The prompt itself may contain no dangerous expressions or env vars with attacker data, but the AI is directed to pull attacker content from GitHub at execution time. This vector is invisible to static YAML analysis because the data fetch happens inside the AI agent's execution environment -- the workflow YAML looks clean.

## Applicable Actions

| Action | Applicable | Notes |
|--------|-----------|-------|
| Claude Code Action | Yes | Confirmed -- uses `gh` CLI via Bash tool to fetch issue/PR content |
| Gemini CLI | Yes | Can execute `gh` commands if shell tools are enabled |
| OpenAI Codex | Yes | Can execute `gh` commands if sandbox allows shell access |
| GitHub AI Inference | No | No shell access -- cannot execute CLI commands at runtime |

Applicability depends on the action having shell/CLI tool access. Actions without shell capabilities cannot fetch data at runtime.

## Trigger Events

Primarily `issues` and `issue_comment` (the AI fetches issue/comment content), but also `pull_request` and `pull_request_target` (fetching PR content, diffs, or review comments). Any trigger that provides an issue number, PR number, or discussion ID the AI can use to fetch attacker-controlled content. See [foundations.md](foundations.md) for the complete list of attacker-controlled contexts and trigger events.

## Data Flow

```
attacker writes malicious issue body (stored in GitHub)
  -> workflow triggers on issue event
  -> prompt instructs AI: "run gh issue view NUMBER"
  -> AI executes gh issue view at runtime
  -> gh CLI returns full issue body (attacker-controlled)
  -> AI processes attacker content from command output
```

The data never passes through YAML expressions or env vars. The prompt may interpolate only safe values like `${{ github.event.issue.number }}` (an integer), but the `gh` command output contains the full attacker-controlled issue body.

## What to Look For

1. **CLI patterns in prompt text:** `gh issue view`, `gh pr view`, `gh pr diff`, `gh api` commands mentioned in the prompt as tools or instructions for the AI
2. **Fetch instructions:** Prompt text that tells the AI to "read the issue", "fetch the PR", "get the comment", "review the diff" using CLI tools
3. **gh authentication setup:** Steps preceding the AI action or `env:` blocks that set up `GITHUB_TOKEN` (required for `gh` CLI authentication) -- indicates the AI has API access

## Where to Look

- The `with.prompt` field -- look for CLI command patterns and natural-language fetch instructions
- `with.prompt-file` content if the file is readable -- the prompt template may contain fetch instructions
- `env:` blocks for `GITHUB_TOKEN` on the AI action step (required for `gh` CLI to authenticate)
- Preceding steps that may configure `gh auth` or set tokens

## Why It Matters

This vector is invisible to static YAML analysis because the attacker-controlled data is not present in the workflow file at all. The prompt looks clean -- no `${{ }}` expressions referencing attacker contexts, no env vars carrying attacker data. But the AI agent is instructed to fetch and process attacker-controlled content at runtime. The distinction between a safe integer (issue number) in the prompt and dangerous content (issue body) returned by the CLI command is subtle and easily overlooked.

## Example: Vulnerable Pattern

```yaml
on:
  issues:
    types: [opened, edited]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          prompt: |
            TOOLS:
            - `gh issue view NUMBER`: Read the issue title, body, and labels

            TASK:
            1. Run `gh issue view ${{ github.event.issue.number }}` to read the issue details.
            2. Analyze the issue and suggest appropriate labels.
            # The issue NUMBER is safe to interpolate (integer)
            # But gh issue view returns the FULL issue body, which IS attacker-controlled
```

**Data flow:** `github.event.issue.body` (stored in GitHub) -> `gh issue view` (runtime fetch by AI) -> AI reads command output containing attacker content -> attacker content in AI context.

## False Positives

- **Metadata-only CLI commands:** `gh` commands that only read repository metadata (labels, milestones, project boards) -- output is not attacker-controlled free text
- **Trusted-author content:** `gh` commands operating on content authored by trusted maintainers (but this is difficult to distinguish statically -- err on the side of flagging)
- **Explanatory text:** Prompt mentioning `gh` in explanatory or documentation text without actually instructing the AI to execute it (e.g., "this repo uses gh for CLI access")
- **No shell access:** If the AI action does not have shell/CLI capabilities (e.g., GitHub AI Inference), `gh` commands in the prompt are inert instructions
