# second-opinion

Get an independent review of uncommitted changes, a branch diff, or a
commit using OpenAI Codex or Google Antigravity. The `second-opinion`
skill can also use Gemini CLI when the selected account supports it.

## Setup

Install and authenticate the CLI you intend to use:

| Provider | Setup |
|----------|-------|
| OpenAI Codex | Install with `npm i -g @openai/codex` and configure a supported ChatGPT account or API authentication |
| Google Antigravity | Follow the [CLI installation guide](https://antigravity.google/docs/cli/getting-started); the executable is `agy` |
| Gemini CLI | Install with `npm i -g @google/gemini-cli` and configure a supported Code Assist, API-key, or Vertex AI account |

Antigravity is the default Google path. If Gemini CLI returns
`UNSUPPORTED_CLIENT` with an Antigravity migration message, that
account cannot use the Gemini CLI path. Review extensions are not required.

Install the plugin in Claude Code:

```text
/plugin marketplace add trailofbits/skills
/plugin install second-opinion@trailofbits
```

## Usage

Invoke the `second-opinion` skill with the provider and scope:

```text
/second-opinion:second-opinion use Codex to review uncommitted changes for bugs
/second-opinion:second-opinion compare Codex and Antigravity against origin/main
/second-opinion:second-opinion use Codex with gpt-6.2-astra at high effort on this branch
/second-opinion:second-opinion use Gemini CLI to review commit abc1234 for security issues
```

Each run starts with two quick checks. If a newer version of this plugin
is published in its marketplace, the skill offers to update first (the
update applies after a restart). It also reads each CLI's current model
list, so new models appear without a plugin update. Neither check blocks
the review when it fails or you are offline.

The skill uses choices already given and asks for missing provider or
scope details. It then reads each selected CLI's model list (`codex debug
models`, `agy models`) and asks which model and reasoning effort to use,
with a recommendation for each. Name a model or effort in the request to
skip that question. General review is the default focus. Applicable project
instructions are included unless you exclude them.

Uncommitted reviews include staged, unstaged, and untracked changes.
When you select both providers, each receives the same captured patch.
Results identify the provider, model, findings, and any gaps in coverage.

## Execution

Codex runs through `codex exec` with a read-only sandbox and structured
JSON findings. Antigravity runs in print mode and returns prose.
Gemini CLI uses a headless prompt for supported accounts.

The skill reports findings without applying fixes or publishing a review.
Authentication errors, denied inspection, and missing output are reported
as incomplete reviews.

## Upgrading an installation with a failed Codex MCP server

Version 1.8.1 removes the plugin's automatic Codex MCP registration.
Codex CLI 0.154.0 dropped the server entry point, as recorded in the
[OpenAI changelog](https://learn.chatgpt.com/docs/changelog). External
reviews use the CLI directly and do not require an MCP connection.

If Claude Code reports `CONNECTION_CLOSED` for the plugin's Codex server,
refresh the marketplace and update the installed plugin:

```bash
claude plugin marketplace update trailofbits
claude plugin update second-opinion@trailofbits
```

Restart Claude Code after updating so it drops the old server
registration. The separate `codex` and `codex-reply` MCP tools are no
longer part of the plugin.
