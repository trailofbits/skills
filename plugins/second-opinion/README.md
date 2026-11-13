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
/second-opinion:second-opinion use Gemini CLI to review commit abc1234 for security issues
```

The skill uses choices already given and asks for missing provider or
scope details. General review is the default focus. Applicable project
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

## Calcifier recipe for `second-opinion`

The [`second-opinion` Python recipe](skills/second-opinion/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/second-opinion/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/second-opinion/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `repo_path` | `str` | Required |
| `provider` | `Literal['codex', 'antigravity', 'gemini', 'google', 'both']` | Required |
| `scope` | `Literal['uncommitted', 'branch', 'commit']` | Required |
| `base` | `str` | `''` |
| `commit` | `str` | `''` |
| `focus` | `str` | `'general correctness and maintainability'` |
| `requirements` | `str` | `''` |
| `codex_model` | `str` | `''` |
| `google_model` | `str` | `''` |
| `codex_effort` | `Literal['none', 'minimal', 'low', 'medium', 'high', 'xhigh']` | `'xhigh'` |
| `include_project_context` | `bool` | `True` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
