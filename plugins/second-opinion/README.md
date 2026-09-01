# second-opinion

Run code reviews using external LLM CLIs (OpenAI Codex, Google Antigravity) on uncommitted changes, branch diffs, or specific commits.

## Prerequisites

### OpenAI Codex CLI

- [Codex CLI](https://github.com/openai/codex) installed: `npm i -g @openai/codex`
- OpenAI API key or ChatGPT Plus subscription configured for Codex

### Google Antigravity CLI

- [Antigravity](https://antigravity.google) installed; binary is `agy`
  (installs to `~/.local/bin`, which may need adding to PATH)
- Google account authenticated (`agy models` should list models)
- No extensions required

### Google Gemini CLI (legacy — paid tiers only)

Gemini CLI stopped serving individual accounts (AI Pro, Ultra, free) on
2026-06-18; they now get `UNSUPPORTED_CLIENT` and are pointed at
Antigravity. Only Gemini Code Assist Standard/Enterprise licenses or a
paid `GEMINI_API_KEY` still work.

- [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed: `npm i -g @google/gemini-cli`
- Code review extension: `gemini extensions install https://github.com/gemini-cli-extensions/code-review`
- Security extension: `gemini extensions install https://github.com/gemini-cli-extensions/security`
- Headless runs need `--skip-trust` or `GEMINI_CLI_TRUST_WORKSPACE=true`

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install second-opinion
```

## Usage

```
/second-opinion
```

The command will prompt for:

1. **Review tool** — Codex, Gemini, or both (default)
2. **Review scope** — uncommitted changes, branch diff, or specific commit
3. **Project context** — optionally include CLAUDE.md/AGENTS.md for project-aware review
4. **Review focus** — general, security, performance, or error handling

### Quick invocation

```
/second-opinion check the uncommitted changes for security issues
```

Inline arguments pre-fill the scope and focus, skipping redundant questions.

## How It Works

Shells out to `codex review` and/or `gemini` CLI with high-capability model configurations. When both tools are selected (the default), runs Codex first then Gemini, presenting results side by side for comparison.

## Codex MCP Tools

This plugin bundles Codex CLI's built-in MCP server (`codex mcp-server`), which auto-starts when the plugin is installed and provides two MCP tools:

- **codex** — start a new Codex session with a prompt, model, sandbox, and approval policy settings
- **codex-reply** — continue an existing session by thread ID for multi-turn conversations

These tools work independently of the `/second-opinion` slash command. Use them when you want direct, programmatic access to Codex without the interactive prompt workflow.
