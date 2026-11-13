---
name: run-workflow
description: "Runs a plugin's JavaScript workflow (workflows/*.js) on Codex or Gemini CLI, where Claude Code's native Workflow tool is unavailable, then checks on it and reports its result. Use when a skill says to run its workflow through workflow-runner, or when asked to run, check on, or resume a plugin workflow outside Claude Code."
allowed-tools: Bash Read Write
---

# Run a plugin workflow

Some plugins ship their orchestration as a script under `workflows/`. Claude Code runs
those natively. This skill runs the same script elsewhere: each `agent()` call becomes a
fresh headless `codex exec` worker inside Codex's own sandbox (Gemini CLI support is
experimental). The script still decides what runs and when it is done. Your job is to
launch it correctly, wait, and report what it returned.

**In Claude Code, use the native `Workflow` tool, not this.** If a native Workflow call
was denied, stop there. This runner is not a way around a denial, and it must not be
used to get access the user did not grant.

## What you need from the calling skill

| Input | Where it comes from |
|---|---|
| Workflow script | In the plugin that holds the calling skill: two directories above that skill's `SKILL.md`. A command like `/<plugin>:<name>` is the file in that plugin's `workflows/` whose `meta.name` is `<name>`. Do not search plugin caches for it: another installed version can differ |
| Arguments | The JSON object the calling skill would pass as the Workflow `args` |
| Target directory | The repository or directory the workflow works on (`--cwd`) |
| Sandbox | Your own current sandbox mode, as Codex states it in your instructions: `read-only`, `workspace-write` or `danger-full-access`. Workers get the same, as Codex's own subagents do |
| Dependencies | Any other plugin whose agents or skills the workflow uses, as `--plugin-root` |
| Budget | Only if the user gave one ("use 500k tokens", "+500k"): `--token-budget 500000` |

Resolve every path to an absolute one before launching. The runner is
[`scripts/run.mjs`](../../scripts/run.mjs), resolved from this file's installed location.
It needs Node.js 22 or newer and an installed, logged-in host CLI. It has no npm
dependencies.

For a dependency, pass the installed plugin directory: the one that holds
`.claude-plugin/plugin.json`. Codex keeps installs under
`~/.codex/plugins/cache/<marketplace>/<plugin>/<version>/`. If several versions are
installed and you cannot tell which one is active, ask. Never point at a copy inside the
target repository or a test fixture: a different copy means different instructions,
with nothing to say so. The runner refuses a workflow script inside the target.

## Launch

Start the run in the background, as an ordinary command, passing the arguments inline
(single-quoted JSON):

```sh
node <runner> <workflow.js> --args '<json>' --cwd <target> --sandbox <your sandbox mode> --detach
```

Add `--plugin-root <dir>` once per dependency. Add `--network` when the calling skill
says its workflow needs network access. Add `--model <name>` only if the user picked a
model for this host. Workflows name Claude models; the runner replaces those with the
CLI's configured model and says so.

The runner checks, without a model call, that Codex is logged in and accepts the flags it
uses. It then prints `"status": "started"` and the run directory, which it picks itself,
within a few seconds. Or it fails with the reason. A setup error (not logged in, an
unsupported Codex version, a missing plugin root) is not a reason to retry with broader
access.

**If it fails with `NEEDS_ESCALATION`, run the same command again with escalated
permissions.**

- **Why:** the runner normally runs inside your sandbox, and so do its workers. That
  needs network access, so workers can reach the model, and a `workspace-write`
  sandbox. The error says which one is missing.
- **How:** in the justification, say that it starts Codex workers under the user's
  login. Each worker still runs under the sandbox mode you pass.
- **Don't** suggest a reusable approval rule for `node`: every later `node` command
  would then skip the sandbox.
- **If escalation is refused,** say so and stop.

Run `--resume` and `--cancel` the way the launch ran: escalated only if it was.
`--status` always runs normally.

## Wait

```sh
node <runner> --status <run directory>
```

Check about once a minute. Large workflows run for an hour or more. After each check,
relay the status's `progress` line to the user (phase, agents done, running and
failed, elapsed time), adding a sentence only when something changed that matters. Never
start a second run of the same workflow while one is `running`.

| Status | Meaning | Next |
|---|---|---|
| `running` | Workers are active | Keep waiting |
| `completed` | The script returned; `result` holds its value | Report it, as below |
| `failed` | The script threw, or the runner refused a setting | Report `error`; do not rerun with a different sandbox |
| `stopped`, `interrupted` | The runner exited before the script finished | `node <runner> --resume <run directory> --detach`, the way the launch ran |

To stop a run, because the user asks or it is clearly going wrong, use
`node <runner> --cancel <run directory>`. Workers stop and the run becomes
`interrupted`, so it can be resumed.

Resume follows Claude Code's rule: recorded agents replay up to the first call that is
new, changed or failed, and that call and every one after it run again. Calls are matched
by prompt and options, not position, so reordering calls does not rerun them. Edits to the workflow script
are picked up the same way. It refuses if the runner or the run's settings changed. If
files in the target changed since the run started, start a new run instead: replayed
results describe the old files.

## Report

`completed` means the script returned. It does not mean the review converged or the
audit found nothing. Present `result` the way the calling skill says to. Then:

- **`workerFailures` is not empty**: say how many workers failed and that the result is
  partial. Each failure names its job directory, which holds the prompt, command, output
  and error.
- **A note says every agent failed**: no work was done. Report it as a failure, with the
  error it names, never as an empty or clean result.
- **Other `notes`**: tell the user about substitutions the runner made, such as a Claude
  model name replaced with the CLI default, and about `agent()` calls the runner rejected.
- **Missing coverage the workflow reports itself** (unanalyzed items, a capped round,
  `halted`): say so. These are the workflow's findings about its own completeness.

If the runner cannot run at all (no Node, no CLI login, escalation refused), say what is
missing and stop. Do not do the workflow's work inline instead. A hand-run imitation
loses the script's fan-out, verification and stopping rules, and nothing would tell the
user that happened.

## What differs from Claude Code

- **Tool lists are enforced by the sandbox, not per tool.** A role whose tools can
  neither write nor run commands gets a read-only sandbox, and in `workspace-write` a role
  without a shell gets no network access. A role without Bash can still run code inside
  its sandbox. Otherwise workers get your session's sandbox, enforced by Codex at the OS
  level; when they run inside it, no role can be narrowed further. The runner trusts the
  sandbox mode you pass; it cannot check it.
- **Two additions so common tools start.** Inside your sandbox, uv and Semgrep keep their
  caches in the temp directory. After an escalated launch, workers may write the usual
  uv, CodeQL and Semgrep caches when the workflow's plugin uses those tools. On macOS
  their commands get the system certificate bundle so Semgrep can start.
- **Workers read your login but cannot renew it** when they run inside your sandbox. If
  it expires during a run, they fail until this session renews it.
- **Workers cannot ask you for approval.** Their requests go to Codex's automatic reviewer
  if your config uses it; otherwise a command the sandbox refuses simply fails. Claude
  Code would pause the run and ask.
- **Workflow scripts are trusted code.** They run with the runner's permissions: your
  sandbox's, or your full permissions after an escalated launch. Only run workflows
  from installed plugins.
- **A worker that runs over 30 minutes** (`--timeout-ms`) is stopped and becomes `null`.
  Claude Code restarts stalled agents instead.
- **Structured output**: Codex workers use the CLI's native schema enforcement. An
  invalid reply is a failed worker (`null`), not a retry.
- **`budget`** has a `total` only when `--token-budget` is set. It stops new agents from
  starting; agents already running finish. Token counts are whatever the CLI reports.
- **Not supported**: nested `workflow()` calls and `isolation: 'worktree'`. A workflow
  that uses either gets an error from that call.
- **Gemini CLI is experimental.** It has only been tested against a simulated CLI, its
  workers run under Gemini's approval mode without Gemini's sandbox, and the schema is
  checked after the reply rather than enforced.
