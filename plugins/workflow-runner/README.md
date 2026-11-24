# Workflow Runner

Several plugins in this marketplace keep their orchestration in a JavaScript workflow
(`workflows/*.js`): `c-review`'s fan-out and coverage gate, `code-improver`'s
review-fix loop, `audit-context-building`'s per-function analysis. Claude Code runs
those scripts with its native `Workflow` tool. Codex has no equivalent, and its
subagents are spawned by the model, not by a script.

This plugin runs the same scripts on Codex. Each `agent()` call becomes a fresh
headless `codex exec` worker under your session's sandbox policy. The same workflow
file runs on each host. Gemini CLI support is experimental (see below).

**In Claude Code, keep using the native Workflow tool.** The runner exists for hosts
that lack one, and it is never a way around a denied Workflow call.

## Install

```sh
codex plugin add workflow-runner@trailofbits
```

It needs Node.js 22+ and an installed, logged-in Codex CLI. There are no npm
dependencies, no daemon and no extra API key: workers use your existing Codex login.
On Linux, Codex runs also need `flock` from util-linux on your PATH.

## Use

Invoke `$workflow-runner:run-workflow` in Codex and name a workflow and its arguments.
Automatic handoffs from workflow skills are tracked in [#386](https://github.com/trailofbits/skills/pull/386).

For a manual Linux run, use an ordinary terminal outside the Codex session sandbox.
Replace `VERSION` and the workflow and target paths with your own values.

```sh
runner="$HOME/.codex/plugins/cache/trailofbits/workflow-runner/VERSION/scripts/run.mjs"
node "$runner" /path/to/plugin/workflows/audit-context.js \
  --args '{"path": ".", "limit": 1}' --cwd /path/to/target \
  --backend codex --sandbox workspace-write --outside-session-sandbox --detach
```

Set `run_dir` to the path printed by the launch command. Check progress with
`node "$runner" --status "$run_dir"`. Resume a stopped run from the same terminal
context with `node "$runner" --resume "$run_dir" --outside-session-sandbox --detach`.

| Command | What it does |
|---|---|
| `run.mjs WORKFLOW.js [--out DIR] [options]` | Run in the foreground; prints a JSON summary |
| `... --detach` | Start in the background and return; progress goes to `DIR/runner.log` |
| `run.mjs --status DIR` | Report state, agent counts, recent progress, and the result once done |
| `run.mjs --cancel DIR` | Stop a running run; it becomes `interrupted` and can be resumed |
| `run.mjs --resume DIR [--detach]` | Continue an interrupted run with its original settings |
| `run.mjs --check WORKFLOW.js` | Compile and resolve the plugin; starts nothing |

`--help` lists every option. The most important ones:

- `--sandbox read-only|workspace-write|danger-full-access` sets the worker sandbox
  mode (default `read-only`). Use your current sandbox mode in a Codex session.
- `--outside-session-sandbox` selects worker-enforced sandboxing even when the
  environment contains `CODEX_SANDBOX`. The skill passes it on Linux after requesting
  approval for launch or resume. Approval comes from the host's command tool.
- `--out DIR`: the run directory. By default the runner picks
  `workflow-runs/<workflow>-<time>` in the temp directory inside the sandbox, or under
  `~/.codex` after an escalated launch.
- `--plugin-root DIR`: an installed plugin whose agents or skills the workflow uses.
  Repeatable. The workflow's own plugin is found automatically.
- `--network`: let workers' commands reach the network, in `workspace-write`.
- `--model`, `--effort`: apply to every worker, replacing the workflow's choices.
- `--token-budget N`: an output-token budget, exposed to the workflow as `budget.total`.

### Inside the sandbox, or with your approval

Before any worker starts, the runner checks without a model call that Codex is logged
in and accepts every flag it passes.

**Linux.** When the Codex session is sandboxed, the skill asks you to approve launch
outside that sandbox.
The Linux sandbox can stop the detached runner when the launching command exits.
After approval, the runner and its workflow script run with your permissions and each
Codex worker applies its own sandbox. Status checks can run inside the session sandbox.
They use a file lock because the Linux sandbox cannot see the launcher process.

**macOS.** The skill first starts the runner as an ordinary command. When it runs
inside the session's sandbox, its workers share that sandbox.

- **Each worker gets its own Codex folder.** A new Codex program (`codex exec`) writes to
  its home folder at startup, and the sandbox does not let it write `~/.codex`. The
  runner gives each run a private folder (`CODEX_HOME`) in the temp directory, with links
  to your login and settings, which workers only read.
- **Workers share the session's sandbox.** macOS does not let a sandboxed program start a
  second sandbox (`sandbox_apply: Operation not permitted`), so workers run without one
  of their own, confined by the session's. Writing outside the workspace fails as it does
  for any command in the session.
- **Tool caches move to the temp directory.** uv and Semgrep cannot write their usual
  caches inside the sandbox, so the runner points them at a folder in the temp directory,
  kept between runs. CodeQL reads its bundled query packs in place and needs nothing.

On macOS, the runner exits with `NEEDS_ESCALATION` in the following cases. The skill
then asks you to approve the same command outside the sandbox.

- **The sandbox has no network access.** Workers have to reach the model. Codex sandboxes
  have network access off unless `sandbox_workspace_write.network_access` is set.
- **The session is read-only,** so there is nowhere to write.

Run `--resume` and `--cancel` in the same launch context as the original run. The skill
asks for approval again for an outside-sandbox run. Records written inside the sandbox
are only resumable there because any command in that sandbox could have changed them.

Tested with Codex 0.163 on macOS. Codex's built-in subagents are not an option: only the
model can start them, and a workflow needs its `agent()` calls dispatched and their
results returned by code. The Codex TypeScript SDK starts the same CLI as a subprocess.

## What matches the native Workflow tool

The runtime implements the script API the native tool documents, and that this
repository's 11 workflows use:

| API | Behavior |
|---|---|
| `agent(prompt, opts)` | A fresh worker. Returns its text, or the schema-validated object. A failed worker returns `null`; a configuration error (unknown `agentType`, unsupported option) rejects, so the script's own `catch` can fall back |
| `parallel(thunks)` | A barrier; never rejects; a thrown branch is `null` |
| `pipeline(items, ...stages)` | No barrier between stages; stages get `(previous, original, index)`; a throw drops that item to `null` |
| `phase()`, `log()`, `args` | As native |
| `budget` | `total` is `null` unless `--token-budget` is set. Once it is, no new agent starts after the reported output tokens reach it; agents already running finish, so a run can overshoot by what they use |
| `Date.now()`, `Math.random()` | Throw, as native, so a resumed run cannot diverge |
| Resume | Recorded agents replay up to the first call with no completed record (new, changed or failed); that one and every agent after it run again, including after edits to the script. Calls are matched by prompt and options, not position, because a pipeline's call order depends on timing: reordering calls does not rerun them |

Supported `agent()` options are `schema`, `label`, `phase`, `model`, `effort` and
`agentType`. Named agents load from `agents/*.md` in the workflow's plugin or a
`--plugin-root`, with `{baseDir}` and `CLAUDE_PLUGIN_ROOT` resolved to their own plugin.

## Where it differs

- **Workflow scripts are trusted code.** The native tool gives a script no filesystem or
  process access. Here the script runs in Node's `vm` module, which is not a security
  boundary, with the runner's permissions: the session sandbox's, or your full permissions
  after an escalated launch. Run workflows only from
  installed plugins; the runner refuses a script inside the target directory or an
  `--add-dir`.
- **Workers inherit the launching session's sandbox.** Claude Code's workflow agents get
  "the same permission checks and sandboxing as any other tool call in the session", and
  Codex's own subagents "inherit the parent turn's current sandbox and approval settings".
  The parent model passes its mode with `--sandbox`; the runner cannot verify it.
- **Tool lists are enforced by the sandbox, not per tool.** A role whose tools can neither
  write nor run commands gets a read-only sandbox, and in `workspace-write` a role without
  a shell gets no network access, after an escalated launch; inside the session's sandbox
  every role gets the session's rules. A role without Bash can still run code inside its
  sandbox: Codex workers have code-running tools besides the shell. So a workflow that
  relies on a role having no shell, such as c-review's, does not run here. Beyond that, a
  role's tool list is stated in its prompt.
- **Workers cannot ask you for approval.** Approvals follow your Codex config: with Codex's
  automatic reviewer configured, a worker's request goes to it; otherwise a command the
  sandbox refuses fails. Claude Code would pause the run and ask instead.
- **Two additions so common tools start inside `workspace-write`.** Inside the session's
  sandbox, uv and Semgrep keep their caches in the temp directory. After an escalated
  launch, when the workflow's plugin uses uv, CodeQL or Semgrep and the tool is installed,
  workers may write its usual cache (created if missing). On macOS, their commands get the system certificate bundle, without
  which Semgrep crashes in the sandbox; the `codex` binary itself keeps the keychain. The
  run's notes list what was granted.
- **Workers read your login but cannot renew it** inside the session's sandbox. If it
  expires during a run, they fail until your session renews it.
- **Claude model names map to the CLI's default**, with one note per name. `max` effort
  becomes `xhigh` on Codex.
- **A worker that runs over 30 minutes** (`--timeout-ms`) is stopped and becomes `null`.
  Claude Code restarts stalled agents instead.
- **Cancellation reaches the worker's process group.** A worker that times out or is
  cancelled, and anything it left running, gets SIGTERM and then SIGKILL two seconds
  later. A tool that starts its own process group, as Codex does for some commands, is
  outside that reach and can outlive the worker.
- **Visible failures.** `agent()` calls the runner rejected are listed in the run's notes,
  and so is a run in which every agent failed, because an expired login looks exactly like
  a workflow that found nothing. A run that returns early with work still running, or
  returns nothing, fails.
- **Workers cannot spawn subagents** (Codex `multi_agent` is disabled for them). The
  script owns fan-out.
- **Not supported**: nested `workflow()` calls and `isolation: 'worktree'`; both reject.
- **Gemini CLI is experimental.** There is no Gemini install path yet, the adapter has only
  run against a simulated CLI, its workers run under Gemini's `--approval-mode` without
  Gemini's sandbox, and structured output is checked after the reply rather than enforced.
  Gemini CLI also no longer serves individual Google accounts: it needs a Code Assist
  Standard or Enterprise, API-key, or Vertex AI account.

## Run records

Each run directory holds `workflow.js`, `state.json`, `result.json` once done, and one
`jobs/NNNN-<label>/` directory per worker with its prompt, exact command, stdout,
stderr, and result or error. After an escalated launch in `workspace-write`, the runner
refuses a run directory that workers can write (the target, temp, any `--add-dir`): a
prompt-injected worker could otherwise rewrite the records that a later escalated resume
trusts. Inside the sandbox the records live in the temp directory, and they can only be
resumed there. A resume never
launches the program named in the records; it looks up `codex` again. Records can contain
source code, secrets and model output: delete them when you are done.

## Status and tests

Tested live with Codex CLI 0.163.0 on macOS, including structured output, the
Claude-model fallback, sandbox confinement, and the workflow skills in this repository,
both inside the session's sandbox and after an escalated launch.

On Ubuntu 24.04 with Codex CLI 0.159.3, smoke tests covered outside-sandbox launch,
sandboxed status polling, cancellation, and resume. A native Codex worker also
completed a workflow using a local mock model endpoint.

```sh
node --test plugins/workflow-runner/tests/*.test.mjs
```

The suites start real processes against a fake CLI (`tests/fake-cli.mjs`), so CI
spends no model tokens. They also compile every workflow in the repository and
exercise the runner's safeguards.
