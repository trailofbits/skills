# Regression Hunt

An agent coordinates focused skills to investigate selected PRs or commits. The host supplies
agent dispatch, authentication and tools. No custom model adapter or Python service is required.

Start with [regression-hunt](skills/regression-hunt/SKILL.md). Supply a change list, a campaign
directory outside the plugin, and execution/resource limits. PRs may be open, closed or merged;
local commits and explicit ranges are supported.

The coordinator and standalone skills use any root `AGENTS.md`,
`PATCHING_GUIDELINES.md` and `THREAT_MODEL.md` as described in the
[project guidance](references/evidence.md#project-guidance).

## Skills

| Skill | Responsibility |
| --- | --- |
| [regression-hunt](skills/regression-hunt/SKILL.md) | Delegate, track progress and resume |
| [prepare-regression](skills/prepare-regression/SKILL.md) | Pin sources and PR/commit context |
| [hunt-regressions](skills/hunt-regressions/SKILL.md) | Identify reachable patch-introduced candidates |
| [reproduce-regression](skills/reproduce-regression/SKILL.md) | Deploy both states and execute a PoC |
| [replay-regression](skills/replay-regression/SKILL.md) | Independently repeat the unchanged PoC |
| [adjudicate-regression](skills/adjudicate-regression/SKILL.md) | Apply the definition and exclusions |
| [report-regressions](skills/report-regressions/SKILL.md) | Validate and render saved decisions |

See the [system flow](docs/system-flow.md), [definition](docs/regression-definition.md),
[file handoffs](references/evidence.md), [report labels](docs/report-definitions.md) and
[example request](examples/request.md). Every packaged helper and reference is inside this
plugin.

## Deterministic helpers

The standard-library scripts require Python 3.13+; invoke them with uv. They do not start
agents, schedule stages or decide whether reasoning is correct.

- [snapshot.py](scripts/snapshot.py): export explicitly selected Git revisions and their diff.
  Requires Git supporting `check-attr --source`. Unsupported LFS/submodule/export-attribute
  cases need explicit source preparation by the agent; failures explain what is missing.
- [evidence.py](scripts/evidence.py): seal and verify complete evidence packages and dependencies.
- [registry.py](scripts/registry.py): freeze scope, reserve IDs and validate assignments/results.
  Binding and retries require coordinator-captured host evidence. Uses POSIX file locks.
- [report.py](scripts/report.py): validate structural proof requirements and render HTML/Markdown/JSON.

Fresh independent agents and authorized execution tools are needed to confirm a finding.
Missing capabilities leave candidates unresolved. Cloud infrastructure is optional and must be
authorized; this plugin does not provision it automatically.

## Development

Run `uv sync --frozen` and `uv run --frozen pytest` from this plugin directory for behavioral
tests. The repository's `make check` also runs these tests and checks formatting and lint.

## Calcifier recipe for `regression-hunt`

The [`regression-hunt` Python recipe](skills/regression-hunt/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

This coordinator requires an explicit caller-supplied host_adapter_argv for genuine primitive fresh-agent launch, messaging, status and interruption. The adapter exchanges the documented JSON request/response for one operation at a time; Python owns campaign progression and validation. Tracked command mutation flags protect hard dry runs. A worker agent configuration alone does not provide this host integration.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/regression-hunt/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/regression-hunt/.calcifier/recipe.py` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `changes` | `list[Change]` | Required |
| `campaign` | `str` | Required |
| `limits` | `Limits` | Required |
| `retries` | `dict[str, str]` | Required |
| `host_adapter_argv` | `list[str]` | Required |

Use published Calcifier 0.2.0 and an external `--output-dir` parent. `campaign` names the campaign directory under that output root; it must stay outside every target checkout. Required inputs are `changes`, `campaign`, `limits`, `retries`, and `host_adapter_argv`. Each `changes` item is `{input,repository,s0,s1}`: the original change description and an existing local Git checkout with resolvable comparison refs. The host resolves repository and both commits, freezes the complete original/resolved descriptor in scope.json, and rejects changed scope on resume. No automatic fetch or installation permission is implied.

`limits` requires positive `attempts`, `polls`, `candidates`, and `handoff_bytes`, `seconds` in (0,3400], an `execution` description, `parallelism:1`, and `deduplicate` boolean. This recipe runs stages serially within those explicit bounds. Attempts count only new reservations/retries; intact accepted evidence can be reused at the limit. `retries` is an assignment-ID to changed-circumstances explanation mapping; use `{}` for ordinary initial/resume work. Retry requires actual terminal evidence and dependent assignments must be revalidated.

`host_adapter_argv` is an explicit argv array for a caller-owned primitive JSON adapter. One request arrives on stdin: `{capability,arguments,filesystem}`. Capability is exactly `codex.spawn_agent`, `codex.send_message`, `codex.list_agents`, or `codex.interrupt_agent`. Arguments are the actual primitive operation arguments. Filesystem context, when supplied, contains `working_directory`, `readable_paths`, and `writable_paths`; the adapter must enforce those restrictions. Return the exact genuine native response object on stdout, without implementing workflow progression or inventing identities, completion or isolation. Spawn returns its actual `task_name`; status returns genuine `agents` entries with `agent_name` and `agent_status`. A worker agent configuration alone does not supply this integration. Spawn/message/interrupt commands are tracked as mutating; status calls are read-only. No manual side-effect API or unsupported tool-config flag is needed.

Python reserves assignments, prepares pristine source snapshots and report skeletons, binds actual launch receipts before release, allocates candidate IDs, routes distinct stage contexts, checks/accepts sealed records and preserves retry history. Fresh workers receive full revision-specific guidance and only their own writable work area, with an explicit result record. The final result includes report paths, coverage and blockers; zero inspected discovery work fails after retaining the result. Compiler stubs cannot certify real host-adapter lifecycle behavior, and no live campaign execution or trust grant was performed.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
