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

## Calcifier recipe for `reproduce-regression`

The [`reproduce-regression` Python recipe](skills/reproduce-regression/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/reproduce-regression/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/reproduce-regression/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `campaign` | `str` | Required |
| `attempt` | `str` | Required |
| `plan` | `Plan` | Required |

Invoke reproduce(campaign, attempt, plan) for an already genuinely bound reproduce assignment containing accepted complete preparation/discovery, the candidate and complete sealed source/dependency evidence. The function derives its owner from the original retained launch binding; it does not create or bind an assignment. Set the recipe output directory to the campaign root for new attempts. Campaign evidence/record paths are relative to that root; output is attempts/<attempt>/reproduce.json plus seal, setup/data, raw command streams, observations, disposition, analysis and private build/S0 and build/S1 trees.

plan is the required typed Plan: authorized:boolean; mode:"live" or "build_test"; commands:[{state:"S0"|"S1",phase:"metadata"|"setup"|"build"|"deploy"|"cleanup"|"resources",argv:[string,...],timeout:positive number}]; poc_argv:[string,...]; timeout:positive number; deployments:[S0 interface string,S1 interface string]; data:{"poc.py":nonempty portable source,"workload.json":nonempty input text,"configuration.json":nonempty common configuration text}; environment:{name:value}; outputs:[attempt-relative additional output paths]. Supply metadata, setup, build, cleanup and resource-inspection commands for each state; live mode also requires deploy commands. The host adds one PoC run for each state after its listed non-cleanup commands.

Caller argv can use {poc}, {workload} and {deployment}; the host substitutes owned data paths and that state's interface. poc_argv must contain all three tokens. Target commands run in the state's owned build directory; explicit cleanup/resource commands run there after the attempted experiment. The same host-persisted PoC, input and common configuration are used for both states. Return value contains status, record, result and blocker; complete means the experiment finished.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
