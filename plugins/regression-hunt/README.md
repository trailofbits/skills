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

## Calcifier recipe for `report-regressions`

The [`report-regressions` Python recipe](skills/report-regressions/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/report-regressions/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/report-regressions/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `campaign` | `str` | Required |
| `attempt` | `str` | Required |
| `guidance_handoff` | `str` | `''` |

Invoke report_regressions(campaign, attempt, guidance_handoff=""). campaign is the campaign root; attempt is an already genuinely bound report-stage assignment for change "campaign", candidate null, with its assigned directory attempts/<attempt> and frozen scope/campaign/progress plus accepted sealed evidence assigned as input. The stage never reserves, binds or accepts itself.

guidance_handoff, when needed, is a campaign-relative path to an already assigned, hash-bound JSON file with shape {"<change-id>": {"s1": "<full immutable SHA>", "absent": ["AGENTS.md", "PATCHING_GUIDELINES.md", "THREAT_MODEL.md"]}}. Include only actually absent names; omit present names. Change keys must be in frozen scope. Each entry permits only s1/absent. All available accepted-preparation, structured scope-input and supplied handoff pins must agree.

Guidance copies under guidance/<change>/<S1>/<name> must be assigned and hash-bound. A complete accepted immutable S1 export can supply guidance or establish absence; otherwise an unaccounted document is fetched only from the pinned Git object when the real repository is available. A missing target pin, incomplete handoff or unavailable guidance blocks with the exact gap. This allows honest incomplete-campaign reporting without inventing preparation.

Outputs are attempts/<attempt>/reports/report.json, report.md and index.html plus attempts/<attempt>/report-stage.json and its seal. Return fields are status, reports (campaign-relative paths), result (coverage/outcome summary), and blocker. Complete describes report-stage completion; the campaign may still contain incomplete coverage or UNRESOLVED findings.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
