# Mutation Testing

Configure mutation testing campaigns, explain what surviving mutations reveal about tests, and investigate potential bugs in the affected code.

The plugin ships one skill, `mutation-testing`. Invoke it with `/mutation-testing:mutation-testing` or ask for help with a mutation testing campaign or its results.

## Workflows

| Request | What the skill does |
|---------|---------------------|
| Set up or optimize a campaign | Configures mewt or muton, checks target selection, measures test duration, and tunes timeouts and per-target test commands. |
| Analyze completed results | Reads the source and tests for each survivor, distinguishes equivalent changes from testing gaps, and recommends specific assertions or inputs in `mutation-testing-report.md`. |
| Investigate potential bugs | Uses survivors to prioritize investigation of the original code. Requires a reproduced proof of concept before describing a bug as confirmed. |

A surviving mutation means the tests did not detect a deliberate change. It can reveal a testing gap or an equivalent implementation. It does not by itself establish a bug in the original code. The analysis workflow recommends test improvements without implementing them.

## Prerequisites

Campaign setup uses [mewt](https://github.com/trailofbits/mewt) or [muton](https://github.com/trailofbits/muton), plus a runnable test suite. Examples follow the mewt 4.x API. Check the installed tool's `--help` for supported flags and language labels. For muton projects, substitute `muton`, `muton.toml`, and `muton.sqlite` in the examples.

Analyzing saved results does not require either tool to be installed. Supply the campaign output, the source at the mutation sites, and the relevant tests. The analysis workflow also accepts results from other mutation testing tools.

## Examples

- "Help me set up mewt for this Rust project."
- "Configure muton for this FunC codebase."
- "My mutation campaign would take 30 hours. Help me reduce its scope."
- "Which of these surviving mutants are equivalent, and what tests are missing?"
- "Investigate the original code around these surviving authorization mutations."

## Validation

The bundled eval uses a captured campaign against a deliberately weak Rust test suite. It requires the agent to distinguish `balance > 0` from two mutations: `balance != 0` is equivalent for `u64`, while `balance >= 0` differs at zero. It also checks authorization, balance-accounting, and logging gaps. The fixture can be analyzed without cargo or mewt.

Run the report-validator tests from the repository root:

```bash
uv run --no-project --with pytest python -m pytest plugins/mutation-testing/tests -q --import-mode=importlib
DETERMINISTIC_ONLY=1 uv run --no-project bash plugins/mutation-testing/tests/smoke-test.sh
```

The deterministic checks accept a correct report and reject reports that misclassify either comparison. They test the grader, not the skill's effectiveness. The optional model eval checks the agent's report against the same validator:

```bash
# Requires Claude Code with plugin eval support and ANTHROPIC_API_KEY.
uv run --no-project bash plugins/mutation-testing/tests/smoke-test.sh
```

The model eval retains reports locally and makes API calls. Its model, judge, run count, and cost ceiling can be set with `MODEL`, `JUDGE_MODEL`, `RUNS`, and `MAX_COST_USD`. A passing fixture does not establish improvement over an agent without the skill.

To reproduce the captured campaign, work on a separate copy:

```bash
mutation_fixture_dir="$(mktemp -d)/vault"
cp -R plugins/mutation-testing/evals/weak-suite-analysis/fixture "$mutation_fixture_dir"
cd "$mutation_fixture_dir"
cargo test
mewt mutate
mewt run
mewt results
```

## References

- [mewt](https://github.com/trailofbits/mewt)
- [muton](https://github.com/trailofbits/muton)
- [Use mutation testing to find the bugs your tests don't catch](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)

## Calcifier recipe for `mutation-testing`

The [`mutation-testing` Python recipe](skills/mutation-testing/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/mutation-testing/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/mutation-testing/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `task` | `str` | Required |
| `project` | `str` | `'.'` |
| `workflow` | `Literal['configure', 'hunt', 'analyze', 'assist']` | `'analyze'` |
| `engine` | `Literal['mewt', 'muton', 'other']` | `'mewt'` |
| `result_files` | `tuple[str, ...]` | `()` |
| `results_scope` | `Literal['all', 'survivors-only', 'unknown']` | `'unknown'` |
| `blockchain` | `bool` | `False` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
