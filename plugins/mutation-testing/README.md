# Mutation Testing

Configure mutation testing campaigns, explain what surviving mutations reveal about tests, and investigate potential bugs in the affected code.

The plugin ships one skill, `mutation-testing`. Invoke it with `/mutation-testing:mutation-testing` or ask for help with a mutation testing campaign or its results.

## Workflows

| Request | What the skill does |
|---------|---------------------|
| Set up or optimize a campaign | Configures mewt or muton, checks target selection, measures test duration, and tunes timeouts and per-target test commands. |
| Analyze completed results | Collects every survivor with its source and tests in one call (`scripts/survivors.py` for mewt/muton results), distinguishes equivalent changes from testing gaps, and recommends specific assertions or inputs in `mutation-testing-report.md`. |
| Investigate potential bugs | Uses survivors to prioritize investigation of the original code. Requires a reproduced proof of concept before describing a bug as confirmed. |

A surviving mutation means the tests did not detect a deliberate change. It can reveal a testing gap or an equivalent implementation. It does not by itself establish a bug in the original code. The analysis workflow recommends test improvements without implementing them.

## Prerequisites

Campaign setup uses [mewt](https://github.com/trailofbits/mewt) or [muton](https://github.com/trailofbits/muton), plus a runnable test suite. Examples follow the mewt 4.x API. Check the installed tool's `--help` for supported flags and language labels. For muton projects, substitute `muton`, `muton.toml`, and `muton.sqlite` in the examples.

Analyzing saved results does not require either tool to be installed. The bundled `scripts/survivors.py` runs with [uv](https://docs.astral.sh/uv/) and reads saved `mewt results --format json` output. Supply the campaign output, the source at the mutation sites, and the relevant tests. The analysis workflow also accepts results from other mutation testing tools.

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

The deterministic checks accept a correct report and reject reports that misclassify either comparison, and check that `survivors.py` reports every captured survivor at its 1-based line (mewt's `line_offset` is 0-based). They test the grader, not the skill's effectiveness. The optional model eval checks the agent's report against the same validator:

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
