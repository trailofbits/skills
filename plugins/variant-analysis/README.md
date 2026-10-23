# Variant Analysis

Find similar vulnerabilities and bugs across codebases using pattern-based analysis.

**Author:** Axel Mierczuk

## When to Use

- Hunt for bug variants after finding an initial vulnerability
- Build CodeQL or Semgrep queries from a known bug pattern
- Perform systematic code audits across large codebases
- Create reusable patterns for recurring vulnerability classes

## What It Does

A five-step process: extract the root cause, write a pattern matching only the known bug,
generalize it one element at a time, triage what it finds, and report.

Each step has its own strategy reference under `skills/variant-analysis/references/`.

## Entry Points

| | Use when |
|---|---|
| `/variant-analysis:variants` | Workflow, for a large codebase or a root cause with many manifestations. Runs the steps across parallel subagents, one per expansion axis (generalizing variable names, function names, sink APIs, …), looping until the sweep stops finding anything new. Takes `bug`, `root`, `lang`, `out` as a JSON object, which Claude fills from the current context. Below ~40 source files (the primary language's, excluding vendored and fixture trees) it sweeps narrow and once, because fan-out buys nothing at that size. |
| The `variant-analysis` skill | The knowledge behind the workflow, and the path for a narrow hunt you want to drive yourself — a handful of files, pasted snippets, or a candidate list to triage against a known root cause. Both fire on their own from a conversational "are there others like this?"; measured on a real codebase, Claude reaches for the workflow more often than the skill, so ask for the skill by name if you want to weigh in on each generalization. |

## Included

- Tool selection guidance (ripgrep, Semgrep, CodeQL)
- Ready-to-use CodeQL and Semgrep templates for Python, JavaScript, Java, Go, and C++
- A report template, and the pitfalls that most often cause hunts to miss variants

## Installation

```
/plugin install trailofbits/skills/plugins/variant-analysis
```

## Related Skills

- `codeql` — deep interprocedural variant analysis
- `semgrep` — fast pattern matching for simpler variants
- `sarif-parsing` — process variant analysis results

## Calcifier recipe for `variant-analysis`

The [`variant-analysis` Python recipe](skills/variant-analysis/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/variant-analysis/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/variant-analysis/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `project_directory` | `str` | Required |
| `original_issue` | `str` | Required |
| `seed_file` | `str` | Required |
| `seed_line` | `int` | Required |
| `language` | `Literal['python', 'javascript', 'java', 'go', 'cpp']` | Required |
| `codeql_database` | `str` | `''` |
| `rounds` | `Literal[2, 4]` | `2` |

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
