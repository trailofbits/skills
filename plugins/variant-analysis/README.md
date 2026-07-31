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
| `/variant-analysis:variants` | Workflow to run on large codebase or many manifestations. Runs the steps across parallel subagents, one per expansion axis (e.g., generalizing variable names, function names, ...), looping until the sweep stops finding anything new. Takes `bug`, `root`, `lang`, `out` which claude fills using the current context. |
| The `variant-analysis` skill | Triggers on its own when you are working on a bug hunt, including straight after finding one in conversation. Best for a narrow search where you want a say in each generalization.|

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
