---
name: taint-trace
description: "Improves taint-analysis coverage and precision by using Trailmark graphs to repair native source, sink, sanitizer, propagation, and type models, then runs an existing taint analyzer. Use when analysis misses flows, cannot resolve framework bindings, or produces false positives from imprecise models."
allowed-tools: Read Grep Glob Bash Edit Write
---

# Taint Trace

Make an existing static taint analyzer understand the codebase's missing contracts.
Trailmark supplies structural evidence; the chosen analyzer computes taint flows.
Every reported flow must identify the analyzer run and the models it depended on.

## Quick Start

Invoke `/trailmark:taint-trace-run` with a target directory. Optional arguments
select languages, backend overrides, and a sink focus. The dynamic workflow owns
the staged execution; the contracts here also apply on hosts executing this skill
directly.
When invoking the workflow from this loaded skill, pass `skill_dir: "{baseDir}"`
so its trusted helper/reference location is explicit, including checkout installs.

```bash
bash "{baseDir}/scripts/taint_trace.sh" catalog
bash "{baseDir}/scripts/taint_trace.sh" context \
  --target <target> --languages auto \
  --output <target>/.trailmark/taint-trace/context.json
```

Read the [language and backend catalog](references/catalog.md), then only the
selected backend's reference. Prefer a working taint configuration already in the
project. Otherwise use the catalog's ordered candidates and any requested backend
overrides. A passing capability probe establishes the selected analysis mode;
parser support and exit status alone do not.
The launcher runs the helper through `uv`, using `trailmark>=0.7.1,<0.8` from the
package index. Native analyzers are separate dependencies.

## Required Graph Evidence

The helper directly checks `entrypoint_evidence()`, `entrypoint_candidates()`,
`source_policy()`, attack-surface, diagnostics, and traversal APIs. Keep these
capability checks even with the release dependency. Read
[graph evidence](references/graph-evidence.md) for binding and snapshot contracts.
An incompatible installation is a setup failure; it cannot be replaced with
LLM reachability guesses.

Inspect callers, callees, source spans, unresolved calls, dependency boundaries,
and entrypoint evidence around dangerous sink arguments and external-input accessors.
Use the graph to select relevant source for reasoning. Keep the analyzer's target
scope broad enough to retain other entrypoints and alternative paths.

Entrypoint evidence can be a heuristic, an ambiguous binding, or a reference whose
runtime consumer is unknown. Confirm which parameter, return, field, or receiver
carries external data. A callback registration does not itself establish execution;
a reachable function does not imply a tainted return value. Preserve these unknowns
in model provenance and the report. References and deferred calls must remain
distinguishable from confirmed calls.

## Model Contracts

- Add the smallest supported contract that repairs an observed modeling gap.
  Prefer native attributes/docblocks when supported; otherwise use native stubs,
  configuration, semantics, or rules. Comments the analyzer ignores are not models.
- Establish why the analyzer needs the contract: retain baseline evidence of a
  missing binding, unresolved type, opaque boundary, or precision problem, and
  state the expected observable effect. Source evidence can justify a contract
  without showing that it adds value. Leave already understood wrappers unchanged;
  there is no annotation quota. See [model quality](references/model-quality.md).
- Anchor each model to its declaration and exact affected value, vulnerability
  context, source evidence, assumptions, and native artifact. Graph node identities
  and line numbers belong to a snapshot; rebind after edits.
  When native tags leave conditions or context limits unclear, explain them in a
  short adjacent comment. Keep detailed graph evidence in the provenance artifacts.
- Explain propagation with the implementation or dependency contract. Do not create
  a parameter-to-return summary solely because a call path would otherwise break.
- A sanitizer removes only the threat it actually prevents, under the required
  conditions and for the correct value. HTML escaping does not sanitize SQL or
  shell commands. A boolean validator is not an unconditional sanitizer. When the
  backend cannot express the distinction, omit the sanitizer model and record the
  limitation.
- Add type hints only when supported by source evidence and useful for analyzer
  resolution. Prefer documentation-only types when a runtime hint would change
  accepted values. Preserve application behavior, existing annotations, and existing
  analyzer configuration. Merge additions idempotently; do not widen exclusions,
  add suppressions, overwrite user models, or introduce runtime taint instrumentation.
- Keep language boundaries explicit. Separate native findings may have a graph
  relationship without forming an analyzer-proven cross-language taint trace.

## Native Execution and Artifacts

Keep a baseline run before adding models and an enriched run afterward. Validate
native model syntax and use real positive/negative capability fixtures for the
selected language and backend. Required contracts are in
[artifact handling](references/artifacts.md). The helpers extract evidence and
validate artifacts; they do not implement a taint engine or certify model semantics.
Inspect analyzer startup before discovery, version checks, builds, or analysis:
autoloaders, plugins, compiler extensions, and configuration hooks can execute
target code. Use trusted tooling and backend-supported isolation; record explicit
hooks and any remaining execution assumptions. Static analysis is not a sandbox.
Pass the baseline validation gate before modifying source or models. Rebuild
context after edits while retaining the original snapshot; findings produced with
added contracts remain conditional on those documented assumptions.

Store context, model provenance, native configuration, native outputs, and a readable
report in the target's `.trailmark/taint-trace/`. Preserve source snapshots and native
traces/SARIF where available. Record exact tool versions, commands, effective target
coverage, exclusions, model changes, and finding changes.
Keep captured evidence out of native source/rule discovery, including tools that
scan unknown extensions; duplicate declarations can silently hide findings.
Native warning counts are not unique flows or coverage. Inspect native traces for
duplicate wrapper locations and shared-helper context merging before claiming a
recovered flow or precision improvement. Model review establishes neither utility
nor coverage; leave benefit unmeasured without native comparison evidence.

Distinguish analyzed, limited, skipped, and failed components. Single-function
engines are useful but must be labeled limited. Skipped languages,
missing extensions, unbound models, parse errors, and empty scans cannot become
clean results. A fully skipped run has performed no taint analysis.

## Backend References

| Backend | Read when selected |
| --- | --- |
| Psalm | [PHP docblocks, stubs, and taint flow](references/psalm.md) |
| Pysa | [Python model files and configuration](references/pysa.md) |
| Clang Static Analyzer | [C/C++ taint configuration](references/clang.md) |
| Infer Pulse | [C-family/Java capture and taint policies](references/infer.md) |
| Joern | [Native dataflow queries and custom semantics](references/joern.md) |
| Checker Framework | [Existing Java tainting configurations](references/checker-framework.md) |
| Semgrep CE/Pro | [Taint rules, language gates, and engine scope](references/semgrep.md) |
| OpenGrep | [Compatible rules and intrafile analysis](references/opengrep.md) |
| CodeQL | [Native model packs and query configuration](references/codeql.md) |

## Rationalizations to Reject

| Rationalization | Why it fails |
| --- | --- |
| "Trailmark's tainted subgraph proves the flow" | It is call reachability; require a native analyzer finding for a taint claim. |
| "The helper is named sanitize, so it is safe" | Names do not establish context, output handling, or conditional behavior; inspect the implementation. |
| "The tool parsed the language, so taint works" | A frontend can parse while omitting dataflow; require the expected positive and negative fixture outcomes. |
| "No findings means the project is clean" | Missing models, ignored files, tool errors, and limited analysis all produce silence; retain measured coverage and gaps. |
| "Annotate every argument to connect the graph" | Wrong source/sink positions manufacture findings and hide actual contracts; bind the affected value. |
| "The annotation is correct, so it improves analysis" | The analyzer may already understand the body; require a modeling-gap hypothesis and native evidence of benefit. |
| "More warnings means more coverage" | New locations can repeat existing flows or reflect context merging; compare native traces and preserve positive/literal-negative behavior. |
| "It only asks for the version" | Startup can load project hooks before handling the flag; apply the backend's startup controls first. |
| "Suppress it so the new configuration passes" | Suppressions conceal unresolved modeling or application defects; report them instead. |
