# Joern: Native Dataflow Queries and Semantics

Joern builds the CPG and computes `reachableByFlows`. Trailmark supplies source
neighborhoods; its call edges do not become taint findings. Install the official
distribution for the host architecture, retain its version/checksum, and put both
`joern` and `joern-parse` on PATH. Verify each frontend runs on the host platform;
the capability probe fails if it does not.

## Executable Capability Contract

The helper ships built-in native fixtures for C, C++, C#, Go, Java, JavaScript,
Kotlin, PHP, Python, Ruby, Swift, and TypeScript. Execute the selected language's
fixture through the common probe:

```bash
bash "{baseDir}/scripts/taint_trace.sh" probe \
  --backend joern --language python \
  --output <artifacts>/joern-python-probe.json
```

`--executable <joern-root>/joern` selects a specific installation. The probe
invokes its sibling `joern-parse`, then runs its generated `trace.sc` query in a
persistent workdir. Source, CPG, frontend logs, native paths, JSON, exact commands,
and native version remain available for inspection. A frontend that produces an
empty graph or unresolved sanitizer call fails the probe.

For an inspectable custom contract to adapt, use
`uv run --no-project "{baseDir}/scripts/joern_fixture.py" --language python --output <artifacts>/joern-python`.
The result can be passed to `probe --contract <artifacts>/joern-python/contract.json`;
ordinary built-in probes do not need this extra generation step.

Each language tests five positive sink sites: direct input, a variable alias,
an ignored sanitizer return, HTML-escaped input reaching SQL, and a return through
the implemented `relay_value` function. Literal input and HTML-escaped output are
negative sites. The cross-function trace must actually enter `relay_value`; there
is no generated propagation summary for that function. Passing these fixtures
establishes these constructs on the installed frontend, not arbitrary callbacks,
reflection, framework dispatch, dependency resolution, or cross-language flow.

Run the contract for each selected language and installation; another frontend's
passing result is not a capability proof.

## Native Queries and Context-specific Semantics

The generated query contains the complete export implementation. Its essential
operations are native Joern calls:

```scala
val sources = cpg.call.nameExact("request_value").toList
val sinks = cpg.call.nameExact("html_output").argument(1).toList
val cleanerNames = cpg.call.nameExact("html_escape").callee.fullName.toList.distinct
val extra = cleanerNames.map(FlowSemantic.from(_, List((0, 0), (1, 1))))
val policy = DefaultSemantics().plus(extra)
val paths = sinks.iterator.reachableByFlows(sources)(EngineContext(policy)).toList
```

The HTML policy omits argument-to-return flow for `html_escape` while preserving
the original argument and receiver. The SQL policy includes `(1, -1)`: HTML
escaping does not remove SQL taint. Each query uses its own `EngineContext` and
imports a separate copy of the original CPG. The fixture's C/C++ and Java external
cleaner declarations represent an explicit pure HTML-escaping contract; the other
fixtures include an implementation. These are assumptions for the fixture, not
models to copy into an application without inspecting its source.

Joern indices are `-1` for return, `0` for receiver, and positive integers for
explicit arguments. They are not AST `order` or another analyzer's indices. Missing
mappings in an explicit semantic kill those flows, so retain all unaffected
arguments and receivers required by the implementation. Never bind semantics to
`<unknownFullName>`: that name can represent many unrelated calls. Require resolved
native callees and use their qualified names/signatures in production models.

Use normal `joern-parse` frontend processing:

```bash
joern-parse <target> --language PYTHONSRC --output cpg.bin
joern --script trace.sc --param cpgFile=cpg.bin --param outFile=joern.json
```

`--nooverlays` can disable language-specific post-processing.
In particular, Ruby needs those passes to resolve calls and apply its semantics.
The fixture query supplies its policies to the native query engine after those
passes. If changing how dataflow overlays are built, repeat all capability cases
with the resulting CPG and policy rather than assuming parsing establishes flow.

## Coverage and Locations

The query exports native paths in the accepted
`{tool: "joern", findings, scanned_files, errors}` envelope. Locations come from
native path elements. Resolve relative CPG filenames against `cpg.metaData.root`,
not the query's working directory. The exporter excludes the frontend-created
`<…>`, `N/A`, `/`, and `builtintypes` pseudo-files; any other missing inventory path
fails. Compare real CPG source files with the intended target and retain frontend
diagnostics and exclusions. CPG presence alone cannot prove a file parsed fully.

The C# exporter converts Roslyn's zero-based lines. The supplied exporter adds one
for this frontend and preserves `native_line` on each finding and trace element.
The capability anchors test that conversion against the source bytes, so a changed
frontend location convention fails the proof instead of silently shifting findings.
Do not apply this correction to other frontends.

For production, populate `errors` from frontend/query failures and inspect native
logs as well as the envelope. The fixture exports an empty errors list only after
its required query, source locations, and file inventory checks succeed. Preserve
the CPG, query, human-readable native paths, and JSON together. Call-depth limits,
unknown external-call propagation, omitted code, and unresolved calls remain
explicit analysis limitations.

Sources: [native dataflow queries](https://docs.joern.io/cpgql/data-flow-steps/),
[semantics and argument mappings](https://docs.joern.io/dataflow-semantics/).
