# Infer Pulse: C, C++, Objective-C, and Configured Java

Use Pulse taint analysis rather than the deprecated Quandary checker or annotation
reachability. Annotation reachability checks calls, not value flow. Preserve the
project's build/capture setup and inspect capture failures before interpreting
results.

For plain C functions, native JSON can describe the following policy:

```json
{
  "pulse-taint-sources": [
    {"procedure": "request_value", "kinds": ["Request"], "taint_target": "ReturnValue"}
  ],
  "pulse-taint-sinks": [
    {"procedure": "execute_command", "kinds": ["Shell"],
     "taint_target": ["ArgumentPositions", [0]]}
  ],
  "pulse-taint-policies": [
    {"short_description": "Request data reaches shell execution",
     "taint_flows": [{"source_kinds": ["Request"], "sink_kinds": ["Shell"]}]}
  ]
}
```

`procedure` is a substring matcher. Inspect which captured procedures matched;
use the installed version's more precise class/method or regex matcher if names
collide. Infer regex syntax is OCaml syntax, not Python/PCRE. For instance methods,
argument position `0` is `this`/`self`, so the first explicit parameter usually
needs a different position. Bind the actual procedure signature rather than
copying C positions into Objective-C or Java models.

For a small C fixture, capture and analyze without running the produced program:

```bash
infer --version
infer run --pulse-only --pulse-taint-config taint.json \
  --results-dir infer-out -- clang -c probe.c -o probe.o
```

The project's normal capture command replaces the fixture compiler command.
Use separate baseline/enriched result directories so cached captures and previous
reports cannot masquerade as current results. Preserve `report.json`, capture
logs, captured file/procedure counts, and taint traces. The helper can ingest the
native report with `--native-output`; issue-free reports do not establish coverage.

Pulse supports kind-specific policies. Add sanitizer kinds only to policies they
actually satisfy, and target returns versus mutated arguments accurately. Do not
enable opaque-file exclusions or source-skipping options to make findings vanish.

Require a positive native `TAINT_ERROR` and literal negative, plus a two-function
fixture for interprocedural claims. Test receiver positions and output aliases.
Experimental support advertised for other Pulse languages is not enabled by this
skill without its own graph and native capability contract.

Sources: [Pulse taint CLI schema](https://fbinfer.com/man/1.2.0/infer-analyze.1.html),
[Infer capture/run interface](https://fbinfer.com/man/1.2.0/infer.1.html),
[Pulse checker](https://fbinfer.com/docs/checker-pulse/).
