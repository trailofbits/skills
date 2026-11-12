# Semgrep

Use project-specific `mode: taint` rules. Single-function analysis can model a
known request accessor at its callsite, but it does not turn a Trailmark call path
into a cross-function finding. Record `intraprocedural` scope and a limited
component for that analysis mode. The installed parser list is discovery evidence,
not a taint capability test.

A Python HTML policy can model a return source and one sink argument:

```yaml
rules:
  - id: trailmark.python.request-to-html
    languages: [python]
    mode: taint
    message: Request data reaches HTML output
    severity: WARNING
    pattern-sources:
      - pattern: app.request_value(...)
        exact: true
    pattern-sanitizers:
      - pattern: app.escape_html(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern: app.render_html($VALUE)
          - focus-metavariable: $VALUE
```

Only add the sanitizer after inspecting its implementation and required options.
A separate SQL rule must retain taint through `escape_html`. `exact: true` keeps
nested input expressions from being mistaken for the sanitized result or source.
Mutation models need the correct l-value and native `by-side-effect` semantics;
matching a validator's name does not establish a postcondition. Custom propagators
must describe a real local contract rather than simulate missing interprocedural
analysis.

Use a local rules file and preserve existing ignore/target policy:

```bash
semgrep --version
semgrep show supported-languages
semgrep validate taint.yml
semgrep scan --oss-only --config taint.yml --json \
  --metrics=off --disable-version-check <target>
```

`validate` checks the rule, not whether it finds the vulnerable fixture. Assert
the expected rule ID and location in a real positive and no finding in its literal
negative. Test HTML sanitation and a SQL finding that must survive it. Inspect
structured errors, scanned paths, skipped paths, timeouts, and rules actually
loaded. A `MissingPlugin` error can occur in JSON even with exit status zero.
An empty `results` array alone is insufficient.

The helper supplies language fixtures for supported local probes. A probe passing
for Python does not enable another language, syntax dialect, framework, or engine.
Translate patterns into that language's syntax and exercise the constructs used
by the target. Bash, Lua, R, Julia, Solidity, Circom, and Move remain experimental.
Objective-C is experimental for `.m` files; do not infer `.mm` support. Cairo also
requires a passing language-specific taint contract.

Select `--pro-intrafile` for a proven intrafile contract or `--pro` for the
engine's supported interfile analysis. Verify scope in native output and with a
two-function or two-file fixture. Language and extension support vary; neither
flag establishes interfile analysis without a passing contract.
PowerShell requires Pro's language extension and remains conditional on a passing
PowerShell contract. Retain the native dataflow traces/SARIF when available;
`--dataflow-traces` does not add traces to JSON in every output mode. Do not publish
rules or upload the target as part of local analysis.

Sources: [taint rule syntax](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview),
[value bindings and side effects](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced),
[language scope](https://docs.semgrep.dev/semgrep-ce-languages),
[CLI and output modes](https://docs.semgrep.dev/cli-reference).
