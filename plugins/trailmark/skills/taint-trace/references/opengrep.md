# OpenGrep

OpenGrep accepts compatible Semgrep taint rules and offers cross-function analysis
within a file using `--taint-intrafile`. Use a separate `opengrep` backend record,
version, capability probe, and measured scope. Do not infer cross-file analysis
from this flag or assume every Semgrep rule feature has identical behavior.

VB.NET is experimental. A language-specific native rule can bind a request return
to an execution argument:

```yaml
rules:
  - id: trailmark.vb.request-to-command
    languages: [vb]
    mode: taint
    message: Request data reaches command execution
    severity: WARNING
    pattern-sources:
      - pattern: getRequestValue(...)
    pattern-sinks:
      - patterns:
          - pattern: $R.exec($VALUE)
          - focus-metavariable: $VALUE
```

Bind the real receiver and method from source evidence; this illustrative matcher
is not a claim that every `.exec` method invokes a shell. Check case-insensitive
identifiers, qualified calls, overloads, `ByRef`, and other VB constructs actually
used by the component. Add no sanitizer based on a `getSafe...` naming convention.

Native local commands use the installed binary:

```bash
opengrep --version
opengrep scan --config taint.yml --json <target>
opengrep scan --taint-intrafile --config taint.yml --json <target>
```

Run the appropriate command on a vulnerable fixture and a literal negative, and
check rule ID, location, structured errors, loaded rules, and nonzero scanned paths.
Use an additional two-function same-file fixture before recording `intrafile`
scope; keep a two-file fixture to expose the remaining boundary. A positive in
one function proves only single-function capability. Native rule validation and
annotation-based rule tests can supplement these checks where supported by the
installed release; they do not replace observed taint findings.

For other catalog languages, OpenGrep is an explicit alternative when a local
capability contract passes. Do not enable its Scala or Elixir frontends here:
Trailmark graph coverage is still required. Preserve JSON/SARIF and the exact
engine flags rather than relabeling an OpenGrep run as Semgrep CE.

Sources: [OpenGrep engine and scope](https://github.com/opengrep/opengrep/blob/main/OPENGREP.md),
[native CLI examples](https://github.com/opengrep/opengrep/blob/main/README.md),
[upstream VB taint rule](https://github.com/opengrep/opengrep/blob/main/tests/tainting_rules/vb/tainted_args.yaml),
[upstream VB fixture](https://github.com/opengrep/opengrep/blob/main/tests/tainting_rules/vb/tainted_args.vb).
