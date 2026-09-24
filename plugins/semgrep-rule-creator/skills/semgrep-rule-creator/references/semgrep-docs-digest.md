# Semgrep documentation digest

Read this only when the quick reference does not answer a rule-syntax, taint-mode, or
constant-propagation question. It is a short stable guide, not a replacement for the full spec.

## Rule and pattern basics

A rule has an `id`, `languages`, `message`, severity, and either a pattern expression or a mode.
Use `pattern` for one required match, `patterns` for AND, `pattern-either` for OR, and
`pattern-not` or `pattern-not-inside` to exclude safe contexts. Metavariables are uppercase, such
as `$X`; `...` matches intervening syntax; `$...ARGS` matches zero or more arguments.

Keep a rule narrow enough to identify the stated problem. Use `focus-metavariable` when the finding
should be reported on a particular source, sink, or argument rather than a surrounding expression.

## Taint mode

Use `mode: taint` when a source must reach a sink. Put untrusted input in `pattern-sources`, the
dangerous operation in `pattern-sinks`, and only real safe transformations in `pattern-sanitizers`.
`exact: true` limits a source or sanitizer to an exact expression. `by-side-effect` models APIs that
change an argument. Test direct flow, intermediate variables, sanitizer behavior, and safe literals.

## Constant propagation

Semgrep can match a literal through a variable assigned that value. Include direct literals,
assigned constants, and reassigned variables in tests when the distinction affects the rule.
Consult the full documentation for language-specific limits or the `constant_propagation` option.

## Test and debug loop

Use only `ruleid:` for a required finding and `ok:` for a required non-finding, immediately before
the relevant code. `semgrep --test` is the oracle. Use `--dump-ast` for an unexpected parse shape
and `--dataflow-traces` for taint propagation. `--validate` catches invalid configuration but does
not prove behavior.

## Full official documentation

- [Rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Pattern syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax)
- [Testing rules](https://semgrep.dev/docs/writing-rules/testing-rules)
- [Taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode)
- [Advanced taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced)
- [Constant propagation](https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation)
- [Trail of Bits Semgrep chapter](https://appsec.guide/docs/static-analysis/semgrep/)
