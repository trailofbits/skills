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
`exact: true` limits a source or sanitizer to the matched expression. Test direct flow,
intermediate variables, sanitizer behavior, and safe literals.

### Advanced capability index

Read the corresponding [advanced taint section](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced)
when the task needs one of these features; check the installed engine and language support.

| Need | Feature and caution |
| --- | --- |
| Container or API-mediated flow | `pattern-propagators`, with explicit `from` and `to`. |
| Multiple taint kinds or multi-stage transformations | Source `label` and source/sink `requires`; experimental semantics need representative tests. |
| Ignore safe primitive types, indexes, or opaque calls | `taint_assume_safe_booleans`, `_numbers`, `_indexes`, `_functions`; each narrows detection, so justify the assumption with positive controls. |
| Interprocedural flow, index sensitivity, control sources, or at-exit sinks | Check Pro-specific capabilities; CE does not provide equivalent coverage. |

Sources with `by-side-effect` taint a focused l-value for later uses; `only` excludes the matched
occurrence itself. Sanitizers with `by-side-effect: true` clear later uses of the focused l-value.
Both need `focus-metavariable` on that l-value. Propagators transfer existing taint from `from` to
`to`; side effects default to true, while false limits propagation to the matched occurrence.

## Constant propagation

Semgrep can match a literal through a variable assigned that value. Include direct literals,
assigned constants, and reassigned variables in tests when the distinction affects the rule.
Consult the full documentation for language-specific limits or the `constant_propagation` option.

## Test and debug loop

Use only `ruleid:` for a required finding and `ok:` for a required non-finding, immediately before
the relevant code. Require nonzero graded positive and negative cases for the rule: an empty
test run can exit successfully. Use `--dump-ast` for an unexpected parse shape
and `--dataflow-traces` for taint propagation. `--validate` catches invalid configuration but does
not prove behavior and may need registry access. Preserve failures as failures or blocked
validation, not evidence that the rule passed.

## Full official documentation

- [Rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Pattern syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax)
- [Testing rules](https://semgrep.dev/docs/writing-rules/testing-rules)
- [Taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode)
- [Advanced taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced)
- [Constant propagation](https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation)
- [Trail of Bits advanced Semgrep guidance](https://appsec.guide/docs/static-analysis/semgrep/advanced/)
