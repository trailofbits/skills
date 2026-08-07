# Variant Creation Mechanics and Troubleshooting

The orchestration lives in `workflows/port-rule-to-languages.js` at the plugin root, which
runs as `/semgrep-rule-variant-creator:port-rule-to-languages`. It owns the phase order,
the recheck of a `NOT_APPLICABLE` verdict, and the validation retry. This file holds what
the script cannot encode: the mechanics inside a phase, and what to do when a pattern will
not match or taint will not flow.

## Core Principle: Independent Cycles

The ordering constraint is per language, not global. Within a language the phases are
strictly sequential — applicability decides whether there is anything to do, the tests
specify the rule, and validation is what finishes it — and no phase may start before the
one before it is done.

What must not happen is batching a phase across languages: writing every test file, then
every rule, then validating everything. Errors compound that way and the failure is hard
to attribute. Separate languages are otherwise independent, so one may reach translation
while another is still being assessed, which is how the workflow runs them.

A language whose tests do not pass is unfinished, not "mostly done".

## Annotation Placement

The annotation comment must be on the line immediately before the code it grades. This is
the single most common way a port fails for a reason that has nothing to do with the rule:

```go
// ruleid: my-rule
vulnerableCode()  // this line gets flagged

// ok: my-rule
safeCode()  // this line must NOT be flagged
```

An annotation followed by a blank line, or by another annotation, grades the wrong line.
Semgrep reports that as a missed or incorrect line, which reads exactly like a pattern bug
and sends you looking in the wrong place.

## Reading a Test Failure

`semgrep --test` reports one of three things.

Passing:

```
1/1: ✓ All tests passed
```

Missed lines — the rule did not match where it should have, so the pattern is narrower
than the vulnerability:

```
✗ python-command-injection-go
  missed lines: [15, 22]
```

Check for a pattern that is too specific, a missing pattern variant, or an AST structure
that does not look the way the pattern assumes.

Incorrect lines — the rule matched where it should not have, so the pattern is broader
than the vulnerability:

```
✗ python-command-injection-go
  incorrect lines: [30, 35]
```

Check for a pattern that is too broad, a missing `pattern-not` exclusion, or a sanitizer
the rule does not know about.

## Troubleshooting

### Pattern Not Matching

1. **Dump the AST**: `semgrep --dump-ast -l <lang> file`
2. **Compare structure**: your pattern against the actual AST, not against the source text
3. **Check metavariables**: is each one binding what you think it binds?
4. **Start broader**: match too much on purpose, then narrow until the safe cases pass

### Taint Not Propagating

Run `semgrep --dataflow-traces -f rule.yaml file`. It shows where taint originates, how it
propagates, where it reaches a sink, and where it stops — which is usually the answer.

1. **Check sanitizers**: one that is too broad silently kills the flow
2. **Verify sources**: is the source pattern matching at all? Test it as a plain pattern
3. **Check `focus-metavariable`**: is it on the part of the sink that receives the input?

### Too Many False Positives

1. **Add `pattern-not`**: exclude the shapes that are actually safe
2. **Add sanitizers**: the language's own validation and quoting functions
3. **Use `pattern-inside`**: limit the rule to the context where the risk exists
4. **Re-read the safe cases**: are they actually safe, or is the rule right and the test wrong?

### YAML Syntax Errors

1. **Run `--validate`**: it names the problem
2. **Check indentation**: YAML is whitespace-sensitive and Semgrep's nesting is deep
3. **Quote strings**: anything containing `:`, `#`, `{`, or a leading `*` needs quoting
4. **Use a block scalar**: `|` or `>-` for patterns that span lines
