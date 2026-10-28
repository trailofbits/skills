# Model quality and demonstrated benefit

Use graph neighborhoods to find contracts worth investigating, then use the native
analyzer to establish what is missing. Keep three questions separate:

- **Correctness:** Does implementation or dependency evidence support the exact
  value binding, vulnerability context, and conditions?
- **Activation:** Did the selected native run load the model and analyze its target?
- **Utility:** Did it recover a previously missing flow, resolve an analysis gap,
  or improve precision while preserving applicable findings?

A model can be correct and active yet redundant. An independent reviewer can judge
its semantics, but cannot establish utility from the diff alone. Prefer no change
when the analyzer already understands the relevant implementation.

## Choosing a useful contract

| Candidate | Evidence to seek before editing | Expected native effect |
| --- | --- | --- |
| Framework-populated parameter or accessor | Host binding and exact affected value; baseline lacks that source binding | A positive boundary-to-sink fixture gains the expected native trace |
| Opaque buffer, queue, or dependency boundary | Serialization/dispatch contract and matching consumer; baseline loses the value at that boundary | Native propagation crosses the modeled boundary without inventing a graph flow |
| Thin wrapper around a modeled builtin | Whether baseline already reports the inner operation and traces through the wrapper | Often no model is needed; an extra warning at the wrapper is not a recovered flow |
| Shared helper used with external and literal values | Helper dependencies and native traces showing unrelated calls merged | A supported context-sensitive summary preserves the positive and removes the literal false positive |
| Unresolved dependency alias or host declaration | Exact versioned declaration/import contract and baseline resolution error | The analyzer resolves the symbol; this alone supplies no source or sanitizer contract |

Names, call reachability, and a quiet baseline are insufficient evidence. Where a
full-project trace is inconclusive, use a small native fixture reflecting the
observed boundary. Keep the vulnerable positive and a literal negative under the
same analyzer setup. For sanitizer claims, also retain a positive in an unaffected
vulnerability context. A reduced fixture demonstrates the tested mechanism; it
does not establish the effect in the full project until that comparison runs.

## Provenance and comparison

New models record a `modeling_gap` alongside their source `evidence`:

```json
{
  "description": "The dependency accessor's return has no native source binding.",
  "baseline_evidence": ["baseline.stderr: unresolved accessor; baseline native trace stops at its return"],
  "expected_effect": "The existing positive boundary-to-command fixture reports the command argument; its literal case stays negative."
}
```

This is an analyst-supplied hypothesis, not a machine-certified improvement. Link
specific diagnostics, configuration, fixture outputs, or native traces. Preserve
failed and inconclusive experiments. The helper validates field structure and
artifact integrity; it does not infer model truth or classify unique taint flows.

Compare native traces, affected values, and vulnerability kinds in addition to
warning locations. Moving a warning, adding a wrapper sink, or merging different
calls through one helper can change counts without exposing a new flow. Unchanged
counts also do not prove redundancy: resolution or trace precision may improve.
Report the evidence and leave benefit unmeasured when it does not settle the claim.

## Setup is part of the result

Resolve dependency declarations before the baseline, then preserve the same setup
for enriched analysis. Record exact stub/alias versions and loaded configuration.
When a native mechanism substitutes a declaration for a bundled implementation,
identify the shadowed body as a coverage gap. A processed file list does not prove
that every body or path in those files was analyzed.

Audit executable startup hooks before running even version/discovery commands.
Keep trusted analyzer installations separate from target bootstrap code and use
the selected backend's supported controls. Do not silently replace explicit
working configuration or describe startup controls as a process sandbox.

An analyzer crash or invalid baseline blocks application modeling. Repair supported
setup, try another eligible backend, or retain a failed component. Offline model
proposals and reviewer approval cannot bypass the baseline mutation gate.
