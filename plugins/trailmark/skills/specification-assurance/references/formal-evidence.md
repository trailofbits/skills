# Graph and formal evidence

## Trailmark capabilities

Formal language support is targeted for **Trailmark 0.9.0**. Lean, Dafny, F*,
Rocq/Coq, WhyML, TLA+, Tamarin, and ProVerif are merged on upstream main. A checkout
can still report `0.8.0` while containing these parsers. Probe the installed
capabilities as well as the version; a release number alone does not establish
which frontends are available.

```bash
uv run --with trailmark python - <<'PY'
from importlib.metadata import version
from trailmark.parse import detect_languages, supported_languages
print(version("trailmark"))
print(supported_languages())
print(detect_languages("<target>"))
PY
```

When 0.9.0 is published, use that release or newer for the new frontends. Before
then, use a user-provided checkout or an explicitly selected pinned upstream
revision if the required parser is present. Run snippets with
`uv run --with <trailmark-checkout> python -`. Record the commit and package origin.
Git checkouts need `npm ci` in the Trailmark checkout before wheel generation;
the pinned Tree-sitter CLI's install script must run (use
`npm ci --ignore-scripts=false` when npm's configuration disables scripts).
Bundled grammar compilation also needs a C compiler. Follow that revision's
installation guide when grammar generation fails. Published distributions carry
the generated grammar sources.
Do not silently install an unmerged PR or claim missing parsers succeeded. The
ordinary implementation graph and Duvet analysis can proceed while unsupported
formal analysis remains a limitation.

Build from the selected source roots and save graph evidence outside source globs:

```python
import json
from pathlib import Path
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("<target>", language="auto")
engine.preanalysis()
summary = engine.summary()
if summary["source_files"] == 0:
    raise RuntimeError("No implementation files inspected")
Path("<run>/graph.json").write_text(engine.to_json())
Path("<run>/source-policy.json").write_text(json.dumps(engine.source_policy(), indent=2))
Path("<run>/diagnostics.json").write_text(json.dumps(engine.parse_diagnostics(), indent=2))
# List the actual production files selected in source_policy(), excluding tests/models.
Path("<run>/graph-scope.json").write_text(json.dumps({"production_files": ["src/packet.py"]}, indent=2))
```

Replace the example production list with the target's inspected production paths.
The native summary includes tests and models; the workflow's `source_files` count
and finalizer's `--production-source-files` argument count only this production list.
The finalizer reconciles the native graph, source policy, diagnostics, inspected
paths, and parsed production nodes. A positive count in an agent response cannot
replace these artifacts.

Inventory formal extensions independently of `detect_languages()` and reconcile
them with selected/inspected files. Parse separate roots explicitly when repository
layout or source policy would exclude formal models. Inspect `callers_of()`,
`callees_of()`, `entrypoint_paths_to()`, `unresolved_calls()`, source spans, and
`paths_between()` around the requirement's enforcement. Resolve overloaded names
to exact node IDs before querying. Save focused query results alongside the graph:
the JSON export does not preserve every query's evidence or call-site information.

Use `edge_kinds=("references",)` with `reachable_from()`, `ancestors_of()`, or
`paths_between()` for formal declarations where supported. Ordinary traversal
defaults to `calls`; proof/type dependencies are often **references**, not runtime
calls. Preserve edge confidence, context attributes, and diagnostics. Missing
edges can reflect unavailable imports, tactics, elaboration, or parser limits.
Declared repository links and `corresponds_to` edges express a relationship; they
do not prove refinement or equivalence.

## Language routes

These identifiers match the released Rust parser and the formal frontend
registrations on upstream main. Probe `supported_languages()` before selecting one.
Use the project's existing pinned verifier commands and dependencies rather than
inventing a universal command for every toolchain version.

| Language / files | Trailmark selector | Native evidence and limits to retain |
| --- | --- | --- |
| Lean 4 `.lean` | `lean` | Lean/Lake checks of the named theorem and its actual statement; `sorry`, axioms, unsafe declarations, imported assumptions, and elaboration configuration. Source references omit tactic/elaborated dependencies. |
| Dafny 4 `.dfy` | `dafny` | Dafny verification of methods/lemmas/contracts; unchecked declarations, `assume`, axiomatic declarations, verification-disabled regions, solver limits, and extraction/compiler settings. |
| F* `.fst`, `.fsti` | `fstar` | F* checks of the relevant refinement/lemma with its options; admits/assumptions, lax checking, effects, extraction settings, and correspondence between interfaces and implementations. |
| Rocq/Coq `.v` | `rocq` | Native compiled proofs and assumptions of the target theorem; `Admitted`, axioms, opaque dependencies, extraction configuration, and the selected Rocq/Coq toolchain. Source dependency graphs do not reconstruct kernel proof terms. |
| WhyML `.mlw`, `.why` | `whyml` | Why3 sessions and every relevant verification condition's prover/status; unproved goals, timeouts, transformations, clone expansion, and imported theories. |
| TLA+ `.tla` | `tlaplus` | TLC/Apalache results or TLAPS proofs of the named invariant/temporal property; constants, bounds, fairness, constraints, explored states, deadlocks, and unfinished obligations. Finite model checking is bounded evidence. |
| Tamarin `.spthy` | `tamarin` | Native lemma results under the exact theory, restrictions, attacker model, and tool options; unfinished proofs and an executability witness for expected protocol traces. Symbol references are not rule execution traces. |
| ProVerif `.pv`, `.pvl` | `proverif` | Native result for each exact query, including false or cannot-prove results, equations, attacker assumptions, libraries, and reachability of relevant events. A parseable query is not a proved query. |
| Rust/Verus `.rs` | `rust` | Native Verus checks, with the selected Rust/Verus versions, of the actual executable definitions and their contracts; `assume`, external bodies, trusted dependencies, ghost boundaries, and compiler/extraction assumptions. |

Trailmark does not run these verifiers. Preserve the native command, environment,
property identity, source revision, stdout/stderr, exit status, and per-obligation
outcome. Exit zero alone is insufficient: a tool may admit obligations, check a
different module, or report an inconclusive property. A proof over contradictory
preconditions or unreachable authentication events can be vacuous.

## Connecting a proof to the implementation

A formal check can have scope `model` or `implementation` in the ledger. To claim
the latter, document which production definitions the checked property governs:

- **Same verified executable definitions:** connect the proved contracts to the
  production entrypoints and actual build. Retain trusted/external code and the
  compiler/runtime assumptions.
- **Extracted/generated code:** retain extraction command, source/model revisions,
  generated artifact hashes, compiler options, and evidence the production build
  uses those artifacts without unverified edits or wrappers that break the contract.
- **Separate model and implementation:** a refinement/equivalence argument must
  relate concrete state, transitions, error paths, encodings, concurrency, and trust
  boundaries to the abstract model. Tests against model-derived known answers add
  useful evidence but do not themselves establish a refinement proof.

If only the design was proved, retain that successful result with scope `model`
and describe the missing implementation binding. Continue assessing production
code with implementation tests. Do not promote the model result to implementation
evidence or relabel an axiom as an implementation.

Primary parser references: [language documentation](https://github.com/trailofbits/trailmark/blob/main/docs/languages.md),
[Lean #134](https://github.com/trailofbits/trailmark/pull/134),
[Dafny #138](https://github.com/trailofbits/trailmark/pull/138),
[F* #139](https://github.com/trailofbits/trailmark/pull/139),
[Rocq #140](https://github.com/trailofbits/trailmark/pull/140),
[WhyML #141](https://github.com/trailofbits/trailmark/pull/141),
[TLA+ #142](https://github.com/trailofbits/trailmark/pull/142),
[Tamarin #143](https://github.com/trailofbits/trailmark/pull/143), and
[ProVerif #144](https://github.com/trailofbits/trailmark/pull/144).
