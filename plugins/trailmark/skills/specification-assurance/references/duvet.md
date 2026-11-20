# Duvet setup and annotation

Use the installed CLI's help and the [official guide](https://awslabs.github.io/duvet/)
for supported options. Install with `cargo install duvet --locked` when missing.
If Cargo is unavailable, install a Rust toolchain using the project's normal
bootstrap method and retry. Record the resolved Duvet package version and origin
from `cargo install --list` or the project's lockfile; some builds have no
`duvet --version`. Do not replace a working installation unnecessarily.

## Configuration

Run from the implementation root. For a new Python project, for example:

```bash
duvet init --lang-python --specification spec/protocol.md
```

For existing projects, edit the configuration instead of expecting `init` to merge
new specifications into an existing file. Its default language patterns are only
a starting point; Python's default `src/**/*.py` does not include `tests/`.

```toml
'$schema' = "https://awslabs.github.io/duvet/config/v0.4.0.json"

[[source]]
pattern = "src/**/*.py"
comment-style = { meta = "##=", content = "##%" }

[[source]]
pattern = "tests/**/*.py"
type = "test"
comment-style = { meta = "##=", content = "##%" }

[[specification]]
source = "spec/protocol.md"
format = "markdown"

[report.html]
enabled = true
path = ".duvet/reports/report.html"

[report.snapshot]
enabled = true
path = ".duvet/snapshot.txt"
```

Duvet supports Markdown and IETF specifications. Retain immutable local copies or
revision-pinned URLs and hashes, including errata and the chosen protocol profile.
For PDF/HTML-only specifications, preserve the original and a faithful text
transcription with section/page provenance. Do not silently rewrite its normative
meaning to suit extraction. Register obligations without RFC keywords explicitly
using a requirement TOML file:

```toml
[[spec]]
target = "spec/protocol.md#rejection"
level = "MUST"
quote = "Rejection leaves the state unchanged."
```

The default requirement roots include `.duvet/requirements/**/*.toml`,
`.duvet/todos/**/*.toml`, and `.duvet/exceptions/**/*.toml`. Add a `[[requirement]]`
pattern for files elsewhere. Read Duvet's extracted requirement files against the
scoped document: lowercase obligations, tables, formulas, and conditional clauses
can need explicit registration. Keep the original quote and record any subordinate
obligations in the ledger rationale.

## Comment styles

Use explicit source patterns and markers for formal sources. The configuration
below handles a ProVerif directory even on Duvet versions without
`init --lang-proverif`. Add a separate `**/*.pvl` pattern if libraries are in scope.

```toml
[[source]]
pattern = "formal/**/*.pv"
comment-style = { meta = "*=", content = "*#" }
```

```text
(*
 *= spec/protocol.md#authentication
 *# A receiver MUST authenticate a message before accepting it.
*)
```

Keep delimiters on their own lines so closing comment syntax cannot contaminate
the quoted requirement. The same block interior works for Rocq (`.v`), F* (`.fst`,
`.fsti`), and WhyML (`.mlw`, `.why`) inside their `(* ... *)` comments. Useful line
markers for other languages:

| Source | `meta` | `content` | Native comment form |
| --- | --- | --- | --- |
| Lean `.lean` | `--=` | `--#` | `--= spec/protocol.md#section` |
| Dafny `.dfy`, Rust/Verus `.rs`, Tamarin `.spthy` | `//=` | `//#` | `//= spec/protocol.md#section` |
| TLA+ `.tla` | `\\*=` | `\\*#` | `\*= spec/protocol.md#section` |

The TLA+ cells show TOML basic-string escaping: use
`comment-style = { meta = '\*=', content = '\*#' }` with TOML literal strings,
or double the backslash inside basic strings. A custom marker configures Duvet's
text scanner, not a Trailmark parser or verifier. Demonstrate that the annotation
appears in the native report before relying on any custom style.

## Honest annotations

Place an implementation citation beside the actual enforcement, and a test
citation beside the assertion that checks it. Use the complete original quotation:

```python
##= spec/protocol.md#length
##% A packet MUST contain at most 16 bytes.
def accepted(packet):
    return len(packet) <= 16
```

```python
##= spec/protocol.md#length
##= type=test
##% A packet MUST contain at most 16 bytes.
def test_length_boundary():
    assert accepted(b"x" * 16)
    assert not accepted(b"x" * 17)
```

The test's import/setup is project-specific. A formal declaration may be cited as
an implementation of a **model** obligation; label that scope in the ledger. Use
`type=test` for a checked formal obligation only when the native verifier actually
checks that property, preserving the run and model-to-code binding. Do not add a
fictional `type=proof`; Duvet has no such annotation type.

`implication` counts as both implementation and test. Use it only for a property
guaranteed by the relevant construction (including its actual compiler/checker),
not for plausible logic. `exception` needs an existing justified waiver or an
applicability decision; it cannot erase a mandatory defect. Use `todo` to retain
an unimplemented obligation with its reason. Merge citations idempotently and keep
preexisting exceptions visible.

For a `supported` record, the gate requires a citation or implication over every
byte of the original obligation. It uses the union of Duvet's annotated text spans:
overlapping annotations cannot compensate for an uncited clause. Tests, exceptions,
and TODOs do not supply implementation traceability. Complete traceability still
needs the separate semantic and native evidence required by the ledger contract.

## Native reports and CI

Capture help/tool identity first. Retain a baseline before adding citations:

```bash
duvet report --json <run>/duvet-before.json --html <run>/duvet-before.html \
  --require-citations true --require-tests true --ci false
```

Save command output and exit status even on failure. The helper consumes the
legacy JSON produced by `--json`, including on builds that also offer `--json-v2`.
Do not feed v2 data to it or convert an unfamiliar format by guessing.

With snapshots enabled, `--ci false` writes the snapshot. Preserve any existing
snapshot before the baseline, and retain its diff. After adding only defensible
annotations, run again with `duvet-after.json` and `duvet-after.html` paths. Review
the snapshot as an intentional coverage change. For workflow assessments, the calling
session's `finalize` command performs this final native run in a fresh `gate-native-*`
directory; its `gate.json` names the resulting report and log. In subsequent CI runs:

```bash
duvet report --ci --require-citations true --require-tests true
```

A snapshot CI pass means the traceability snapshot matches, even if it already
contains gaps. Pair it with the ledger checker for the assessed revision. Bind
execution logs to their source snapshot. Preserve citation-only diffs and location
mappings; rerun affected commands when behavior, assertions, or proof obligations
change, or mark the evidence stale.
Where supported, `duvet query` can correlate coverage artifacts; feature-probe it
and keep line execution separate from the truth of assertions.

Primary references: [annotations](https://awslabs.github.io/duvet/annotations.html),
[configuration](https://awslabs.github.io/duvet/config.html),
[reports](https://awslabs.github.io/duvet/reports.html), and
[source](https://github.com/awslabs/duvet).
