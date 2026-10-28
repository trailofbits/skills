# Helper and Artifact Contracts

The helper extracts graph evidence, runs native subprocesses, and checks captured
artifacts. It neither generates application models nor solves taint propagation.
Use `/trailmark:taint-trace-run` for staged orchestration, or use these interfaces
when a host executes the skill directly. Paths below use `<target>` for the target
checkout. Keep run artifacts in its `.trailmark/taint-trace/` directory.
Invoke the shell launcher with `uv` available; it resolves the published
`trailmark>=0.7.1,<0.8` dependency declared by the helper.

## Graph Context and Backend Selection

```bash
bash "{baseDir}/scripts/taint_trace.sh" catalog
bash "{baseDir}/scripts/taint_trace.sh" context \
  --target <target> --languages php \
  --output <target>/.trailmark/taint-trace/context.json
```

`--languages auto` inventories graphable languages. Repeat `--focus NODE` for
bounded neighborhoods around known graph nodes. Context contains `schema_version`,
`target`, Trailmark version, summary, source policy, parse diagnostics, attack
surface, entrypoint evidence/candidates, unresolved calls, graph nodes/edges,
focus contexts, source hashes, and limitations. Preserve the initial snapshot;
re-extract as `rebound-context.json` after source changes.

The context command also retains inspected source and existing configuration bytes
in a sibling `context.json.sources/` directory, with hashes in `source_snapshots`.
Keep these artifacts with the original graph so inline edits remain reviewable;
the helper checks that neither the source changed during extraction nor the stored
snapshots changed afterward.

Source, model, and configuration copies end in `.snapshot` so extension-based
source/rule discovery does not load the evidence as additional inputs. Their
records retain original paths and byte hashes; native commands still load the
original files. Keep the artifact tree outside native discovery when a tool scans
unknown extensions or detects languages by content. Older captures retain source
extensions and must also stay outside native inputs when recapturing a run;
preserve historical evidence rather than renaming it in place.

Backend IDs are `psalm`, `pysa`, `clang`, `infer`, `joern`, `checker-framework`,
`semgrep`, `semgrep-pro`, `opengrep`, and `codeql`. A catalog route is a candidate,
not permission to call an untested backend supported. Graph support is mandatory.

## Capability and Native Run Records

```bash
bash "{baseDir}/scripts/taint_trace.sh" probe \
  --backend psalm --language php \
  --output <target>/.trailmark/taint-trace/psalm-probe.json
bash "{baseDir}/scripts/taint_trace.sh" run \
  --backend psalm --language php --phase baseline --scope interprocedural \
  --cwd <target> \
  --output <target>/.trailmark/taint-trace/php-baseline.json \
  -- vendor/bin/psalm --taint-analysis --debug --no-cache --output-format=json
```

The built-in probes run real Psalm, Joern, and Semgrep/OpenGrep fixtures. Other native
engines require `probe --contract FILE`, with language-appropriate vulnerable and
literal-negative fixtures, native commands, and expected rule/location assertions.
Use a sanitizer and cross-function/cross-file fixture wherever claiming those
behaviors. The probe must check native findings, not just a parser or return code.
An expected anchor can include `rule_id` to require a particular vulnerability
context at that location. The Psalm profile requires `TaintedSql` through HTML
escaping; an HTML finding at the same line cannot satisfy that assertion. The
required contract also checks a direct positive, a literal negative, and a native
cross-function wrapper. Conditional escaping, promoted fields, and named-argument
precision are optional checks whose failures become limitations. Preserve those
results with the passing core proof. The profile retains a separate unmodeled
baseline with no findings, using the same native engine, and validates both native
records when checking the saved proof.

A custom Clang fixture directory can contain this `probe.c`:

```c
extern char *request_value(void);
extern void execute_command(const char *value);
void direct(void) { execute_command(request_value()); }
static void wrapper(const char *value) { execute_command(value); }
void through_wrapper(void) { wrapper(request_value()); }
void literal(void) { execute_command("literal"); }
```

Its `taint.yaml` declares `request_value` return as a source and argument zero of
`execute_command` as a sink:

```yaml
Propagations:
  - Name: request_value
    DstArgs: [-1]
Sinks:
  - Name: execute_command
    Args: [0]
```

A `clang-contract.json` beside `fixtures/clang/` can then contain:

```json
{
  "backend": "clang",
  "language": "c",
  "scope": "translation-unit",
  "fixture_root": "fixtures/clang",
  "commands": [[
    "clang", "--analyze", "probe.c",
    "-Xclang", "-analyzer-checker=optin.taint.GenericTaint",
    "-Xclang", "-analyzer-config",
    "-Xclang", "optin.taint.TaintPropagation:Config={workdir}/taint.yaml",
    "-Xclang", "-analyzer-output=plist", "-o", "probe.plist"
  ]],
  "native_output": "{workdir}/probe.plist",
  "version_command": ["clang", "--version"],
  "expect": {
    "positive": [{"file": "probe.c", "line": 3}],
    "negative": [{"file": "probe.c", "line": 6}],
    "cross_function": [{"file": "probe.c", "line": 4}]
  }
}
```

Run the contract through the helper:

```bash
bash "{baseDir}/scripts/taint_trace.sh" probe \
  --backend clang --language c --contract clang-contract.json \
  --output clang-probe.json
```

This is a contract to execute, not a claim that a particular installed Clang
passed. `fixture_root` resolves
relative to the contract; the helper copies it to a persistent proof workdir and
executes command arrays there. `{workdir}` and `{fixture_root}` placeholders are
available in argv/native-output paths. Every negative file must be reported as
scanned or also contain a positive anchor. Here the wrapper sink demonstrates
the claimed cross-function behavior and the literal case shares its source file.

`run` captures exact argv, working directory, tool version, activated engine, subprocess output,
native artifacts, and hashes. Native JSON on stdout is the default input; use
`--native-output FILE` for a tool-created report such as Infer's `report.json`,
Clang plist, Joern's query export, or CodeQL SARIF. Checker Framework uses native
compiler diagnostics. Repeat `--model FILE` to bind model/configuration snapshots
to the run. Enriched records use `--phase enriched` and a separate output path.

New run records also bind an `execution` artifact containing requested/effective
analysis and version argv, working directory, configuration files, startup policy,
and execution assumptions. For Psalm, an absent explicit `--root` selects a private
empty Composer-discovery root for both commands and an absolute target config;
root-relative configurations using `resolveFromConfigFile="false"` (or `"0"`) fail before
startup. Explicit roots and all other backends remain caller-managed. This controls
automatic discovery, not explicit plugins/autoloaders, interpreter hooks, or process
permissions. Review those hooks before invocation. Full validation requires this
artifact and checks its hash and command binding; historical runs without it must
be recaptured before they can pass the gate.

Allowed scope labels are `intraprocedural`, `intrafile`, `interprocedural`,
`translation-unit`, and `cross-translation-unit`. Choose the scope established by
the actual command and capability test. Unknown native file counts stay unknown;
never copy Trailmark file counts into analyzer coverage. Native finding locations
also do not enumerate all analyzed files. Preserve native traces/SARIF without
requiring conversion from other native formats.

## Manifest

A manifest has `schema_version: 1`, `target`, `context`, `models`, `components`,
and `limitations`. At completion, any added models require `rebound_context`,
pointing to a graph snapshot of the edited source. Keep `context` pointing to the
original evidence. The source hashes make stale snapshots detectable.
Context, probe, and run-record paths resolve relative to the manifest directory.
Model `artifact` paths instead resolve relative to `target`.

Every generated model records:

| Field | Contract |
| --- | --- |
| `id`, `language`, `backend` | Stable model identifier and selected language/backend |
| `role` | `source`, `sink`, `sanitizer`, `propagator`, or `type` |
| `anchor` | `file`, `start_line`, `end_line`, and `node_id` from the original `context` declaration |
| `value` | Exact parameter, return, field, or receiver affected |
| `contexts` | Applicable vulnerability contexts, such as HTML or SQL |
| `evidence` | Nonempty source/contract observations justifying the model |
| `modeling_gap` | New models: analyst hypothesis with nonempty `description`, `baseline_evidence` string array, and `expected_effect` |
| `assumptions` | Explicit unresolved conditions; an empty list is permitted |
| `artifact` | Target-relative path to analyzer-consumed markup or native model file |

Keep the model's provenance anchor bound to the original evidence, even when inline
annotations shift its declaration. `rebound_context` records the edited source and
supports enriched finding locations; it does not replace the original model anchor.

`modeling_gap` is optional for existing schema-version-1 manifests; when present,
its fields are validated. New workflow models include it. It explains why the
native analyzer needs the otherwise justified contract; it does not certify a
benefit. The helper leaves benefit unmeasured. Retain native comparison evidence
for any analyst claim of recovered flow, resolved binding, or improved precision.

Models supplement existing configuration idempotently. The artifact must actually
be loaded by the native command. Unsupported sanitizer distinctions must be
omitted, not represented by blanket untainting; generated sanitizer models for
Clang and Checker Framework are rejected because their generic contracts lack
independent vulnerability kinds.

Each component records `id`, `root`, `language`, `backend`, `scope`, `status`, `reason`,
`probe`, `baseline`, `enriched`, and `gaps`. Active components link a real passing
probe and baseline/enriched run records. Retain original
configuration, exclusions, native diagnostics, and recorded limitations.
Use the component's canonical `root` as the native working directory. Each active
component must overlap graphed source files; another component's graph or enriched
run cannot establish coverage or model loading for it.

| Status | Meaning |
| --- | --- |
| `analyzed` | Native analysis ran with a passing contract and measured coverage supporting the declared scope |
| `limited` | Native analysis ran with explicit limits, including single-function scope or unknown measured coverage |
| `skipped` | No supported graph/backend combination or an intentionally unselected component; state why |
| `failed` | Setup, capability, model-loading, syntax, execution, or artifact error prevented valid analysis |

## Validation and Report

```bash
bash "{baseDir}/scripts/taint_trace.sh" validate \
  --manifest <target>/.trailmark/taint-trace/manifest.json --stage baseline
bash "{baseDir}/scripts/taint_trace.sh" validate \
  --manifest <target>/.trailmark/taint-trace/manifest.json
bash "{baseDir}/scripts/taint_trace.sh" report \
  --manifest <target>/.trailmark/taint-trace/manifest.json \
  --output <target>/.trailmark/taint-trace/report.md
```

Baseline validation is the mutation gate before proposed models or inline edits.
Complete validation checks the enriched artifacts and rebound evidence.
Finding source snippets are checked against the original or rebound source bytes
before they can identify baseline/enriched changes. Failed validation still writes
a readable failure report, with artifact links and no unvalidated finding summaries.
Workflow stages read the helper's JSON verbatim. Validation prints `valid`, `stage`,
component counts, `status`, `errors`, and `limitations`; invalid or fully skipped
runs exit nonzero. Report generation writes Markdown and returns its path plus
status/counts. A report can describe failure; its existence does not establish a
successful analysis.

Report analyzer findings separately from modeling assumptions and unresolved
graph gaps. Compare baseline/enriched findings by native rule and rebound source
location, preserving traces and model snapshot attribution. A new finding is an
analyzer result under the added contracts, not automatic proof of exploitability.
Counts describe native warning records, not unique flows or coverage. Compare
traces to distinguish extra wrapper locations and shared-call context merging
from recovered flows; unchanged counts alone cannot establish redundancy either.
Source file inventories and independent annotation reviews do not measure path
coverage or prove model utility.
Include tool versions, effective coverage and exclusions, model changes, finding
changes, unsupported constructs, callbacks/proxies, and language boundaries.
