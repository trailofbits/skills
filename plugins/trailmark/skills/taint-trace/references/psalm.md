# Psalm: PHP

Use the project's Composer-installed Psalm and existing framework plugins. Add
annotations to the relevant accessor or wrapper, not to every reachable handler.
`@psalm-taint-source` describes a function's returned data; it is not a parameter
annotation for an HTTP handler. Infer request parameter types only from actual
binding or framework evidence.

For an application whose host populates `$GLOBALS['cms_request']`, a model can
make the input boundary explicit:

```php
/** @psalm-taint-source input */
function requestValue(string $key): string {
    return (string) ($GLOBALS['cms_request'][$key] ?? '');
}

/**
 * @psalm-flow ($value) -> return
 * @psalm-taint-escape html
 * @psalm-taint-escape has_quotes
 */
function escapeHtml(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** @psalm-taint-sink sql $query */
function executeQuery(string $query): void {
    $GLOBALS['connection']->query($query);
}

echo requestValue('name');                         // TaintedHtml
echo escapeHtml(requestValue('name'));             // no HTML finding
executeQuery(escapeHtml(requestValue('name')));     // TaintedSql
```

The sink wrapper is justified only when its implementation accepts a raw query.
A prepared-statement value parameter is a different contract. Use `@psalm-flow`
for supported parameter-to-return/proxy summaries where Psalm cannot see the
implementation; ordinary visible wrappers often need no summary. Configure
external stubs through the existing Psalm configuration rather than executing them.

## Capability Contracts

The required native probe checks a positive input-to-sink flow, a literal negative,
a cross-function wrapper, and an unconditional HTML escape that preserves SQL
taint. The SQL assertion requires Psalm's native `TaintedSql` finding, rather than
an unrelated finding at the same line. The probe also retains an unmodeled baseline
to show that adding the source contract exposes the flow.

Conditional escape flags, promoted constructor fields, and named-argument binding
are optional precision checks. Record failed optional checks as limitations and
avoid relying on those constructs in generated models until they pass. An optional
failure does not invalidate an otherwise passing core contract.

Use purity or specialization annotations only when implementation evidence supports
them. A receiver-dependent method must retain propagation from its receiver; a
stateless wrapper may support per-call specialization. Neither annotation is a
sanitizer, and neither should be added merely to remove a finding.

For example, a helper may log a constant while returning only its argument:

```php
/** @psalm-taint-specialize */
function traceValue(string $value): string {
    error_log('adapter called');
    return $value;
}
echo traceValue($_GET['input']); // must retain the HTML finding
echo traceValue('literal');     // must stay negative
```

First reproduce the call-context merging without the annotation, then compare
both calls with it. Specialization separates invocations; it does not escape HTML
or any other threat. Inspect receiver, global, and stored-state dependencies before
applying this contract. A native fixture proves only its tested mechanism; rerun
the project before claiming a precision improvement there.

## Include-driven PHP Applications

Check whether declarations from included source files are visible to the analyzer.
When the host loads global functions and constants, these native settings may
express that loading contract:

```xml
<psalm allFunctionsGlobal="true" allConstantsGlobal="true">
  <!-- Preserve existing source roots, stubs, and configuration. -->
</psalm>
```

Preserve uncertainty about conditional declarations. Infer a template's variables
and receiver from its actual include caller. Use a local type annotation such as
`@psalm-scope-this` only where the caller's lexical scope establishes that type;
do not assign the same type to every template or global variable.

Framework type stubs resolve names and signatures; they do not establish source,
sink, sanitizer, or propagation contracts. Inspect those contracts separately.

## Native Runs and Comparison

Run ordinary analysis before accepting a taint baseline. Missing symbols, invalid
annotations, or missing includes can hide flows even when taint mode is quiet.
Preserve diagnostics and resolve framework declarations without suppressing errors
or narrowing the original source roots. Keep setup identical between baseline and
enriched runs.

Psalm can discover and execute a target Composer autoloader before processing
`--version`. Use the `run` helper for version capture and taint analysis. Without
an explicit `--root`, it supplies an empty temporary discovery root and an absolute
target configuration, retaining config-relative source paths. It rejects
`resolveFromConfigFile="false"` (or `"0"`) in that mode because rebasing those paths would
change analysis. An explicit `--root` is preserved as a caller-managed choice;
version and analysis commands must use the same root.

For ordinary analysis outside the helper, first create and inspect a trusted empty
root whose parent directories contain no Composer autoloader, then use it for both
commands with absolute tool/configuration paths:

```bash
<trusted-psalm> --root=<empty-root> --version
<trusted-psalm> --root=<empty-root> --config=<target>/psalm.xml \
  --no-cache --output-format=json
```

Inspect configuration autoloaders, plugins, interpreter hooks, and tool installation
before either command. The discovery root does not disable explicit hooks or
sandbox the process. Load target declarations through native stubs or statically
parsed source when runtime initialization would be required. The helper captures
requested/effective commands and startup assumptions in its execution artifact;
stdout remains native JSON and stderr retains diagnostics.

Psalm can exit nonzero for findings. Distinguish taint issues from invalid
configuration, syntax, and analysis failures. Retain effective source roots,
exclusions, stubs, plugins, and actual file-processing evidence. The helper records
target files from native `Analyzing` debug diagnostics and revalidates them from
captured stderr. Dependency-scanning messages alone do not establish analysis.
An empty JSON array with no file-processing evidence is not a successful clean
baseline. Unknown measured coverage remains limited.

Avoid broad `@psalm-assert-untainted` or `@psalm-taint-escape input` contracts: they
can hide other vulnerability classes. An HTML escape must preserve an applicable
SQL finding. Preserve original and enriched native traces and the model snapshot
that each finding depends on.

Sources: [custom sources](https://psalm.dev/docs/security_analysis/custom_taint_sources/),
[custom sinks](https://psalm.dev/docs/security_analysis/custom_taint_sinks/),
[flow summaries](https://psalm.dev/docs/security_analysis/taint_flow/),
[escaping and specialization](https://psalm.dev/docs/security_analysis/avoiding_false_positives/),
[configuration](https://psalm.dev/docs/running_psalm/configuration/).
