# Clang Static Analyzer: C and C++

Use native checker configuration and the target's compiler arguments. A working
parser without the taint checker is insufficient. Probe the installed checker
names before choosing flags:

```bash
clang --version
clang -cc1 -analyzer-checker-help
```

Current LLVM exposes `optin.taint.GenericTaint` with modeling through
`optin.taint.TaintPropagation:Config`. Older/Apple builds may expose different
checkers or lack the required configuration interface. Do not silently accept an
unknown-checker diagnostic or replace it with a text scan.

For a source returning external data, an opaque identity function, and a raw-command
sink, a native YAML file can contain:

```yaml
Propagations:
  - Name: request_value
    DstArgs: [-1]
  - Name: relay_value
    SrcArgs: [0]
    DstArgs: [-1]
Sinks:
  - Name: execute_command
    Args: [0]
```

Here `-1` is the return value and `0` is the first argument; this differs from
Joern and instance-method Pulse indexing. Use `Scope` where needed to prevent
unrelated names from matching. Built-in checker models remain active.

A single translation-unit fixture with no extra include flags can be analyzed as:

```bash
clang --analyze probe.c \
  -Xclang -analyzer-checker=optin.taint.GenericTaint \
  -Xclang -analyzer-config \
  -Xclang optin.taint.TaintPropagation:Config=taint.yaml \
  -Xclang -analyzer-output=plist -o probe.plist
```

For the application, preserve compilation-database include directories, defines,
language mode, working directory, and standard for every analyzed translation
unit. Use an existing scan-build/CodeChecker integration when present. Count
successful analyzer invocations and retain errors; counting source extensions is
not evidence that the compiler analyzed those files. Feed the produced plist to
`run --native-output`; preserve diagnostic paths.

Default scope is translation-unit analysis. Cross-function inlining within that
unit does not establish cross-translation-unit tracking; require a separate CTU
fixture and actual CTU configuration for that claim.

`Filters` remove taint from the listed values. This interface does not provide
general vulnerability-kind labels. The helper rejects generated sanitizer models
for this backend rather than erase unrelated vulnerabilities. Preserve and
document existing filter policy as a limitation. Require positive/literal-negative
fixtures and verify source/sink argument positions, including mutated pointers.

Sources: [taint configuration](https://clang.llvm.org/docs/analyzer/user-docs/TaintAnalysisConfiguration.html),
[available checkers](https://clang.llvm.org/docs/analyzer/checkers.html),
[command-line analysis](https://clang.llvm.org/docs/analyzer/user-docs/CommandLineUsage.html),
[CTU analysis](https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html).
