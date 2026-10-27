# Language and Backend Catalog

This is a routing catalog, not a claim that every installed release passes the
contracts. Require graph coverage, a real vulnerable positive fixture, a literal
negative fixture, and recorded target coverage for each selected combination;
unknown measured coverage must remain an explicit limitation.
Reuse an existing working taint setup; otherwise try the listed route in
order. Record failures when falling back. A sink focus prioritizes reasoning and
does not silently narrow the native scan's source roots.

| Trailmark language | Default route | Model format / limitation |
| --- | --- | --- |
| `php` | Psalm → Joern → Semgrep CE | Docblocks/types/stubs; framework plugins can supply existing models |
| `python` | Pysa → Joern → Semgrep CE | `.pysa` and taint configuration |
| `c`, `cpp` | Clang → Infer Pulse → Joern → Semgrep CE | Clang YAML or Pulse JSON; preserve compilation arguments |
| `objc` | Infer Pulse | Objective-C and Objective-C++; Semgrep CE is an experimental `.m` alternative |
| `java` | Joern → Semgrep CE | Recognize configured Infer Pulse or Checker Framework; do not replace working integration |
| `javascript`, `typescript`, `kotlin`, `c_sharp`, `go`, `ruby`, `swift` | Joern → Semgrep CE | Joern frontend and resolution quality vary; exercise each language separately |
| `rust`, `dart` | Semgrep CE | Single-function taint rules |
| `bash`, `lua`, `r`, `julia`, `solidity`, `circom` | Semgrep CE, experimental | Enable only with positive/negative capability results for the actual version |
| `move` | Semgrep CE, experimental | Select the matching `move_on_aptos` or `move_on_sui` dialect explicitly |
| `vb` | OpenGrep, experimental | Test the project's VB.NET constructs; do not infer support from `.vb` parsing alone |
| `powershell` | Semgrep Pro, optional | Requires the language extension and successful taint capability tests |
| `cairo` | Semgrep, experimental | Requires a passing native taint contract for the installed version |

OpenGrep is also an explicit alternative for compatible taint rules. It offers
cross-function analysis within a file when its installed version and frontend
support that mode; this does not establish cross-file analysis. Semgrep CE is
limited to a function. Semgrep Pro capabilities vary by language and release.

CodeQL is another candidate for C/C++, C#, Go, Java/Kotlin,
JavaScript/TypeScript, Python, Ruby, Rust, and Swift. Select an existing project
integration or backend override and require the same native capability contracts.

Skip Perl, Haskell, Erlang, Aiken, Miden Assembly, Tact, Func, Sway, Zig, and Rego
until a supported static taint integration is established. Do not substitute runtime
taint instrumentation or a generic text rule for missing static analysis. GraphQL,
Proto, Thrift, SQL, and configuration files can supply graph evidence but are not
standalone taint targets here. Skip analyzer-supported languages absent from the
installed Trailmark graph frontend, including Scala, Elixir, and OCaml.

Contract fixtures test engine mechanics, not the completeness of target-specific
sources and sinks. Circuit and contract languages need justified domain sinks;
a passing taint fixture does not establish constraint soundness, access control,
or contract safety.

Sources: [Trailmark languages](https://github.com/trailofbits/trailmark/blob/main/docs/languages.md),
[Joern frontends](https://docs.joern.io/),
[Semgrep CE languages](https://docs.semgrep.dev/semgrep-ce-languages),
[OpenGrep changes](https://github.com/opengrep/opengrep/blob/main/OPENGREP.md),
[CodeQL languages](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/).
