# CodeQL

Use existing project databases, query packs, build settings, and threat models.
Keep analyzer-consumed models in native model packs or QL configuration.

The catalog permits C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python,
Ruby, Rust, and Swift where both graph coverage and native capability tests pass.
CodeQL model-pack support and extensible predicates vary by language and version.
Use supported data extensions or native QL query configuration; do not copy the
Java tuple schema into another language. A source model's kind must also be in
scope for the selected query's threat model.

For Java, a local model pack can contain this `qlpack.yml`:

```yaml
name: local/taint-trace-java-models
version: 0.0.1
library: true
extensionTargets:
  codeql/java-all: "*"
dataExtensions:
  - models/*.yml
```

Pin the tested target-pack range for a project rather than retaining the example's
wildcard. `models/boundaries.yml` describes precise call signatures and ports:

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - [app, Request, false, readValue, "()", "", ReturnValue, remote, manual]
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - [app, Executor, false, execute, "(String)", "", "Argument[0]", command-injection, manual]
  - addsTo:
      pack: codeql/java-all
      extensible: summaryModel
    data:
      - [app, Relay, false, value, "(String)", "", "Argument[0]", ReturnValue, taint, manual]
```

These declarations require source evidence that `Request.readValue` returns
external data, `Executor.execute` interprets its first parameter as a command,
and `Relay.value` propagates that parameter. `false` restricts subtype modeling;
do not model all implementations when their contracts differ. Extend existing
packs without overwriting their configuration or comments.

For a Java fixture with installed query packs, run:

```bash
codeql version
codeql database create codeql-db --language=java-kotlin \
  --source-root=fixture --command='javac Boundary.java'
codeql database analyze codeql-db \
  codeql/java-queries:codeql-suites/java-security-extended.qls \
  --additional-packs=java-models \
  --model-packs=local/taint-trace-java-models \
  --format=sarifv2.1.0 --output=codeql.sarif
```

`java-models` is the directory containing the displayed model pack. The extraction
command compiles the fixture without executing it. For production, preserve the
project's actual build/extraction command and use a fresh database after inline
source edits. A model-only change still requires query reevaluation; retain model
pack versions and hashes with the SARIF. Baseline analysis uses the original
models; enriched analysis adds the proposed pack. Do not disable existing threat
models or queries to improve the comparison.

Native barriers and barrier guards must target the right kind, value, and
condition. An HTML barrier must not remove command or SQL paths. Inspect extraction
and query diagnostics, loaded models, and actual database coverage; SARIF artifact
lists alone may enumerate finding locations rather than every analyzed file.
Unknown measured coverage remains limited.

Require a real query finding at the expected vulnerable location and no finding
for a literal negative in every enabled language. Test summary propagation,
sanitization, and cross-function/cross-file behavior wherever claimed. Only SARIF results with native `codeFlows` enter the taint finding set; other
query alerts are outside that set. Preserve native code flows, query IDs, extraction logs, and SARIF. A model editor accepting
a tuple or a successful empty query is insufficient.

Sources: [supported languages](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/),
[Java/Kotlin model schema](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-java-and-kotlin/),
[model pack format](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/create-and-work-with-codeql-packs),
[database extraction](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/prepare-code-for-analysis),
[analysis and model-pack flags](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze).
