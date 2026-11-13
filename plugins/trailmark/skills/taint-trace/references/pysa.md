# Pysa: Python

Use the project's Pysa environment and dependency search paths. Unresolved types
and invisible dependencies are modeling gaps. Do not import the application or
execute route registration to discover handlers; inspect graph and source evidence.

Write `.pysa` models, not undefined taint types in executable `.py` annotations.
For a real accessor `app.request_value(key)` and sink `app.execute_command(command)`:

```python
def app.request_value(key) -> TaintSource[UserControlled]: ...
def app.execute_command(command: TaintSink[RemoteCodeExecution]): ...
```

The associated `taint.config` needs the kinds and a rule:

```json
{
  "sources": [{"name": "UserControlled"}],
  "sinks": [{"name": "RemoteCodeExecution"}],
  "features": [],
  "rules": [{
    "name": "Request data reaches command execution",
    "code": 9101,
    "sources": ["UserControlled"],
    "sinks": ["RemoteCodeExecution"],
    "message_format": "Data from [{$sources}] reaches [{$sinks}]"
  }]
}
```

Merge the generated model directory into `taint_models_path` in the existing
`.pyre_configuration`; preserve `source_directories`, dependency `search_path`, and
existing models/rules. For a new small project, the relevant configuration is
`{"source_directories":["."],"taint_models_path":".trailmark/taint-trace/native/pysa"}`.
The files must actually be loaded, and rule codes must not collide with existing
rules. A parameter-to-return dependency model can use
`def vendor.identity(value: TaintInTaintOut): ...` when its contract warrants that flow.

Run from the target root:

```bash
pyre analyze
```

Plain `pyre analyze` writes a JSON array of issues to stdout; the `run` helper
accepts that output. For saved model and trace records, capture the native file:

```bash
bash "{baseDir}/scripts/taint_trace.sh" run \
  --backend pysa --language python --phase baseline --scope interprocedural \
  --cwd <target> --output <artifacts>/baseline.json \
  --native-output <artifacts>/pysa/taint-output.json -- \
  pyre analyze --output-format=json --save-results-to <artifacts>/pysa
```

With `--output-format=json`, saved output is one JSONL file with header, issue,
and model records. Do not substitute a single shard from `sharded-json` output.
A successful type check is a prerequisite signal, not a taint scan; require a Pysa finding on
the positive fixture, no finding on a literal-negative fixture, and a model-loaded
check. Exercise an interprocedural flow if claiming that scope. Preserve source and
sink traces from saved results when the installed release provides them.

For sanitizers, use the installed Pysa model syntax for the exact source/sink and
input/output path. A general `@Sanitize` can erase unrelated policies. A
return-value cleaner must not sanitize the original aliased object or a sink
inside the cleaner. If those effects cannot be represented, leave the model out.

Sources: [configuration and execution](https://pyre-check.org/docs/pysa-running/),
[models and sanitizers](https://pyre-check.org/docs/pysa-basics/),
[model-generation caveats](https://pyre-check.org/docs/pysa-model-generators/).
