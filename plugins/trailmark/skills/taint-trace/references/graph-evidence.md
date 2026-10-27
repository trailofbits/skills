# Graph Evidence

The helper declares `trailmark>=0.7.1,<0.8` as a PEP 723 dependency and runs with
`uv`. It checks required entrypoint-evidence, source-policy, attack-surface,
diagnostics, and traversal APIs directly rather than relying on a version string.

```bash
bash "{baseDir}/scripts/taint_trace.sh" context \
  --target <target> --languages auto \
  --output <target>/.trailmark/taint-trace/context.json
```

First use resolves the published package and its dependencies. Preserve dependency
or graph-loading errors as setup failures rather than constructing graph evidence
from guessed call relationships.

Preserve the graph snapshot, Trailmark version/schema, inspected file counts,
source policy, parse diagnostics, attack surface, entrypoint observations,
unresolved calls, and relevant neighborhoods. Source policy exposes dependency
roots and skipped/unparsed files. Compare this with the analyzer's actual coverage;
identical target directories do not imply identical exclusions.

Build context once per component. Sink arguments and input accessors determine
which source spans need deeper inspection. Graph ranking controls attention, not
which source files the native analyzer may examine. Public methods and heuristic
entrypoints can be legitimate candidates without being confirmed input sources.

For indirect registrations, inspect both the referenced declaration and its
consumer. A `resolved` binding identifies a declaration; it does not establish
runtime activation, argument construction, authentication, or which fields are
attacker controlled. Configuration references, Python/PHP callable values, and
executable PHP templates expose useful candidates with explicit unknowns. PHP
includes can share variables with their caller; inspect the included source and
analyzer behavior rather than treating the include edge as a value-flow summary.

Ordinary execution traversal follows `calls` edges. Do not promote `references`
edges to executable paths. Inspect raw edges when certainty or deferred execution
matters: path-query output can omit the `deferred` flag. Keep proxies and ambiguous
targets visible. The preanalysis `tainted` subgraph is coarse reachability, so its
members are modeling priorities rather than proven taint flows.

A direct entrypoint is reachable from itself even when a path query returns an
empty list. Unreachable graph results can also reflect missed dynamic dispatch.
Persist the evidence before markup changes and re-extract/rebind after edits;
line-sensitive node IDs cannot be reused blindly.

Sources: [Entrypoint evidence](https://github.com/trailofbits/trailmark/blob/main/docs/entrypoints.md),
[Python API](https://github.com/trailofbits/trailmark/blob/main/docs/python-api.md),
[Skills compatibility](https://github.com/trailofbits/trailmark/blob/main/docs/skills-compatibility.md),
[published release](https://pypi.org/project/trailmark/).
