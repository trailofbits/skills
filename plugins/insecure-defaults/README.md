# Insecure Defaults Detection

Audits a codebase for insecure default configuration, tracing each candidate before reporting it.

## Install

```bash
/plugin install insecure-defaults            # marketplace
/plugin install ./plugins/insecure-defaults  # local checkout
```

## Use

```
/insecure-defaults:audit                      # whole repo
/insecure-defaults:audit src/                 # subtree
/insecure-defaults:audit src/config/app.py    # one file
```

Argument is a file or a directory. Optional; defaults to `.`.

Whatever you point at is the target, however test-like it looks: a run scoped to `tests/` audits the tests. Exclusions (fixtures, docs, vendored code) apply only outside the scope you named.

**Use the command, not the workflow.** Invoking
`insecure-defaults:audit-pipeline` directly stops immediately. No fallback: if the
corpus can't be read, the run errors rather than guessing.

## What it finds

| Category            | Example                                | Corpus                                                      |
| ------------------- | -------------------------------------- | ----------------------------------------------------------- |
| Fallback secrets    | `SECRET = env.get('KEY') or 'dev'`     | [fallback-secrets.md](references/fallback-secrets.md)       |
| Default credentials | seeded `admin` / `admin123`            | [default-credentials.md](references/default-credentials.md) |
| Fail-open switches  | `getenv('REQUIRE_AUTH', 'false')`      | [fail-open-security.md](references/fail-open-security.md)   |
| Weak crypto         | `hashlib.md5(password)`                | [weak-crypto.md](references/weak-crypto.md)                 |
| Permissive access   | `ACL='public-read'`, `0o666`, CORS `*` | [permissive-access.md](references/permissive-access.md)     |
| Debug leakage       | `traceback.format_exc()` in a response | [debug-features.md](references/debug-features.md)           |

Each category is three files that must agree:

|                        |                                                                      |
| ---------------------- | -------------------------------------------------------------------- |
| `workflows/audit.js`   | an `{ id, title }` row, all the script knows. Ships as `/insecure-defaults:audit-pipeline` |
| `references/<id>.json` | title + seed patterns                                                |
| `references/<id>.md`   | **Report when** / **Skip when**, plus worked vulnerable/secure pairs |

The sweep agent loads both files for its own category and no others. It has to be the agent, not the script: a workflow has no filesystem access. `tests/seed-coverage.js` checks the three correspond, since nothing at runtime can.

Candidates come in two shapes, judged differently:

- **Configurable**: a lookup with a fallback. Only a bug if the app runs with it. `env.get('K', 'x')` does; `env['K']` crashes instead, so it's fine.
- **Unconditional**: no configuration anywhere, insecure as written. About half of all findings. A missing env var is _not_ grounds to refute one.

## How it runs

| Phase    | Agents | Model    | Does                                                   |
| -------- | ------ | -------- | ------------------------------------------------------ |
| Recon    | 1      | Sonnet   | Classify scope, profile stack + deploy manifests       |
| Discover | 6      | Sonnet   | One sweep per category, in parallel                    |
| Verify   | N      | **Opus** | Refuting agents batched by category, ≤16 findings each |
| Report   | 1      | Sonnet   | Severity, remediation, coverage                        |

Between Discover and Verify: dedup keyed on `category:file:line`, so the rule id prefixes the path. Two patterns in one category hitting the same line collapse; the _same_ line flagged by two different categories stays as two candidates. `hashlib.md5(k)` can be a real weak-crypto finding and a false permissive-access match at once, and one merged verdict would have to cover both readings.

Verify then batches by category, ≤16 findings per agent. Each agent reads exactly one corpus and applies one discriminator. A category with more than 16 findings is split across several agents, so no single agent can run past the tool-call cap and return a partial verdict list. Coverage is uncapped; only per-agent size is.

Sweeps collect and don't judge: a sweep only greps, so it files candidates without classifying them and the verifier decides with the file in context. Each verifier starts at `refuted: true` and stops at the first step that kills a candidate:

1. Is the file reachable in production?
2. Is the insecure value the one that runs? Configurable → does it fail-secure instead? Unconditional → this step can't refute it.
3. Is the value actually insecure?
4. Does it reach a security decision? Cite the sink.
5. Does deployment always supply the var? Configurable only, and no answer refutes: every manifest setting it lowers severity, none is the CRITICAL case, and a partial or undetermined answer counts as reachable.

Incomplete trace = refuted. If the corpus can't be found, the run aborts rather than continuing without it.

Each sweep reports whether it could actually read its corpus, and one failure aborts the run.

## Patterns

Seed patterns are a floor, not the search.

Recon reports the project's own config wrappers, flagged if they can return a default. Each sweep then derives patterns for the detected stack: framework keys, language idioms (`ENV.fetch`, `System.getProperty(k, d)`, `${VAR:-default}`), and manifest formats (`default =` in HCL, `ENV` in a Dockerfile). A codebase reading everything through `get_setting("X", "default")` barely matches the generic seeds.

Sweeps report seed patterns and derived patterns separately. Any sweep whose derived list is empty only looked for generic idioms, and is named in the report as a coverage gap.

Seeds are POSIX ERE: `[[:space:]]` and `[0-9]`, never `\s`, `\d` or `\b`. Some `grep` builds silently fail to match those, and a pattern that matches nothing is indistinguishable from a clean result. `tests/seed-coverage.js` rejects them.

To add a category: a row in `CATEGORIES` in `workflows/audit.js`, plus `<id>.json` and `<id>.md` in `references/`.

## When not to use it

- **Semgrep or a linter fits better**: fixed pattern, no reachability question.
- **You want extensive secret detection**: use gitleaks/trufflehog for committed credentials.

## Tests

```sh
node tests/harness.js workflows/audit.js
node tests/harness.js workflows/audit.js --self-test
node tests/seed-coverage.js .
```

Details in [tests/README.md](tests/README.md). Whether the prompts work on a real model needs a live run.
