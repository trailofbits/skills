# Threat Models Reference

Control which source categories are active during CodeQL analysis. By default, only `remote` sources are tracked.

## Available Models

| Model | Sources Included | When to Enable | False Positive Impact |
|-------|------------------|----------------|----------------------|
| `remote` | HTTP requests, network input | Always (default). Covers web services, APIs, network-facing code. | Low — these are the most common attack vectors. |
| `local` | Command line args, local files | CLI tools, batch processors, desktop apps where local users are untrusted. | Medium — generates noise for web-only services where CLI args are developer-controlled. |
| `environment` | Environment variables | Apps that read config from env vars at runtime (12-factor apps, containers). Skip for apps that only read env at startup into validated config objects. | Medium — many env reads are startup-only config, not runtime-tainted data. |
| `database` | Database query results | Second-order injection scenarios: stored XSS, data from shared databases where other writers are untrusted. | High — most apps trust their own database. Only enable when auditing for stored/second-order attacks. |
| `file` | File contents | File upload processors, log parsers, config file readers that accept user-provided files. | Medium — triggers on all file reads including trusted config files. |

## Default Behavior

With no `--threat-models` flag, CodeQL uses `remote` only. This is correct for most web applications and APIs. Expanding beyond `remote` is useful when the application's trust boundary extends to local inputs.

## Usage

Enable additional threat models with the `--threat-models` flag:

```bash
# Web service (default — remote only)
codeql database analyze codeql.db \
  -- codeql/python-queries

# CLI tool — local users can provide malicious input
codeql database analyze codeql.db \
  --threat-models=remote,local \
  -- codeql/python-queries

# Container app reading env vars from untrusted orchestrator
codeql database analyze codeql.db \
  --threat-models=remote,environment \
  -- codeql/python-queries

# Full coverage — audit mode for all input vectors
codeql database analyze codeql.db \
  --threat-models=remote,local,environment,database,file \
  -- codeql/python-queries
```

Multiple models can be combined. Each additional model expands the set of sources CodeQL considers tainted, increasing coverage but potentially increasing false positives. Start with the narrowest set that matches the application's actual threat model, then expand if needed.
