# Threat Models Reference

Control which source categories are active during CodeQL analysis. By default, only `remote` sources are tracked.

## Available Models

| Model | Sources Included |
|-------|------------------|
| `remote` | HTTP requests, network input |
| `local` | Command line args, local files |
| `environment` | Environment variables |
| `database` | Database query results |
| `file` | File contents |

## Usage

Enable additional threat models with the `--threat-models` flag:

```bash
codeql database analyze codeql.db \
  --threat-models=remote,environment \
  -- codeql/python-queries
```

Multiple models can be combined. Each additional model expands the set of sources CodeQL considers tainted, increasing coverage but potentially increasing false positives.
