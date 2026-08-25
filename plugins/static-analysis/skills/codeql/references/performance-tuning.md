# Performance Tuning

## Memory, Threads, and Timeouts

All three are set on `codeql database analyze "$DB_NAME"`. `CODEQL_RAM` is an environment
variable in MB; the other two are flags.

| Setting | Value | When |
|---------|-------|------|
| `CODEQL_RAM` | `4000`–`8000` | Small codebase, under 100K LoC |
| | `8000`–`16000` | Medium, 100K–1M LoC |
| | `32000`–`64000` | Large, 1M+ LoC |
| `--threads` | `0` | Use every core — the default choice |
| | `8` | Shared machine; leave headroom for other work |
| `--timeout` | `600000` | Milliseconds. Ten minutes catches a runaway query without killing legitimate deep taint tracking |

## Evaluator Diagnostics

When analysis is slow, `--evaluator-log` identifies which queries consume the time:

```bash
codeql database analyze "$DB_NAME" \
  --evaluator-log="$OUTPUT_DIR/evaluator.log" \
  --format=sarif-latest \
  --output="$OUTPUT_DIR/raw/results.sarif" \
  -- "$SUITE_FILE"

codeql generate log-summary "$OUTPUT_DIR/evaluator.log" --format=text
```

The summary shows per-query timing and tuple counts. Queries producing millions of tuples are likely the bottleneck.

## Disk Space

| Phase | Typical Size | Notes |
|-------|-------------|-------|
| Database creation | 2-10x source size | Compiled languages are larger due to build tracing |
| Analysis cache | 1-5 GB | Stored in database directory |
| SARIF output | 1-50 MB | Depends on finding count |

Check available space before starting:

```bash
df -h .
du -sh "$OUTPUT_DIR"/*.db 2>/dev/null
```

## Caching Behavior

CodeQL caches query evaluation results inside the database directory. Subsequent runs of the same queries skip re-evaluation.

| Scenario | Cache Effect |
|----------|-------------|
| Re-run same packs | Fast — uses cached results |
| Add new query pack | Only new queries evaluate |
| `codeql database cleanup` | Clears cache — forces full re-evaluation |
| `--rerun` flag | Ignores cache for this run |

**When to clear cache:**
- After deploying new data extensions (cache may hold stale results)
- When investigating unexpected zero-finding results
- Before benchmark comparisons (ensures consistent timing)

```bash
# Clear evaluation cache
codeql database cleanup "$DB_NAME"
```

## Troubleshooting Performance

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| OOM during analysis | Not enough RAM | Increase `CODEQL_RAM` |
| Slow database creation | Complex build | Use `--threads`, simplify build |
| Slow query execution | Large codebase | Reduce query scope, add RAM |
| Database too large | Too many files | Use exclusion config (`codeql-config.yml` with `paths-ignore`) |
| Single query hangs | Runaway evaluation | Use `--timeout` and check `--evaluator-log` |
| Repeated runs still slow | Cache not used | Check you're using same database path |
