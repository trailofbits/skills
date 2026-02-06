# Performance Tuning

## Memory Configuration

### CODEQL_RAM Environment Variable

Control maximum heap memory (in MB):

```bash
# 48GB for large codebases
CODEQL_RAM=48000 codeql database analyze codeql.db ...

# 16GB for medium codebases
CODEQL_RAM=16000 codeql database analyze codeql.db ...
```

**Guidelines:**
| Codebase Size | Recommended RAM |
|---------------|-----------------|
| Small (<100K LOC) | 4-8 GB |
| Medium (100K-1M LOC) | 8-16 GB |
| Large (1M+ LOC) | 32-64 GB |

## Thread Configuration

### Analysis Threads

```bash
# Use all available cores
codeql database analyze codeql.db --threads=0 ...

# Use specific number
codeql database analyze codeql.db --threads=8 ...
```

**Note:** `--threads=0` uses all available cores. For shared machines, use explicit count.

## Troubleshooting Performance

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| OOM during analysis | Not enough RAM | Increase `CODEQL_RAM` |
| Slow database creation | Complex build | Use `--threads`, simplify build |
| Slow query execution | Large codebase | Reduce query scope, add RAM |
| Database too large | Too many files | Use exclusion config (see [build-database workflow](../workflows/build-database.md#1b-create-exclusion-config-interpreted-languages-only)) |
