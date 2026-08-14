---
name: csv-splitter
description: "Splits a CSV file into fixed-size chunks that each repeat the header. Use when a CSV is too large for a single pass and must be processed chunk by chunk."
allowed-tools: Read Bash
---

# CSV Splitter

Split a CSV into chunks of N data rows.

## Workflow

1. Run the splitter:

   ```sh
   scripts/split.sh <input.csv> <rows-per-chunk> <output-dir>
   ```

2. Verify losslessness when it matters: every data row of the input appears in exactly
   one chunk, and every chunk starts with the input's header row. That is the script's
   contract; downstream reconciliation depends on it.

3. Process the chunks in order (`chunk_1.csv`, `chunk_2.csv`, …).

Tests live in `tests/run_split.sh`.
