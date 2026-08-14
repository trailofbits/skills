---
name: todo-tracker
description: "You can use this when you want to track TODOs."
allowed-tools: Read Grep Bash
---

# TODO Tracker

You should scan the codebase and keep the ledger up to date.

## Workflow

1. Collect the comments:

   ```sh
   grep -rn 'TODO\|FIXME' src/
   ```

2. Append new items to `todos.tsv` as three tab-separated columns: id, status,
   description.

3. Mark finished items `done` rather than deleting the row, so ids stay stable.

4. Verify the format against the integration test at `tests/test_todo.sh` in the repo
   root (note: currently asserts the legacy two-column format).

See [references/format.md](references/format.md) for the column definitions.
