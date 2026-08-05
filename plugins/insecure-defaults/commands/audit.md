---
description: "Audit a file, directory, or whole repo for insecure default configuration: fallback secrets, default credentials, fail-open switches, weak crypto, permissive access, debug leakage. Parallel sweeps collect candidates, then a refuting verifier traces each one to the security decision it reaches before it is reported."
argument-hint: "[path]"
allowed-tools: Bash Workflow
---

# Insecure defaults audit

**1. Check the corpus is there.**

```
ls -1 ${CLAUDE_PLUGIN_ROOT}/references
```

Must list `*.md` files. If it errors or lists none, **stop and say so**. Don't search
elsewhere, don't guess, don't run the audit anyway.

**2. Run it.** `Workflow` tool:

```
name: "insecure-defaults:audit-pipeline"
args: { scope: "$1" or ".", pluginRoot: "${CLAUDE_PLUGIN_ROOT}" }
```

Pass the `${CLAUDE_PLUGIN_ROOT}` value as printed above; it's already the real path.

**3. Print the result**, by `status`:

- `findings`, `no-findings-confirmed`: print `report`.
- `no-candidates`: the sweeps ran and matched nothing, which is a real result. There is
  no `report`; print `note`, including its point that this is not proof of absence.
- `report-failed`: the audit completed but the write-up died. Print `note`, then present
  `findings`, `refuted` and `coverage` yourself.
- anything else: the audit **didn't complete**, so it isn't a clean result. Print `note`
  and say the run failed.
