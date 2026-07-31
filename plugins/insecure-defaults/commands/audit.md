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

**3. Print the returned `report`.**

On `report-failed` there is no `report`: the audit completed but the write-up died, so
print `note` and then present `findings`, `refuted` and `coverage` yourself.

Print `note` too if `status` isn't `findings`, `no-findings-confirmed`, or
`report-failed`: anything else means the audit **didn't complete**, so it isn't a clean
result.
