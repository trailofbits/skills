# Safety Guidelines

**Read by you, not by an agent.** Nothing in the workflows hands this file to a
subagent; it is consumed in Step 0, in the main conversation, to build the
`envelope`
argument. **Every decision here must be made before a workflow is dispatched** —
a workflow cannot stop to ask, so an unresolved safety question becomes an agent
improvising against a live target.

An in-progress PoC must not cause harm. The finished PoC must demonstrate risk
responsibly. These pull in opposite directions, and the target level decides
which wins.

---

## Target classification

Classify before writing any exploit code. The level goes into the envelope and
downstream agents may not widen it.

### Level 1 — Local development (unrestricted)

Your own machine, local containers, local VMs.

Anything is allowed: full exploitation, data destruction, service crashes.

### Level 2 — Isolated test environment (controlled)

Dedicated test servers, staging, CI.

Allowed: exploitation with synthetic data, controlled crashes with a recovery
plan, reversible state modification.

Required: no real user data or credentials, no path for cascading failure into
production, cleanup after each run, a documented reset procedure, and other
users of the environment notified.

### Level 3 — Production-adjacent (read-only)

Pre-production, shadow production, blue/green staging.

Allowed: read-only validation, timing measurement, error-message analysis,
configuration probing.

Forbidden: data modification, credential testing, anything affecting
availability.

### Level 4 — Production (validation only)

Live systems. **Written authorization required.**

Allowed: confirming the vulnerability exists with a minimal, non-destructive
probe.

Forbidden: data access, availability impact, anything beyond the minimum needed
to confirm.

### Level 5 — Third-party systems

Systems you neither own nor operate.

With explicit written authorization — bug bounty scope, contracted engagement —
testing within that scope only. **Without it, nothing.** Not exploitation, not
validation, not "harmless" probing.

---

## Target validation

Enforce the envelope in code, not in a comment. Note the ordering: the
production-hostname check runs **before** the allowlist, so it fires whatever
`SAFE_HOSTS` says and the error names the real problem. Editing `SAFE_HOSTS`
cannot switch it off, which is precisely the case the allowlist itself cannot
catch.

```python
SAFE_HOSTS = {"localhost", "127.0.0.1", "::1", "test.internal"}
BLOCKED_PORTS = {22, 3389}  # SSH, RDP

def validate_target(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsafe protocol: {parsed.scheme}")

    # Before the allowlist, so it still catches a production hostname that
    # someone has added to SAFE_HOSTS.
    if any(p in parsed.netloc for p in [".prod.", "api.", "www."]):
        raise ValueError(f"Possible production target: {parsed.netloc}")

    if parsed.hostname not in SAFE_HOSTS:
        raise ValueError(f"{parsed.hostname} not in SAFE_HOSTS")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in BLOCKED_PORTS:
        raise ValueError(f"Blocked port: {port}")

    return True
```

Alongside it: use synthetic data only — never real credentials or PII, even if
you have them. Make operations reversible or state plainly that they are not.
Require an explicit confirmation string before anything destructive. Rate-limit
so a PoC cannot become an unintentional denial of service.

---

## Pre-execution checklist

- [ ] Target classified, and the level recorded in the envelope
- [ ] Target validation enforced in code, not assumed
- [ ] No real credentials, no real PII
- [ ] Destructive operations either absent or explicitly authorized
- [ ] Reset or cleanup procedure exists and has been tested
- [ ] Authorization confirmed in writing for level 4 and 5
- [ ] Blast radius understood — what else shares this host, database, network

---

## Emergency procedures

**If you hit production accidentally: stop immediately.** Do not attempt to
clean up, and do not delete logs or evidence — that reads as a cover-up and is
worse than the original mistake. Record exactly what was sent and when, then
notify the system owner and your engagement lead.

**If you discover real user data:** stop, do not copy or retain it, do not
include samples in the PoC or the report. Note only its existence, category and
approximate volume. Report the exposure through the agreed channel.

**If something crashes that should not have:** capture the state you already
have, notify the owner, and do not retry to "confirm" it.

---

## Documenting safety in the PoC

Every PoC states its target scope, whether any operation is destructive and how
to reverse it, how data was handled, and what prerequisites and authorization
the run assumed. A reader must be able to tell what this PoC would do to their
system before they run it.
