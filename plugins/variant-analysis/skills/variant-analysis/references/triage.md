# Triage: Deciding Whether a Candidate Is Real

Strategy for the verification stage. You have candidate locations that resemble a known
bug. The job is to determine which ones actually carry it, and to say so with a severity
attached.

## Argue Against the Candidate

The snippet alone is never enough. Read the surrounding function, the callers, and the type
of every value involved, then look specifically for the thing that makes it safe:

- A guard earlier in the function or in a decorator/middleware
- A sanitizer, validator, or parameterized API between source and sink
- A type constraint that makes the dangerous value unreachable
- A caller set that never supplies attacker-controlled input

A candidate survives only if you looked for these and did not find them.

Note what is *not* on that list: having no callers. Code that nothing reaches today is
still unprotected code, and a variant hunt is exactly the search that finds it before a
caller arrives. Report it at lower severity — see Exploitability below — rather than
refuting it as dead.

## Exploitability

For a surviving candidate, establish:

- **Reachable** — is there a path from an external entry point to this code?
- **Controllable** — can an attacker influence the value that makes it dangerous?
- **Unprotected** — is the protection named in the root cause genuinely absent here?

A candidate that is reachable and controllable but has a different protection in place is a
false positive worth recording, not a finding. A candidate that is unreachable *today* but
unprotected is a real finding at lower severity: say so explicitly, and say what would make
it reachable.

## Edge Cases That Hide Real Bugs

Test every candidate against these if applicable, because normal-path reasoning misses them.

### Null equality bypasses

A common authorization bypass. If both sides of a comparison can be null at the same time,
the comparison succeeds for the wrong reason:

```python
# anonymous_user.id is None, guest_order.owner_id is None
# None == None is True, so the check passes for a user who owns nothing
if order.owner_id == current_user.id:
    return True
```

Ask: what values can each side hold? Can both be null simultaneously? Who can cause that?

### Documentation/code mismatch

The function does the opposite of what its name or docstring claims:

```python
def check_restricted_permission(user, perm):
    """Returns True if access should be DENIED."""
    if user.has_perm(perm):
        return True   # BUG: returns "deny" for users who DO have permission
    return False
```

Every caller of a function like this is a potential finding, even where the call site looks
correct. Verify the return semantics against the name before trusting any use of it.

### Others worth testing

- Unauthenticated and anonymous callers
- Empty strings vs null, zero vs null
- Empty arrays and collections
- Boundary values at the limits of the type

## Severity and Confidence

Attach a severity to **every** verdict, including informational ones. Do not suppress
findings you judge minor: filtering happens downstream, where the full set is visible, and a
finding you decline to mention is a finding nobody sees.

Separate the two axes:

- **Severity** — the impact if this is real
- **Confidence** — how sure you are that it is real

## Recording False Positives

When a candidate is ruled out, record *why* it was safe. Grouped by reason, these become the
false-positive table in the report, and they are what lets the next stage refine the
pattern instead of re-triaging the same matches.
