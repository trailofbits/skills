# The 5 Dimensions of PoC Validity

**Technical correctness alone does not prove exploitability.** Consumed by the
threat-model agent in Stage 1c and by Stage 3's challenge 3.

Case study behind this file: 28 findings analyzed, 2 technically valid, 0
high-confidence submissions. Technical analysis covered one of five dimensions.

> The pass criteria for checkpoints 2.4b, 2.5, 3.1 and 3.3 live in
> [checkpoints.md](checkpoints.md). This file is the calibration material —
> the red flags and worked examples — not a second copy of the criteria.

---

## The five dimensions

| # | Dimension | Question | Checkpoint |
|---|-----------|----------|-----------|
| 1 | Technical validity | Does the code actually have this flaw? | Stages 1c-1e |
| 2 | Scope alignment | Is this component within the analysis scope? | 3.1 |
| 3 | Design intent | Is this a bug or intentional behavior? | 3.3 |
| 4 | Root cause | Internal logic, integration, or an external dependency? | 2.4b |
| 5 | Impact class | Exploitable vulnerability, or missing hardening? | 2.5 |

A finding must pass all five. Failing dimension 1 is rare; findings die on 2
through 5.

**The rule that catches the most false positives:** centralized control is not a
vulnerability. Privileged access is not a bug when it is intentional.

---

## Red flags

**Stop and reassess if any of these hold.**

### Scope

- Vulnerable component is infrastructure outside the analysis focus
- Component is a shared library spanning several systems
- Component does not match the stated objectives
- It is unclear whether the component is in scope

→ Request clarification **before** writing a PoC. Ambiguous is not "yes".

### Design intent

Three indicator *classes*, which is what `byDesignIndicators` counts:

- **Privilege identifiers** — an explicit check (`isAdmin`, `requiresOwner`), or a
  name implying deliberate power (`emergency*`, `override*`, `force*`)
- **Symmetric sibling paths** — the same pattern appears elsewhere, guarded and
  unguarded the same way, so it is not a one-off slip
- **Documentation or tests** — comments or the README describe it as a feature, or
  tests cover it as normal operation

→ **Two or more, plus a search of usage and test coverage, before marking
by-design.** One class firing is a flag to check, not a verdict, and `decideGate`
enforces that arithmetically: `byDesign: true` returns NOT_VULNERABLE only when
`byDesignIndicators` is 2 or more. Below the bar the analysis continues, so a
function called `forceUpdate()` cannot end it on its name.

### Root cause

- The exploit requires an external service to fail
- The exploit requires a dependency to misbehave
- The exploit requires a misconfiguration
- The missing validation is defense-in-depth rather than core logic

→ Classify as an integration issue and cap severity accordingly.

### Impact class

- The issue is "missing X" rather than "allows Y"
- It requires the user to harm themselves
- No external attacker is involved
- The impact is usability or convenience, not security

→ Classify as a hardening gap, not a vulnerability.

---

## Worked examples

Calibration for the judgment calls above.

**1. Missing input validation.** `processData(input)` does not validate; the
function is in scope; it should validate; the cause is internal; an attacker
supplies the input directly.
→ 5/5 clear. **HIGH.** Write the PoC.

**2. Admin bypasses a validation check.** `if (isAdmin) skipValidation()`. In
scope and technically real, but the privilege check is explicit and the pattern
is deliberate.
→ Fails dimension 3. **NOT A VULNERABILITY.** No PoC.

**3. No rate limit on password reset.** In scope, not by-design. But nothing in
the existing code can be *exploited* — a defense is absent.
→ Fails dimension 5. **Hardening gap**, medium priority, written up as such.

**4. Null dereference when the database returns an unexpected value.** In scope,
a genuine missing check. But it requires the database to misbehave first.
→ Dimension 4 is integration, not internal. **MEDIUM**, and the report must
state the external precondition.

---

## Additional questions for the adversarial pass

These extend the five challenges rather than replacing them:

1. Is this component in the analysis scope? Verify against an explicit statement.
2. Is this by-design? Check privilege indicators, naming, documentation, tests.
3. What is the root cause — internal, integration, or external?
4. Exploitable vulnerability or hardening gap?
5. What am I assuming? List each assumption and verify it with evidence.
