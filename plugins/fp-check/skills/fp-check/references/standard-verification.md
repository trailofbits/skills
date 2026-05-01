# Standard Verification

Linear single-pass checklist for straightforward bugs. No task creation — work through each step sequentially and document findings inline.

## Escalation Checkpoints

Two points in this checklist may trigger escalation to [deep-verification.md]({baseDir}/references/deep-verification.md):

1. **After Step 1 (Data Flow)**: Escalate if 3+ trust boundaries, callbacks/async control flow, or ambiguous validation chain
2. **After Step 5 (Devil's Advocate)**: Escalate if any question produces genuine uncertainty you cannot resolve

When escalating, hand off all evidence gathered so far — deep verification will continue from where you left off.

## Checklist

### Step 1: Data Flow

Trace data from source to the alleged vulnerability sink.

- Map trust boundaries crossed (internal/trusted vs external/untrusted)
- Identify all validation and sanitization between source and sink
- Check API contracts — many APIs have built-in bounds protection that prevents the alleged issue
- Check for environmental protections (compiler, runtime, OS, framework) that prevent exploitation entirely (not just raise the bar)
- Apply class-specific checks from [bug-class-verification.md]({baseDir}/references/bug-class-verification.md)

**Key pitfall**: Analyzing the vulnerable code in isolation. Conditional logic upstream may make the vulnerability mathematically unreachable. Trace the full validation chain.

**Escalation check**: If you found 3+ trust boundaries, callbacks or async control flow in the path, or an ambiguous validation chain — escalate to deep verification.

### Step 2: Exploitability

Prove the attacker can trigger the vulnerability.

- **Attacker control**: Prove the attacker controls data reaching the vulnerable operation. Internal storage set by trusted components is not attacker-controlled.
- **Bounds proof**: For integer/bounds issues, create an explicit algebraic proof using the template in [evidence-templates.md]({baseDir}/references/evidence-templates.md). Verify: IF validation_check_passes THEN bounds_guarantee_holds.
- **Race feasibility**: For race conditions, prove concurrent access is actually possible. Single-threaded initialization and synchronized contexts cannot have races.

### Step 3: Impact

Determine whether exploitation has real security consequences.

- Distinguish real security impact (RCE, privesc, info disclosure) from operational robustness issues (crash recovery, cleanup failure)
- Distinguish primary security controls from defense-in-depth. Failure of a defense-in-depth measure is not a vulnerability if primary protections remain intact.

### Step 4: PoC Sketch

Create a pseudocode PoC showing the attack path. Executable and unit test PoCs are optional for standard verification.

```
Data Flow: [Source] → [Validation?] → [Transform?] → [Vulnerable Op] → [Impact]
Attacker controls: [what input, how]
Trigger: [pseudocode showing the exploit path]
```

See [evidence-templates.md]({baseDir}/references/evidence-templates.md) for the full PoC template.

### Step 5: Devil's Advocate Spot-Check

Answer these 7 questions. If any produces genuine uncertainty, escalate to deep verification.

**Against the vulnerability:**

1. Am I seeing a vulnerability because the pattern "looks dangerous" rather than because it actually is? (pattern-matching bias)
2. Am I incorrectly assuming attacker control over trusted data? (trust boundary confusion)
3. Have I rigorously proven the mathematical condition for vulnerability can occur? (proof rigor)
4. Am I confusing defense-in-depth failure with a primary security vulnerability? (defense-in-depth confusion)
5. Am I hallucinating this vulnerability? LLMs are biased toward seeing bugs everywhere — is this actually real or am I pattern-matching on scary-looking code? (LLM self-check)

**For the vulnerability (always ask — false-negative protection):**

6. Am I dismissing a real vulnerability because the exploit seems complex or unlikely?
7. Am I inventing mitigations or validation logic that I haven't verified in the actual source code? Re-read the code after reaching a conclusion.

**Escalation check**: If any question above produces genuine uncertainty you cannot resolve with the evidence at hand — escalate to deep verification.

### Step 6: Gate Review

Apply all six gates from [gate-reviews.md]({baseDir}/references/gate-reviews.md) and all 13 items from [false-positive-patterns.md]({baseDir}/references/false-positive-patterns.md) to reach a verdict.
