# False Positive Patterns — Lessons Learned

Apply ALL items in this checklist to EACH potential bug during verification.

Contents:

- [Checklist](#checklist) — 13 items to apply to every bug (trace validation, confirm data paths, bounds logic, TOCTOU, trust boundaries, real vs theoretical impact, defense-in-depth)
- [The devil's advocate questions](#the-devils-advocate-questions) — the 13 the deep route answers, of which 7 are the standard route's spot check. **This is the list Stage 1f is told to work through**, and it is not the same list as the checklist above
- [Red Flags for False Positives](#red-flags-for-false-positives) — recurring failure patterns: pattern-based, context-blind, math/bounds, API-contract

## Checklist

### 1. Trace Full Validation Chain

Don't analyze isolated code snippets. Trace backwards to find ALL validation that precedes potentially dangerous operations. Network packet size operations may look dangerous but often have bounds validation earlier in the function.

### 1a. Map Complete Conditional Logic Flow

Vulnerable-looking code may be unreachable due to conditional logic that creates mathematical guarantees. Example: array access `buffer[length-4]` appears unsafe when `length < 4`, but if the code is only reachable when `length > 12` due to earlier validation, the vulnerability is impossible.

**Verify:**

- What conditions must be met for execution to reach the alleged vulnerability?
- Do those conditions mathematically prevent the vulnerability scenario?
- Are there minimum size/length requirements that guarantee safe access?
- Does the conditional flow create impossible-to-violate bounds?

### 2. Identify Defensive Programming Patterns

Distinguish between actual vulnerabilities and defensive assertions/validations. `ASSERT(size == expected_size)` followed by size-controlled operations is defensive, not vulnerable. Verify that checks actually prevent the alleged vulnerability.

### 3. Confirm Exploitable Data Paths

Only report vulnerabilities with CONFIRMED exploitable data flow paths. Don't assume network-controlled data reaches dangerous functions without tracing the actual path step by step.

### 4. Understand Data Source Context

Distinguish between data sources and their trust levels. API return values, compile-time constants, and network data have different risk profiles. Determine the actual source and whether it is attacker-controlled.

### 5. Analyze Bounds Validation Logic

Look for mathematical relationships between validation checks and subsequent operations. If `packet_size >= MIN_SIZE` is checked and `MIN_SIZE >= sizeof(header)`, then `packet_size - sizeof(header)` cannot underflow.

### 6. Verify TOCTOU Claims

Time-of-check-time-of-use issues require proof that the checked value can change between check and use. If a size is checked and immediately used in the same function with no external modification possible, there is no TOCTOU.

### 7. Understand API Contract and Trust Boundaries

Always understand API contracts before claiming buffer overflows. Some APIs have built-in bounds protection and cannot write beyond the buffer regardless of input parameters.

### 8. Distinguish Internal Storage from External Input

Internal storage systems (configuration stores, registries) are controlled by trusted components, not attackers. Values set during installation by trusted components are not attacker-controlled.

### 9. Don't Confuse Pattern Recognition with Vulnerability Analysis

Code patterns that "look vulnerable" may be safely implemented due to context and API contracts. Size parameters being modified doesn't mean buffer overflow if the API prevents writing beyond bounds.

### 10. Verify Concurrent Access is Actually Possible

Don't assume race conditions exist without proving concurrent access patterns. Single-threaded initialization contexts cannot have race conditions. Verify the threading model and synchronization mechanisms.

### 11. Assess Real vs Theoretical Security Impact

Focus on vulnerabilities with actual security impact. Storage failure for non-critical data is an operational issue, not a security vulnerability. Ask: would this lead to code execution, privilege escalation, or information disclosure?

### 12. Understand Defense-in-Depth vs Primary Controls

Failure of defense-in-depth mechanisms is not always a vulnerability if primary protections exist. Token cleanup failure is not critical if tokens are single-use by design at the server.

### 13. Apply the Checklist Rigorously, Not Superficially

Having a checklist doesn't prevent false positives if it isn't applied systematically. For EVERY potential vulnerability, work through ALL checklist items before concluding.

---

## The devil's advocate questions

**One list, and the route decides how much of it you answer.** The deep route
answers all 13. The standard route answers the **7 marked ★**, which are the ones
that dispose of the most findings for the least reading — they are not a different
list, so the two cannot drift apart.

Both routes finish with 12 and 13, which argue *for* the finding. They are not
optional and they carry equal weight: a triage tool that only guards one direction
drifts toward it, and losing a real bug costs more than reporting a doubtful one.
The dismissal-side guards in [dismissal-grounds.md](dismissal-grounds.md) extend them.

Assume you are biased toward finding bugs and toward rating them critical. These
questions exist to work against that bias, not to be recited.

**Against the finding:**

1. What non-vulnerability explanations exist for this code pattern?
2. How would the original developers justify this implementation?
3. What crucial system architecture context might be missing?
4. ★ Am I seeing a vulnerability because the pattern "looks dangerous" rather than because it actually is? (pattern-matching bias)
5. Even if validation looks insufficient, does it actually prevent the claimed condition?
6. ★ Am I incorrectly assuming attacker control over trusted data? (trust boundary confusion)
7. ★ Have I rigorously proven the mathematical condition for the vulnerability can occur? (proof rigor)
8. Beyond theoretical possibility, is this practically exploitable?
9. ★ Am I confusing a defense-in-depth failure with a primary security vulnerability?
10. What compiler, runtime or OS protections might prevent exploitation?
11. ★ Am I hallucinating this vulnerability? LLMs are biased toward seeing bugs everywhere and rating every finding critical — is this real, or am I pattern-matching on scary-looking code?

**For the finding (false-negative protection):**

12. ★ Am I dismissing a real vulnerability because the exploit seems complex or unlikely?
13. ★ Am I inventing mitigations or validation logic I have not verified in the actual source? Re-read the code after reaching a conclusion.

**A question you cannot resolve with the evidence at hand is not a pass.** Put it
in `unresolvedUncertainty`; it returns NEEDS MORE INFO, which is a supported
outcome. On the standard route it is also the signal that the finding wanted the
deep one.

---

## Red Flags for False Positives

### Pattern-Based False Positives

- Reporting vulnerabilities in validation/bounds-checking code itself
- Claiming TOCTOU without proving the value can change
- Ignoring preceding validation logic
- Assuming network data reaches operations without tracing the path
- Confusing defensive programming (assertions/checks) with vulnerabilities
- Analyzing vulnerable-looking patterns without tracing conditional logic that controls reachability
- Reporting "vulnerabilities" in error handling or cleanup code
- Flagging size calculations without understanding mathematical constraints
- Identifying "dangerous" functions without checking if inputs are bounded
- Claiming buffer overflows in fixed-size operations with compile-time bounds
- Reporting race conditions in single-threaded or synchronized contexts

### Context-Blind Analysis False Positives

- Analyzing code snippets without understanding broader system design
- Ignoring architectural guarantees (single-writer, trusted input sources)
- Missing that "vulnerable" code is unreachable due to earlier validation
- Confusing debug/development code paths with production paths
- Reporting issues in code that only runs during trusted installation/setup
- Flagging theoretical issues that cannot occur due to system architecture
- Missing that alleged vulnerabilities are prevented by framework or language guarantees
- Reporting issues in test-only or debug-only code paths as production vulnerabilities

### Mathematical/Bounds Analysis False Positives

- Reporting integer underflow without proving the mathematical condition can occur
- Claiming buffer overflow when bounds are mathematically guaranteed by validation
- Missing that conditional logic creates mathematical impossibility of vulnerable conditions
- Reporting off-by-one errors without checking if loop bounds prevent the condition
- Claiming memory corruption when allocation sizes are verified sufficient
- Reporting arithmetic overflow without checking if input ranges prevent the condition

### API Contract Misunderstanding False Positives

- Claiming buffer overflows when APIs have built-in bounds checking
- Reporting memory corruption for APIs that manage their own memory safely
- Missing that return values are already validated by the API contract
- Confusing API parameter modification with vulnerability when API prevents unsafe modification
- Reporting issues explicitly handled by the API's safety guarantees
- Missing that seemingly dangerous operations are safe due to API implementation details
