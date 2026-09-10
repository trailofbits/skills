# Bug-Class-Specific Verification

Different bug classes need different verification. Pass the class as
`finding.bugClass` in Step 0 and apply the requirements below **in addition to**
whatever the stage prompts ask for.

**The class you pass also picks the route**, so use one of these names. Four of
the nine escalate to the deep route, because for those the work the deep route
adds — the API-contract and environment pass, the algebraic bounds proof, the race
feasibility proof — *is* the verification, not an extra opinion on it.

| Class | Covers | Route |
|---|---|---|
| [Memory Corruption](#memory-corruption) | overflows, OOB, UAF, double-free, type confusion | **deep** |
| [Logic Bugs](#logic-bugs) | auth bypass, access control, state transitions, privesc | standard |
| [Race Conditions](#race-conditions) | TOCTOU, data races, signal handling | **deep** |
| [Integer Issues](#integer-issues) | overflow, underflow, truncation, signedness | **deep** |
| [Crypto Weaknesses](#crypto-weaknesses) | weak algorithms, nonce reuse, timing channels | standard |
| [Injection](#injection) | SQL, XSS, command, template, path traversal | standard |
| [Information Disclosure](#information-disclosure) | uninitialized memory, leaks, side channels | standard |
| [Denial of Service](#denial-of-service) | algorithmic complexity, resource exhaustion, crashes | **deep** |
| [Deserialization](#deserialization) | object injection, gadget chains | standard |

The route column is not documentation of a preference — it is checked.
`test_every_bug_class_has_a_routing_decision` fails the build if a class here has
no routing decision, and `test_select_route_recognises_every_bug_class_name`
extracts `selectRoute` and runs it against these exact strings. Adding a class
below without routing it breaks the build, which is the point: it used to inherit
`standard` in silence, and Memory Corruption spent a while taking the cheap path
with no bounds proof.

Passing a free-hand description instead of a name here still works — the matcher
covers the obvious spellings (`buffer overflow`, `use-after-free`, `OOB write`,
`algorithmic complexity`) — but a name is what the tests pin.

## Memory Corruption

Buffer overflow, heap overflow, stack overflow, out-of-bounds read/write, use-after-free, double-free, type confusion.

**Language safety check first:** Memory corruption in safe Rust, Go (without `unsafe.Pointer`/cgo), or managed languages (Java, C#, Python) is almost always a false positive — the type system or runtime prevents it. Verify whether the code is in an `unsafe` block (Rust), uses cgo/`unsafe.Pointer`/`reflect.SliceHeader` (Go), or reaches native memory another way: JNI, P/Invoke and `sun.misc.Unsafe` on the JVM and CLR, `ctypes`, `cffi`, a C extension or a misused buffer protocol in CPython.

**Then check the three exceptions before rejecting**, because "safe language" is a claim about the safe subset and not about the whole program:

- **A Go data race is not memory-safe.** Go's memory model gives racing programs undefined behaviour, and a torn write to an interface value or a slice header is real type confusion with a real OOB read behind it. So a Go memory-safety finding whose trigger is a race is not disposed of by "no `unsafe.Pointer` here" — it is a concurrency finding, and the deep route's race-feasibility proof is what decides it.
- **The `unsafe` block need not be the one you are looking at.** A safe wrapper that computes a length or an index which an `unsafe` block downstream trusts is where most real Rust findings live. Trace the value, not the block.
- **An attacker who supplies the `ctypes` call already has code execution**, so that is the attacker-already-holds-it ground in [dismissal-grounds.md](dismissal-grounds.md), not this one. What is *not* dismissed is attacker-controlled **data** reaching an existing native boundary — a size, an offset, a length passed to a C extension.

If none of those apply and the path is entirely in the safe subset, reject the memory corruption claim unless it involves a compiler bug or soundness hole.

**Verify:**

- What exactly gets corrupted? (which object, field, or memory region)
- What is the corruption size and offset? Can the attacker control them?
- Is the corruption a useful exploitation primitive (arbitrary read/write, vtable overwrite, function pointer overwrite) or just a crash?
- What allocator is in use (glibc, tcmalloc, jemalloc, Windows heap)? Does it have hardening that blocks exploitation?
- For UAF: trace the object lifetime — what frees it, what reuses the memory, can the attacker control the replacement object?
- For type confusion: prove the type mismatch exists and that misinterpretation of the data leads to a useful primitive.

## Logic Bugs

Authentication bypass, access control errors, incorrect state transitions, confused deputy, privilege escalation through API misuse.

**Verify:**

- Check against the specification, RFC, or design docs — not just the code. Does the implementation match the intended behavior?
- Map all state transitions. Can the system reach a state the developer didn't anticipate?
- Identify implicit assumptions that are never enforced in code.
- For auth bugs: verify ALL authentication/authorization paths, not just the one that appears broken. Is there a secondary check that catches it?
- Logic bugs pass every bounds check and mathematical proof — don't let clean static analysis convince you it's a false positive.

## Race Conditions

TOCTOU, data races, signal handling races, concurrent state modification.

**Verify:**

- What is the actual race window? Is it nanoseconds or seconds?
- Can the attacker widen the window (e.g., by stalling a thread with a slow NFS mount, large allocation, or CPU contention)?
- Verify the threading model: what threads/processes can actually access this data concurrently?
- Check all synchronization primitives in use — mutexes, atomics, RCU, lock-free structures.
- For TOCTOU on filesystem: can the attacker control the path between check and use (symlink races)?

## Integer Issues

Overflow, underflow, truncation, signedness errors, wraparound.

**Verify:**

- What are the exact integer types and their ranges at every point in the computation?
- Is the overflow signed (undefined behavior in C/C++ — compiler may exploit this) or unsigned (defined wraparound)?
- Trace the integer through all casts, conversions, and promotions. Where does truncation or sign extension occur?
- After the integer issue occurs, is the resulting value actually used in a dangerous way (allocation size, array index, loop bound)?
- Check if compiler warnings (`-Wconversion`, `-Wsign-compare`) flag this.

## Crypto Weaknesses

Weak algorithms, bad parameters, nonce reuse, padding oracle, insufficient randomness, timing side channels.

**Verify:**

- Check parameter choices against current standards (NIST, IETF) and known attacks. "AES-128" is fine; "DES" is not.
- Verify randomness sources. Is the PRNG cryptographically secure? Is it properly seeded?
- For nonce reuse: prove the same nonce can actually be used twice in practice, not just theoretically.
- For timing side channels: is the code actually reachable by an attacker who can measure timing? Network jitter may make remote timing attacks impractical.
- Compare the implementation against a reference implementation or test vectors from the spec.

## Injection

SQL injection, XSS, command injection, server-side template injection, path traversal, LDAP injection.

**Verify:**

- Trace attacker input from entry point to the sink (query, command, template, filesystem path). Is there any sanitization or escaping along the way?
- Check if the framework provides automatic escaping (e.g., parameterized queries, template auto-escaping). If so, is it actually enabled and not bypassed?
- For XSS: what context does the input land in (HTML body, attribute, JavaScript, URL)? Each requires different escaping.
- For path traversal: is the path canonicalized before the access check? Can `../` or null bytes bypass validation?
- Test actual payload delivery through all intermediate processing — encoding, decoding, and transformation steps may neutralize or enable the payload.

## Information Disclosure

Uninitialized memory reads, error message leaks, timing side channels, padding oracles.

**Verify:**

- What specific data leaks? Not all leaks are equal — a stack leak revealing ASLR base or canary is critical; one revealing a static string is worthless.
- Is the leaked data actually useful to an attacker for further exploitation (ASLR bypass, session tokens, crypto keys)?
- For uninitialized memory: prove the memory is actually uninitialized at the point of read, not just potentially uninitialized on some code path.
- For timing side channels: can the attacker make enough measurements with sufficient precision? What's the noise level?
- For error messages: does the error path actually reach the attacker, or is it logged server-side only?

## Denial of Service

Algorithmic complexity, resource exhaustion, crash bugs, infinite loops, memory bombs.

**Verify:**

- What is the resource consumption ratio? Attacker sends X bytes, server consumes Y resources. Is the amplification meaningful?
- Can the resource be reclaimed (connection closes, memory freed) or is it permanent exhaustion?
- For algorithmic complexity: what is the actual worst-case input? Prove it triggers worst-case behavior, don't just claim O(n²).
- For crash bugs: is the crash reliably triggerable, or does it depend on specific heap/stack layout?
- Does the service restart automatically? A crash that causes a 100ms restart is different from one that requires manual intervention.

## Deserialization

Unsafe deserialization, object injection, gadget chain exploitation.

**Verify:**

- Does the attacker actually control the serialized data that reaches the deserialization call?
- **Does this format even need a gadget chain?** Some do not, and requiring one there turns an immediate RCE into a "design smell". Python `pickle` executes an attacker-chosen callable directly through `__reduce__` — `os.system` is in the standard library and no chain is needed; PyYAML's `yaml.load` without `SafeLoader` constructs arbitrary objects the same way. Java `ObjectInputStream`, PHP `unserialize`, Ruby `Marshal` and .NET `BinaryFormatter` **do** need a gadget: the format calls magic methods on types that must already be present.
- Where a gadget chain IS required: does a usable one exist in the classpath or import graph? Without one, unsafe deserialization on those formats is a design smell rather than a demonstrated bug — but say which formats you mean, and check the version, because a chain that lands in a later release retroactively makes it one.
- What deserialization library and version is in use? Are there known gadget chains for it?
- Are there type restrictions, allowlists, or look-ahead deserialization filters that block dangerous classes?
