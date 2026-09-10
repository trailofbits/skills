# PoC Anti-Patterns

Consumed by the Stage 3 builder. Everything here is a rule about how the PoC is
*constructed*; the mechanical checks live in `scripts/poc-lint.sh` and are not
repeated as prose.

> Placeholder, ellipsis, TODO and narration detection is the linter's job:
> `{baseDir}/scripts/poc-lint.sh --symbol <symbol under test> <poc-file>`
> Run it before returning. Do not hand-grep for these patterns.

---

## Negative proofs after a Stage 1 refusal

Demonstrating that a guard **rejects** the payload is evidence for a refutation,
not a PoC for the reported finding. It is optional because Stage 1 already
decided the verdict, and it stays within four boundaries:

- Drive the **entry point**. Calling the sink directly is still an exploit and
  only shows that the sink is dangerous in isolation.
- Assert the refusal, so the proof fails if the payload reaches the sink.
- Do not place it beside confirmed-vulnerability or exploit framing.
- If it unexpectedly reaches the sink, re-dispatch Stage 1 with that new fact;
  do not report from the negative proof alone.

---

## 1. Reimplementation — the failure that invalidates everything

> This rule is what `poc-lint.sh` calls **Principle 5**, and the linter can only
> carry half of it. Pass `--symbol <the symbol under test>` — qualified or not,
> in the form the code uses; for `a.b.c` and `a::c` it keys on `c` — or it prints
> `Principle 5 NOT checked` and neither rule behind that flag runs.
>
> With a symbol it enforces exactly one thing: **rule 8**, that the name appears
> somewhere in your code. A PoC that never names the symbol cannot be calling it.
> That is *mention*, not invocation, and the clean line says so.
>
> **Rule 6 is a note, not a gate.** It reports a definition of that name in your
> PoC and does not change the exit code, because a grep cannot tell a copy of the
> target from the `def main()` driver a standalone PoC legitimately has. A clean
> exit is therefore not a finding that you did not reimplement — the rest of this
> section is addressed to you and to the reviewer, not to the linter.

**A PoC that copies the vulnerable code and calls the copy only proves the copy
is broken.** It says nothing about the application. The real code may have
surrounding validation, different configuration, compiler flags, or recovery
that changes the outcome — which is exactly what Stage 1 spent its effort
establishing.

### Copying the function

```python
# WRONG — reimplements the vulnerable function
def vulnerable_parse(data):
    # Copied from target/parser.py:47
    offset, limit = int(data["offset"]), int(data["limit"])
    return buffer[offset : offset + limit]  # integer overflow

vulnerable_parse({"offset": "2147483647", "limit": "10"})
```

```python
# RIGHT — calls the real code
from target.parser import parse_request

try:
    parse_request({"offset": "2147483647", "limit": "10"})
    raise AssertionError("expected OverflowError")
except OverflowError:
    pass  # proves the real parser overflows
```

### Mocking the vulnerable component

This is the subtle one, and the boundary is worth stating precisely.

```javascript
// WRONG — mocks away the very thing under test.
// The "exploit" works against the mock, not the application.
jest.mock("../src/auth", () => ({
  validateToken: (t) => JSON.parse(atob(t.split(".")[1])),
}));
```

```javascript
// RIGHT — mock the dependency, never the target
jest.mock("../src/database");
const auth = require("../src/auth");

// Assert the NEGATIVE — this is a TEST-INTEGRATED PoC, so it FAILS while the
// real auth is bypassed and passes once the signature is verified. Asserting
// that the exploit works is backwards HERE: it would go green while the bug
// exists and red once it is fixed, which is a regression test for the bug. A
// standalone PoC (the Python one above) asserts the opposite, because nothing
// runs it in CI. See test-integration.md.
//
// Write the assertion against the behaviour the FIX will have. `const result =
// await auth.validateToken(...); expect(result.admin).toBe(false)` looks like
// the same thing and is not: a fixed validateToken never returns a token to
// inspect, so that form is red before the fix AND after it, which is a broken
// test rather than a demonstration.
await expect(auth.validateToken(craftMaliciousJWT({ admin: true }))).rejects.toThrow();
```

### What is acceptable

- Mocking **dependencies** of the vulnerable code — databases, network, external APIs
- Test fixtures that set up state the vulnerable code operates on
- Helper functions that craft payloads or measure impact, but not the vulnerable logic
- Minimal wrappers that call the real code with instrumentation

### If reimplementation is detected

The linter's `possible-reimplementation` note is where you will usually see the
candidate, and it exits 0 regardless — grep cannot tell a façade re-export or a
local driver from a copy. The decision is made on the two files, by the reviewer
who checks the artifact, and it is recorded as `reimplementation`:
`COPY_OF_TARGET` returns BLOCKED for the whole stage. When it is a copy, say so
in this form and stop:

```text
⚠️ REIMPLEMENTATION DETECTED — this PoC does not test real code.

Found:  vulnerable function copied from target/parser.py:47 into the PoC
Issue:  proves the copy is broken, not that the application is exploitable
Action: import and call target.parser.parse_request() directly
Status: BLOCKED until fixed
```

---

## 2. Verify in the process that runs the payload

The second-most common way a PoC is silently wrong. If the payload executes on
the target, verification must observe something **the target** does. Checking
local state after sending a payload to a remote host cannot detect the
vulnerability, and reports "not vulnerable" for a target that is — a false
negative, which is the worst outcome for a tool whose job is proving bugs exist.

```python
# WRONG — payload runs on the target, marker checked locally
requests.post(target, data=pickle_payload)
if os.path.exists("/tmp/poc_successful"):   # this machine, not the target
    ...
```

```javascript
// WRONG — pollution happens in the TARGET's Node process
await fetch(`${TARGET}/api/merge`, { method: "POST", body: payload });
const testObj = {};
if (testObj.polluted === true) { ... }   // inspects THIS process
```

Verify instead by one of:

- **Out-of-band callback** — the payload calls a listener you control. Works
  regardless of where the code ran.
- **Target-observable side effect** — a subsequent response that changes, a log
  line, a database row.

If the target cannot reach your listener, do not fall back to a local check.
Either move the listener somewhere reachable or assert on a target-side effect.

**Confirming a precondition is not confirming impact.** A polluted prototype is
not RCE until the target actually spawns a child process; assert on the spawn's
effect, not on the pollution.

---

## 3. Required PoC structure

Every PoC has all of these. The linter enforces the mechanical parts; these are
the ones that need judgment.

| Section | Requirement |
|---------|-------------|
| Setup | Dependencies declared, install and run commands stated, versions pinned where they matter |
| Real code invocation | Imports and calls the symbol under test — record which one |
| Payload | Concrete attacker input, fully specified, no parameters left abstract |
| Execution | Actually calls the vulnerable path. Not commented out, not narrated |
| Validation | Asserts on the *impact*, not merely that the code ran |
| Cleanup | Restores state, or documents what is irreversible |

**Assert on impact.** `assert response.status_code == 500` proves an error
occurred; `assert "secret123" in response.text` proves data was disclosed. Only
the second one is a finding.

---

## 4. Rationalizations to reject

| Rationalization | Why it is wrong | Required action |
|-----------------|-----------------|-----------------|
| "I'll print what would happen" | Proves nothing | Write code that does it |
| "It works in theory" | Theory is not proof | Run it, capture the output |
| "I'll reimplement the logic to show it's broken" | Proves your copy is broken | Call the real code |
| "Same algorithm, so same bug" | Environment, config and guards differ | Exercise the real deployment path |
| "Panics crash the process" | Many runtimes recover — see `recovery-mechanisms.md` | Prove nothing catches it |
| "The prototype is polluted, so it's RCE" | Pollution is a precondition, not an impact | Assert on the spawn side effect |
| "It's a placeholder, I'll fill it in later" | Later does not arrive | `poc-lint.sh` must exit 0 before you return |

---

## 5. Obscure gadgets worth remembering

Most exploit primitives a model already knows. These three are the ones that
tend not to surface unprompted:

- **Node prototype pollution → RCE:** polluting `env` with
  `NODE_OPTIONS: "--require /proc/self/environ"` yields execution *when the
  target subsequently spawns a child process*.
- **PHP magic hash:** `'0e462097431906509019562988736854'` compares equal to
  `"0"` under `==` because both parse as `0e...` scientific notation.
- **Path traversal filter bypass:** `....//` survives a naive single-pass
  `../` strip, which reassembles it into `../`.
