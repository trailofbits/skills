# Test-Integrated PoCs

Consumed by the Stage 3 builder at checkpoint 4.1. **Prefer this form.** The
project's own harness supplies the real-code invocation for free, which is what
the real-code rule requires and what standalone scripts most often violate.

## The convention

A security test **fails while the vulnerability exists and passes once it is
fixed.** It then survives as a permanent regression test.

This is the opposite of the instinct to write a test that "demonstrates the
exploit working", and getting it backwards is a live failure mode — an earlier
version of this file carried docstrings claiming "if this test PASSES the
vulnerability exists" above assertions that failed when it existed.

**Write the docstring to match the assertion, then re-read both.**

```python
def test_sqli_union_extracts_passwords(client):
    """
    SECURITY: SQL injection via UNION in the search endpoint.

    FAILS while the vulnerability exists (the password hash comes back).
    PASSES once the query is parameterized.

    The fix is to bind `q` as a parameter instead of concatenating it.
    """
    payload = "' UNION SELECT password_hash FROM users WHERE username='admin'--"
    response = client.get(f"/search?q={payload}")

    assert "secret123" not in response.text, (
        "VULNERABILITY: SQL injection allows extracting password hashes"
    )
```

## Framework detection

Look for the marker file, then follow the project's existing test layout and
naming rather than imposing your own.

| Marker | Framework | Run |
|--------|-----------|-----|
| `pytest.ini`, `pyproject.toml`, `tests/` | pytest | `pytest -m security` |
| `package.json` with `jest` | Jest | `npm test` |
| `*_test.go` | Go testing | `go test ./... -run Security` |
| `Cargo.toml` | cargo test | `cargo test` |
| `pom.xml` | JUnit via Maven | `mvn test` |
| `build.gradle`, `build.gradle.kts` | JUnit via Gradle | `./gradlew test` |

## Naming and isolation

- Name the test for the vulnerability: `test_vuln_<type>_<component>`
- Tag it so it can be run alone — `@pytest.mark.security`, a `Security` prefix
  in Go, a `describe("security", ...)` block in Jest
- Keep security tests runnable in isolation; they often need fixtures or
  timing tolerances the rest of the suite does not

## Four rules

1. **Make it loud.** The assertion message states the vulnerability and its
   impact, so a future failure is self-explaining to someone who has no context.
2. **Assert the negative.** Assert that the dangerous outcome does *not* occur —
   `assert "secret" not in response.text`, `assert balance >= 0`. Asserting only
   the happy path (`assert status == 200`) proves nothing about security.
3. **Document the fix in the docstring.** The next reader needs to know what
   makes the test pass, not just that it currently fails.
4. **Assert on impact, not on execution.** That an error occurred is not a
   finding; that data was disclosed is.

## When a test-integrated PoC will not work

Escalate to a standalone script when there is no test suite, when the exploit
needs a running service the harness cannot start, or when timing or concurrency
cannot be reproduced inside the test runner. Record which of these applies —
"there was no suite" and "the suite was inconvenient" are different answers.
