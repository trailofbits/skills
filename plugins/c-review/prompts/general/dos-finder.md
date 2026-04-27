---
name: dos-finder
description: Detects denial of service vulnerabilities
---

**Finding ID Prefix:** `DOS` (e.g., DOS-001, DOS-002)

**Bug Patterns to Find:**

1. **High Resource Usage**
   - Unbounded memory allocation from user input
   - Unbounded loop iterations
   - Exponential algorithm on attacker input

2. **Resource Leaks**
   - Memory not freed on error paths
   - File descriptors not closed
   - Connections not released

3. **Inefficient Copies**
   - Large container passed by value
   - Unnecessary deep copies
   - String concatenation in loops

4. **Dangling References**
   - Reference to moved-from object
   - Reference in lambda captures after move

5. **Algorithmic Complexity**
   - O(n²) or worse on user input
   - Hash collision attacks possible
   - Regex backtracking (ReDoS)

**Common False Positives to Avoid:**

- **Bounded allocations:** Allocations with verified upper bounds (e.g., `if (size > MAX) return`)
- **Internal-only code:** Code paths not reachable from untrusted input
- **Intentional resource limits:** System-level limits (ulimits) may be in place
- **Rate limiting present:** External rate limiting may prevent exploitation
- **Streaming processing:** Code that processes data in fixed-size chunks

**Search Patterns:**
```
malloc\s*\(.*user|malloc\s*\(.*input|malloc\s*\(.*size
while\s*\(1\)|for\s*\(;;\)|for\s*\(.*<.*input
vector<.*>\s+\w+\s*=|string\s+\w+\s*=.*\+
std::move\s*\(
```
