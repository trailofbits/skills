---
name: half-closed-socket-finder
description: Finds half-closed socket handling issues
---

**Finding ID Prefix:** `HALFCLOSE` (e.g., HALFCLOSE-001, HALFCLOSE-002)

**The Core Issue:**
`shutdown(sock, SHUT_WR)` or `shutdown(sock, SHUT_RD)` creates a half-closed socket.
This can be exploitable when:
- Remote endpoint has a bug triggered only after "connection closed"
- Data still needs to be read/written via the half-closed socket

```c
shutdown(sock, SHUT_WR);  // No more writes, but can still read
// Application may not handle this state correctly
// Attacker can exploit vulnerability window
```

**Bug Patterns to Find:**

1. **Use After Partial Shutdown**
   ```c
   shutdown(sock, SHUT_RD);
   // Later...
   read(sock, buf, len);  // May return unexpected results
   ```

2. **Incomplete Shutdown Sequence**
   ```c
   shutdown(sock, SHUT_WR);  // Send EOF to remote
   // Should still drain incoming data
   // But code might not handle remaining reads
   ```

3. **Race Window After Shutdown**
   ```c
   shutdown(sock, SHUT_WR);
   // Attacker sends data in this window
   // Vulnerability in post-shutdown read handling
   ```

4. **State Machine Confusion**
   - Code expects fully closed connection
   - Half-closed state not handled

**Common False Positives to Avoid:**

- **Intentional half-close:** Protocol requires half-close for proper shutdown sequence
- **Data drained after shutdown:** Code properly reads remaining data before close
- **No further operations:** Socket is closed immediately after shutdown
- **Well-tested protocol implementation:** Standard protocol implementations handle this
- **UDP sockets:** Half-close semantics don't apply to UDP

**Search Patterns:**
```
shutdown\s*\(.*SHUT_WR|shutdown\s*\(.*SHUT_RD|shutdown\s*\(.*SHUT_RDWR
shutdown\s*\(.*[12]\)  # SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2
close\s*\(.*sock|closesocket\s*\(
```
