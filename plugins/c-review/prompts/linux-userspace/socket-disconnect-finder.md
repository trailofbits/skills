---
name: socket-disconnect-finder
description: Identifies socket disconnect handling issues
---

**Finding ID Prefix:** `SOCKDISCON` (e.g., SOCKDISCON-001, SOCKDISCON-002)

**The Core Issue:**
`connect(sock, AF_UNSPEC)` can disconnect an already-connected TCP socket.
The socket can then be reconnected to a different address.

```c
// sock is connected to legitimate server
struct sockaddr sa = { .sa_family = AF_UNSPEC };
connect(sock, &sa, sizeof(sa));  // Disconnects!
// sock can now be reconnected to attacker server
```

This has been used for nsjail escapes and other sandbox bypasses.

**Bug Patterns to Find:**

1. **Attacker Control Over connect() Arguments**
   ```c
   connect(sock, user_provided_addr, len);
   // If user can set sa_family = AF_UNSPEC, they can disconnect
   ```

2. **Socket Reuse After Error**
   ```c
   if (connect(sock, addr1, len) < 0) {
       // Error path - socket might be disconnected
       connect(sock, addr2, len);  // Reconnecting
   }
   ```

3. **UDP Socket Address Override**
   - UDP sockets can have default destination changed
   - AF_UNSPEC removes the default destination

**Common False Positives to Avoid:**

- **Address family validated:** Code checks `addr->sa_family` before passing to connect
- **Trusted address source:** Address structure comes from trusted internal source, not user input
- **Sandbox already restricts connect:** Seccomp or other sandbox limits connect syscall
- **Socket not reused:** Socket is closed and recreated rather than reconnected
- **Intentional disconnect:** Code deliberately uses AF_UNSPEC to reset socket state

**Search Patterns:**
```
connect\s*\(
AF_UNSPEC
sockaddr.*sa_family
bind\s*\(|listen\s*\(|accept\s*\(
```
