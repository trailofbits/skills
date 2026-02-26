---
name: seatbelt-sandboxer
description: "Generates minimal macOS Seatbelt sandbox configurations. Use when sandboxing, isolating, or restricting macOS applications with allowlist-based profiles."
allowed-tools:
  - Read
  - Write
  - Bash
  - Glob
  - Grep
---

# macOS Seatbelt Sandbox Profiling

Generate minimally-permissioned allowlist-based Seatbelt sandbox configurations for applications.

## When to Use

- User asks to "sandbox", "isolate", or "restrict" an application on macOS
- Sandboxing any macOS process that needs restricted file/network access
- Creating defense-in-depth isolation if supply chain attacks are a concern

## When NOT to Use

- Linux containers (use seccomp-bpf, AppArmor, or namespaces instead)
- Windows applications
- Applications that legitimately need broad system access
- Quick one-off scripts where sandboxing overhead isn't justified

## Profiling Methodology

### Step 1: Identify Application Requirements

Determine what the application needs across these resource categories:

| Category | Operations | Common Use Cases |
|----------|------------|------------------|
| **File Read** | `file-read-data`, `file-read-metadata`, `file-read-xattr`, `file-test-existence`, `file-map-executable` | Reading source files, configs, libraries |
| **File Write** | `file-write-data`, `file-write-create`, `file-write-unlink`, `file-write-mode`, `file-write-xattr`, `file-clone`, `file-link` | Output files, caches, temp files |
| **Network** | `network-bind`, `network-inbound`, `network-outbound` | Servers, API calls, package downloads |
| **Process** | `process-fork`, `process-exec`, `process-exec-interpreter`, `process-info*`, `process-codesigning*` | Spawning child processes, scripts |
| **Mach IPC** | `mach-lookup`, `mach-register`, `mach-bootstrap`, `mach-task-name` | System services, XPC, notifications |
| **POSIX IPC** | `ipc-posix-shm*`, `ipc-posix-sem*` | Shared memory, semaphores |
| **Sysctl** | `sysctl-read`, `sysctl-write` | Reading system info (CPU, memory) |
| **IOKit** | `iokit-open`, `iokit-get-properties`, `iokit-set-properties` | Hardware access, device drivers |
| **Signals** | `signal` | Signal handling between processes |
| **Pseudo-TTY** | `pseudo-tty` | Terminal emulation |
| **System** | `system-fsctl`, `system-socket`, `system-audit`, `system-info` | Low-level system calls |
| **User Prefs** | `user-preference-read`, `user-preference-write` | Reading/writing user defaults |
| **Notifications** | `darwin-notification-post`, `distributed-notification-post` | System notifications |
| **AppleEvents** | `appleevent-send` | Inter-app communication (AppleScript) |
| **Camera/Mic** | `device-camera`, `device-microphone` | Media capture |
| **Dynamic Code** | `dynamic-code-generation` | JIT compilation |
| **NVRAM** | `nvram-get`, `nvram-set`, `nvram-delete` | Firmware variables |

For each category, determine: **Needed?** and **Specific scope** (paths, services, etc.)

If the application has multiple subcommands that perform significantly different operations, such as `build` and `serve` commands for a Javascript bundler like Webpack, do the following:
* Profile the subcommands separately
* Create separate Sandbox configurations for each subcommand
* Create a helper script that acts as a drop-in replacement for the original binary, executing the sandboxed application with the appropriate Seatbelt profile according to the subcommand passed.

### Step 2: Start with Minimal Profile

Begin with deny-all and essential process operations, saved in a suitably-named Seatbelt profile file with the `.sb` extension.

```scheme
(version 1)
(deny default)

;; Essential for any process
(allow process-exec*)
(allow process-fork)
(allow sysctl-read)

;; Metadata access (stat, readdir) - doesn't expose file contents
(allow file-read-metadata)
```

### Step 3: Add File Read Access (Allowlist)

Use `file-read-data` (not `file-read*`) for allowlist-based reads:

```scheme
(allow file-read-data
    ;; System paths (required for most runtimes)
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/System")
    (subpath "/Library")
    (subpath "/opt")                    ;; Homebrew
    (subpath "/private/var")
    (subpath "/private/etc")
    (subpath "/private/tmp")
    (subpath "/dev")

    ;; Root symlinks for path resolution
    (literal "/")
    (literal "/var")
    (literal "/etc")
    (literal "/tmp")
    (literal "/private")

    ;; Application-specific config (customize as needed)
    (regex (string-append "^" (regex-quote (param "HOME")) "/\\.myapp(/.*)?$"))

    ;; Working directory
    (subpath (param "WORKING_DIR")))
```

**Why `file-read-data` instead of `file-read*`?**
- `file-read*` allows ALL file read operations including from any path
- `file-read-data` only allows reading file contents from listed paths
- Combined with `file-read-metadata` (allowed broadly), this gives:
  - ✅ Can stat/readdir anywhere (needed for path resolution)
  - ❌ Cannot read contents of files outside allowlist

### Step 4: Add File Write Access (Restricted)

```scheme
(allow file-write*
    ;; Working directory only
    (subpath (param "WORKING_DIR"))

    ;; Temp directories
    (subpath "/private/tmp")
    (subpath "/tmp")
    (subpath "/private/var/folders")

    ;; Device files for output
    (literal "/dev/null")
    (literal "/dev/tty"))
```

### Step 5: Configure Network

Three levels of network access:

```scheme
;; OPTION 1: Block all network (most restrictive - use for build tools)
(deny network*)

;; OPTION 2: Localhost only (use for dev servers, local services)
;; Bind to local ports
(allow network-bind (local tcp "*:*"))
;; Accept inbound connections
(allow network-inbound (local tcp "*:*"))
;; Outbound to localhost + DNS only
(allow network-outbound
    (literal "/private/var/run/mDNSResponder")  ;; DNS resolution
    (remote ip "localhost:*"))                   ;; localhost only

;; OPTION 3: Allow all network (least restrictive - avoid if possible)
(allow network*)
```

**Network filter syntax:**
- `(local tcp "*:*")` - any local TCP port
- `(local tcp "*:8080")` - specific local port
- `(remote ip "localhost:*")` - outbound to localhost only
- `(remote tcp)` - outbound TCP to any host
- `(literal "/private/var/run/mDNSResponder")` - Unix socket for DNS

### Step 6: Test Iteratively

After you generate or edit the Seatbelt profile, test the functionality of the target application in the sandbox. If anything fails to work, revise the Seatbelt profile. Repeat this process iteratively until you have generated a minimally-permissioned Seatbelt file and have confirmed empirically that the application works normally when sandboxed using the Seatbelt profile you generated.

If the program requires external input to function fully (such as a Javascript bundler that needs an application to bundle), find sample inputs from well-known, ideally official sources. For instance, these example projects for the Rspack bundler: https://github.com/rstackjs/rstack-examples/tree/main/rspack/

```bash
# Test basic execution
sandbox-exec -f profile.sb -D WORKING_DIR=/path -D HOME=$HOME /bin/echo "test"

# Test the actual application
sandbox-exec -f profile.sb -D WORKING_DIR=/path -D HOME=$HOME \
  /path/to/application --args

# Test security restrictions
sandbox-exec -f profile.sb -D WORKING_DIR=/tmp -D HOME=$HOME \
  cat ~/.ssh/id_rsa
# Expected: Operation not permitted
```

**Common failure modes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| Exit code 134 (SIGABRT) | Sandbox violation | Check which operation is blocked |
| Exit code 65 + syntax error | Invalid profile syntax | Check Seatbelt syntax |
| `ENOENT` for existing files | Missing `file-read-metadata` | Add `(allow file-read-metadata)` |
| Process hangs | Missing IPC permissions | Add `(allow mach-lookup)` if needed |

## Seatbelt Syntax Reference

### Path Filters
```scheme
(subpath "/path")           ;; /path and all descendants
(literal "/path/file")      ;; Exact path only
(regex "^/path/.*\\.js$")   ;; Regex match
```

### Parameter Substitution
```scheme
(param "WORKING_DIR")                                    ;; Direct use
(subpath (param "WORKING_DIR"))                          ;; In subpath
(string-append (param "HOME") "/.config")                ;; Concatenation
(regex-quote (param "HOME"))                             ;; Escape for regex
```

### Operations

**File operations:**
```scheme
(allow file-read-data ...)          ;; Read file contents
(allow file-read-metadata)          ;; stat, lstat, readdir (no contents)
(allow file-read-xattr ...)         ;; Read extended attributes
(allow file-test-existence ...)     ;; Check if file exists
(allow file-map-executable ...)     ;; mmap executable (dylibs)
(allow file-write-data ...)         ;; Write to existing files
(allow file-write-create ...)       ;; Create new files
(allow file-write-unlink ...)       ;; Delete files
(allow file-write* ...)             ;; All write operations
(allow file-read* ...)              ;; All read operations (use sparingly)
```

**Process operations:**
```scheme
(allow process-exec* ...)           ;; Execute binaries
(allow process-fork)                ;; Fork child processes
(allow process-info-pidinfo)        ;; Query process info
(allow signal)                      ;; Send/receive signals
```

**Network operations:**
```scheme
(allow network-bind (local tcp "*:*"))              ;; Bind to any local TCP port
(allow network-bind (local tcp "*:8080"))           ;; Bind to specific port
(allow network-inbound (local tcp "*:*"))           ;; Accept TCP connections
(allow network-outbound (remote ip "localhost:*"))  ;; Outbound to localhost only
(allow network-outbound (remote tcp))               ;; Outbound TCP to any host
(allow network-outbound
    (literal "/private/var/run/mDNSResponder"))     ;; DNS via Unix socket
(allow network*)                                    ;; All network (use sparingly)
(deny network*)                                     ;; Block all network
```

**IPC operations:**
```scheme
(allow mach-lookup ...)             ;; Mach IPC lookups
(allow mach-register ...)           ;; Register Mach services
(allow ipc-posix-shm* ...)          ;; POSIX shared memory
(allow ipc-posix-sem* ...)          ;; POSIX semaphores
```

**System operations:**
```scheme
(allow sysctl-read)                 ;; Read system info
(allow sysctl-write ...)            ;; Modify sysctl (rare)
(allow iokit-open ...)              ;; IOKit device access
(allow pseudo-tty)                  ;; Terminal emulation
(allow dynamic-code-generation)     ;; JIT compilation
(allow user-preference-read ...)    ;; Read user defaults
```

## Known Limitations

1. **Deprecated but functional**: Apple deprecated sandbox-exec but it works through macOS 14+
2. **Temp directory access often required**: Many applications need `/tmp` and `/var/folders`

## Example: Generic CLI Application

```scheme
(version 1)
(deny default)

;; Process
(allow process-exec*)
(allow process-fork)
(allow sysctl-read)

;; File metadata (path resolution)
(allow file-read-metadata)

;; File reads (allowlist)
(allow file-read-data
    (literal "/") (literal "/var") (literal "/etc") (literal "/tmp") (literal "/private")
    (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/opt")
    (subpath "/System") (subpath "/Library") (subpath "/dev")
    (subpath "/private/var") (subpath "/private/etc") (subpath "/private/tmp")
    (subpath (param "WORKING_DIR")))

;; File writes (restricted)
(allow file-write*
    (subpath (param "WORKING_DIR"))
    (subpath "/private/tmp") (subpath "/tmp") (subpath "/private/var/folders")
    (literal "/dev/null") (literal "/dev/tty"))

;; Network disabled
(deny network*)
```

**Usage:**
```bash
sandbox-exec -f profile.sb \
  -D WORKING_DIR=/path/to/project \
  -D HOME=$HOME \
  /path/to/application
```

## References

- [Apple Sandbox Guide (reverse-engineered)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- [sandbox-exec man page](https://keith.github.io/xcode-man-pages/sandbox-exec.1.html)
