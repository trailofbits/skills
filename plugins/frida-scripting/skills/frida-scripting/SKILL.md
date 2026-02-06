---
name: frida-scripting
description: >
  Develops Frida scripts for dynamic instrumentation, introspection, and
  manipulation of macOS and iOS binaries. Use when hooking functions, tracing
  execution, inspecting memory, or interacting with the Objective-C and Swift
  runtimes at runtime on Apple platforms.
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Bash
---

# Frida Scripting for macOS and iOS

Frida is a dynamic instrumentation toolkit that injects a JavaScript runtime (QuickJS) into target processes, providing direct access to memory, function hooks, and runtime metadata. This skill teaches how to write production-quality Frida scripts for introspection and manipulation of Mach-O binaries on macOS and iOS, with emphasis on the Objective-C runtime, Interceptor API, Stalker tracing, and platform-specific constraints.

The core value of Frida over static analysis: you observe **actual runtime behavior** — real arguments, return values, object graphs, and code paths that static tools can only approximate.

## When to Use

- Hooking Objective-C or Swift methods to observe arguments, return values, and call sequences
- Intercepting C/C++ functions in Mach-O binaries (crypto APIs, network calls, file I/O)
- Tracing execution flow through unfamiliar code with Stalker
- Reading and writing process memory to inspect data structures at runtime
- Bypassing or analyzing security mechanisms (jailbreak detection, certificate pinning, entitlement checks)
- Enumerating classes, methods, and modules in a running process
- Prototyping binary analysis workflows before committing to static RE

## When NOT to Use

- **Static structure analysis** — Use Ghidra, IDA, or Hopper to understand binary layout, cross-references, and control flow graphs before reaching for Frida
- **Kernel instrumentation** — Frida is user-space only; use dtrace or kernel debugging for kernel-level analysis
- **Encrypted iOS binaries** — Decrypt first (e.g., via `frida-ios-dump` or similar) before attempting to hook
- **Simple function tracing on macOS** — `dtrace` is lighter-weight and doesn't require injection for basic syscall/function tracing
- **Persistent modifications** — Frida hooks are ephemeral (process lifetime); use binary patching for permanent changes
- **Performance-critical production monitoring** — Frida adds overhead; use `os_signpost`, Instruments, or eBPF for production telemetry

## Decision Tree

```text
What are you trying to do?

├─ Observe function calls (arguments + return values)?
│  ├─ Objective-C method?
│  │  └─ Use Interceptor.attach on ObjC method implementation
│  │     See: references/objc-swift-patterns.md
│  │
│  ├─ Swift method?
│  │  └─ Check if it bridges to ObjC (most UIKit/Foundation do)
│  │     ├─ ObjC-bridged → Hook via ObjC.classes
│  │     └─ Pure Swift → Find mangled symbol with Module.enumerateExports()
│  │        Hook with Interceptor.attach (args are raw registers)
│  │
│  └─ C/C++ function?
│     └─ Resolve with Module.findExportByName() or DebugSymbol.fromName()
│        Hook with Interceptor.attach
│
├─ Trace execution flow through unknown code?
│  └─ Use Stalker.follow() with call/block/exec events
│     See: Stalker section below
│
├─ Enumerate classes, methods, or modules?
│  ├─ ObjC classes → ObjC.enumerateLoadedClasses()
│  ├─ Methods on a class → ObjC.classes.ClassName.$methods
│  ├─ Loaded modules → Process.enumerateModules()
│  └─ Exports in a module → Module.enumerateExports()
│
├─ Read or modify memory?
│  └─ Use NativePointer read/write methods or Memory.scan()
│     See: references/script-patterns.md
│
├─ Replace a function entirely?
│  └─ Use Interceptor.replace() with NativeCallback
│     Caution: must match exact calling convention
│
└─ Instrument on a non-jailbroken iOS device?
   └─ Use Frida Gadget embedded in the app
      See: references/ios-specifics.md
```

## Platform Selection

```text
What platform are you targeting?

├─ macOS
│  ├─ SIP enabled (default)?
│  │  ├─ Your own app or entitled app → Works with Frida
│  │  └─ System process / Apple-signed → Frida blocked
│  │     See: references/macos-specifics.md
│  └─ SIP disabled?
│     └─ Full access to all processes
│
└─ iOS
   ├─ Jailbroken device?
   │  └─ Install frida-server via package manager
   │     Full access to all processes
   │     See: references/ios-specifics.md
   │
   └─ Stock (non-jailbroken) device?
      ├─ Your own app (development profile)?
      │  └─ Use Gadget injection or debugserver attach
      └─ Third-party app?
         └─ Re-sign with Gadget embedded
            See: references/ios-specifics.md
```

## Quick Reference

| Task | API / Command |
|------|--------------|
| List processes | `frida-ps -U` (USB) or `frida-ps -D <id>` |
| Trace ObjC method | `frida-trace -U -m '-[ClassName methodName:]' <app>` |
| Trace C function | `frida-trace -U -i 'CCCrypt*' <app>` |
| Attach to running process | `frida -U <app>` (REPL) |
| Spawn and instrument | `frida -U -f com.example.app` (add `--pause` to halt on spawn) |
| Load script file | `frida -U -l script.js <app>` |
| Hook ObjC method (JS) | `Interceptor.attach(ObjC.classes.X['- method:'].implementation, {...})` |
| Hook C export (JS) | `Interceptor.attach(Module.findExportByName(null, 'open'), {...})` |
| Enumerate exports | `Module.enumerateExports('libSystem.B.dylib')` |
| Scan memory | `Memory.scan(base, size, 'DE AD BE EF', {onMatch(addr, size) {...}})` |
| Allocate string | `Memory.allocUtf8String('replacement')` |

## Core Workflow

### 1. Identify the Target

Before writing hooks, understand what you're instrumenting:

```javascript
// List loaded modules
Process.enumerateModules().forEach(m => {
  console.log(`${m.name} @ ${m.base} (${m.size})`);
});

// Find specific exports
Module.enumerateExports('Security').forEach(e => {
  if (e.name.includes('SecItem'))
    console.log(`${e.type} ${e.name} @ ${e.address}`);
});
```

### 2. Attach Hooks

```javascript
// ObjC method hook
const impl = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation;
Interceptor.attach(impl, {
  onEnter(args) {
    // args[0] = self, args[1] = _cmd, args[2] = NSURLRequest
    const request = new ObjC.Object(args[2]);
    console.log(`URL: ${request.URL().absoluteString()}`);
  },
  onLeave(retval) {
    console.log(`Task: ${new ObjC.Object(retval)}`);
  }
});
```

```javascript
// C function hook
Interceptor.attach(Module.findExportByName('libSystem.B.dylib', 'open'), {
  onEnter(args) {
    this.path = args[0].readUtf8String();
  },
  onLeave(retval) {
    console.log(`open("${this.path}") = ${retval.toInt32()}`);
  }
});
```

### 3. Validate Results

Always verify hooks are firing and arguments are correct before building complex scripts. Use `frida -U -l script.js <app>` with small, focused hooks first.

## Interceptor Patterns

### Attach vs Replace

| Use | When |
|-----|------|
| `Interceptor.attach()` | Observe calls without changing behavior — logging, tracing, argument inspection |
| `Interceptor.replace()` | Change function behavior entirely — bypass checks, return fake data |

### Argument Handling

Interceptor callbacks receive raw `NativePointer` arguments. Converting them depends on the function signature:

| Argument Type | Conversion |
|--------------|------------|
| C string (`char *`) | `args[N].readUtf8String()` |
| Integer | `args[N].toInt32()` or `.toUInt32()` |
| Pointer to struct | `args[N].readByteArray(size)` |
| ObjC object | `new ObjC.Object(args[N])` |
| Return value (ObjC) | `new ObjC.Object(retval)` |

### Preserving State Across onEnter/onLeave

Use `this` to pass data between callbacks:

```javascript
Interceptor.attach(target, {
  onEnter(args) {
    this.fd = args[0].toInt32();     // Save for onLeave
  },
  onLeave(retval) {
    console.log(`fd=${this.fd} → ${retval.toInt32()}`);
  }
});
```

## Stalker: Code Tracing

Use Stalker for execution flow analysis when you don't know which functions matter.

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
  events: { call: true, ret: false, exec: false },
  onReceive(events) {
    const parsed = Stalker.parse(events, { annotate: true, stringify: true });
    parsed.forEach(e => console.log(JSON.stringify(e)));
  }
});

// Stop after a duration
setTimeout(() => Stalker.unfollow(), 5000);
```

**Stalker constraints:**
- High overhead — use `Stalker.exclude()` to skip known-safe modules (libc, libdispatch)
- AArch64 and x86_64 only — check `Process.arch` before using
- Block-level events generate massive output — prefer `call` events for initial analysis

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|----------------|----------------|
| "The function name looks right, I'll hook it" | Verify with `Module.enumerateExports()` or `ObjC.classes.X.$methods` — names can be misleading, especially with C++ mangling or Swift name mangling |
| "It works in the iOS Simulator" | The Simulator runs x86_64/arm64 macOS binaries, not real iOS — runtime behavior, entitlements, and frameworks differ significantly |
| "I'll just trace everything with Stalker" | Unscoped Stalker tracing crashes or hangs most non-trivial apps — always use `Stalker.exclude()` and time-bound tracing |
| "The hook isn't firing, so the function isn't called" | More likely: wrong module, wrong symbol name, method dispatched through a different selector, or the function is inlined. Verify the address is correct |
| "I'll use `Interceptor.replace()` for logging" | Replace changes behavior; use `attach` for observation. Replace without matching the exact ABI crashes the target |
| "ObjC.choose() will find all instances" | `ObjC.choose()` scans the heap and is slow — only use it for targeted object discovery, not routine inspection |

## Anti-Patterns

| Anti-Pattern | Problem | Correct Approach |
|-------------|---------|------------------|
| Hooking inside `onEnter` | Re-entrant hooks cause infinite recursion | Set up all hooks at script load time |
| Not caching `args[N]` | Repeated access has overhead per call | `const arg = args[0];` then use `arg` |
| Global string allocation in `onEnter` | Memory leak per call | Allocate once globally or use `this` pattern |
| `console.log` in hot paths | Frida message passing is synchronous and slow | Batch with `send()` or filter before logging |
| Ignoring thread safety | ObjC objects accessed from wrong thread crash | Use `ObjC.schedule(ObjC.mainQueue, fn)` for UI objects |

## Spawn vs Attach

| Mode | When to Use | Command |
|------|-------------|---------|
| **Attach** | Process is already running; you want to hook specific behavior on demand | `frida -U <name-or-pid>` |
| **Spawn** | You need to hook initialization code, `+[load]`, or early framework setup | `frida -U -f <bundle-id>` |

Spawn mode is essential for:
- Hooking jailbreak detection that runs in `didFinishLaunching`
- Intercepting certificate pinning setup in `+[load]` or static initializers
- Catching early file/keychain access

## Best Practices

| Practice | Why |
|----------|-----|
| Start with `frida-trace` before writing custom scripts | Validates targets exist and are hookable |
| Cache argument reads: `const x = args[0]` | Avoids repeated framework overhead |
| Store allocated memory on `this` or globally | Prevents garbage collection of replaced buffers |
| Use `try/catch` in all callbacks | Unhandled exceptions crash the target process |
| Scope hooks to specific modules | `Module.findExportByName('libfoo.dylib', 'func')` avoids ambiguity |
| Test on the target platform, not the Simulator | Runtime behavior differs between Simulator and device |

## Platform-Specific Guides

| Platform | Guide |
|----------|-------|
| iOS (jailbroken + stock) | [references/ios-specifics.md](references/ios-specifics.md) |
| macOS (SIP + hardened runtime) | [references/macos-specifics.md](references/macos-specifics.md) |
| ObjC & Swift patterns | [references/objc-swift-patterns.md](references/objc-swift-patterns.md) |
| Reusable script templates | [references/script-patterns.md](references/script-patterns.md) |
| Common problems | [references/troubleshooting.md](references/troubleshooting.md) |

## Resources

**[Frida Documentation](https://frida.re/docs/home/)**
Official reference for all APIs, tools, and platform-specific setup.

**[Frida JavaScript API](https://frida.re/docs/javascript-api/)**
Complete API reference for Interceptor, Stalker, ObjC, Memory, Module, and all runtime objects.

**[Frida CodeShare](https://codeshare.frida.re/)**
Community-contributed scripts demonstrating real-world instrumentation patterns.
