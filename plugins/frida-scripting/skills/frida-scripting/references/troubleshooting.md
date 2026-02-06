# Frida Troubleshooting Guide

## Connection and Attachment Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| "Failed to attach: unable to access process" | SIP protecting the process (macOS) | Check `csrutil status`; target non-Apple binaries, or disable SIP for research |
| "Failed to attach: unable to access process" | Missing `get-task-allow` entitlement | Re-sign with: `codesign -f -s "ID" --entitlements ents.plist /path/to/app` (add `com.apple.security.get-task-allow` = `true` to entitlements) |
| "Failed to spawn: unable to find application" | Wrong bundle identifier | Use `frida-ps -Ua` to list installed apps with their bundle IDs |
| "Failed to connect to remote frida-server" | frida-server not running on device | SSH into device and start: `frida-server &` |
| "Unable to communicate with device" | USB trust not established | Unlock device, tap "Trust" on the prompt |
| "Process terminated" on attach | Crash caused by instrumentation | Use spawn mode (`frida -U -f <bundle-id>`) to attach cleanly at startup |
| No device listed in `frida-ps -U` | usbmuxd not running (Linux) | `sudo systemctl start usbmuxd` or install `libimobiledevice` |

## Script Runtime Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Error: expected a pointer` | Passing wrong type to `Interceptor.attach` | Ensure target is a `NativePointer`, not a string. Use `Module.findExportByName()` |
| `Error: unable to find method` | ObjC method doesn't exist on this class | Check with `ObjC.classes.X.$ownMethods` — method may be on a superclass or category |
| `Error: access violation reading 0x0` | Dereferencing null pointer in callback | Add null checks: `if (args[0].isNull()) return;` |
| `TypeError: not a function` | Calling a property as a method | ObjC properties need `()`: `obj.name()` not `obj.name` |
| `Error: script is destroyed` | Script unloaded while callbacks pending | Keep script session alive; avoid detaching too early |
| `RangeError: invalid array length` | `readByteArray` with wrong size | Verify size argument: `data.length()` may return an ObjC object, use `.valueOf()` |

## Hook Not Firing

When an `Interceptor.attach` succeeds but the callback never executes:

### Diagnostic Checklist

1. **Verify the address is correct**
   ```javascript
   const addr = Module.findExportByName('libfoo.dylib', 'target_func');
   console.log(`Hook target: ${addr}`);
   // If null, the function doesn't exist in that module
   ```

2. **Check if the function is actually called**
   ```javascript
   // Use frida-trace first to confirm
   // frida-trace -U -i 'target_func' AppName
   ```

3. **Check for inlined functions**
   - Small functions may be inlined by the compiler — no call instruction exists
   - Verify in disassembly (Ghidra/IDA) that the function is actually called, not inlined

4. **Check method dispatch**
   - ObjC methods may be dispatched through `forwardInvocation:` or method resolution
   - Swift methods may use vtable dispatch instead of direct calls
   - Use `ApiResolver('objc')` to find the actual implementation address

5. **Check the module name**
   ```javascript
   // Module name is case-sensitive and must include extension
   Module.findExportByName('Security', 'func')       // Framework
   Module.findExportByName('libsqlite3.dylib', 'func') // Dylib
   Module.findExportByName(null, 'func')               // Any module
   ```

6. **Check for address space layout randomization**
   - Addresses change each launch — never hardcode addresses between sessions
   - Always resolve dynamically via `Module.findExportByName()` or `Module.findBaseAddress()` + offset

## Target Process Crashes

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Crash in `onEnter` | Reading invalid argument | Add `try/catch` around argument access |
| Crash in `onLeave` | Modifying return value with wrong type | Match exact return type expected by caller |
| Crash after `Interceptor.replace()` | ABI mismatch in replacement | Ensure `NativeCallback` matches original function signature exactly |
| Crash on `ObjC.choose()` | Heap corruption or racing GC | Run on main thread: `ObjC.schedule(ObjC.mainQueue, ...)` |
| Crash during Stalker trace | Instrumenting incompatible code | Use `Stalker.exclude()` for system frameworks |
| SIGABRT after attach | Code signature invalidated | Use spawn mode, or re-sign the binary |

### Safe Callback Pattern

Always wrap callbacks to prevent target crashes:

```javascript
Interceptor.attach(target, {
  onEnter(args) {
    try {
      // Your hook logic here
    } catch (e) {
      console.log(`[!] Error in onEnter: ${e.message}`);
    }
  },
  onLeave(retval) {
    try {
      // Your hook logic here
    } catch (e) {
      console.log(`[!] Error in onLeave: ${e.message}`);
    }
  }
});
```

## Performance Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Target becomes sluggish | Too many hooks or logging | Reduce hook count; use `send()` instead of `console.log` for bulk data |
| `console.log` bottleneck | Synchronous message passing | Batch messages: collect in array, send periodically |
| Stalker overwhelming output | Tracing too many modules | Use `Stalker.exclude()` aggressively; trace only target modules |
| Memory growth over time | String allocations in hooks not freed | Allocate strings globally, not per-call |
| Frida CLI unresponsive | Large data in console output | Use `send()` with binary data instead of `console.log(hexdump(...))` |

### Efficient Logging Pattern

```javascript
// Instead of console.log per event:
const buffer = [];
const FLUSH_INTERVAL = 1000;  // ms

function log(msg) {
  buffer.push(msg);
  if (buffer.length >= 100) flush();
}

function flush() {
  if (buffer.length > 0) {
    send({ type: 'log', entries: buffer.splice(0) });
  }
}

setInterval(flush, FLUSH_INTERVAL);
```

## Version Compatibility

| Issue | Diagnosis | Resolution |
|-------|-----------|------------|
| "Unable to load script" | Frida client/server version mismatch | Ensure `frida --version` matches device's frida-server version |
| API method not found | Using API from newer Frida version | Check `Frida.version` in script; consult changelog for API availability |
| Gadget crash on load | Gadget version incompatible with app | Download Gadget matching your `frida-tools` version |

### Checking Versions

```bash
# Client version
frida --version

# Server version (on device)
ssh root@device "frida-server --version"

# In-script version check
console.log(`Frida ${Frida.version} on ${Process.platform}/${Process.arch}`);
```

## Common Mistakes

| Mistake | Why It Fails | Correct Approach |
|---------|-------------|------------------|
| `Interceptor.attach('open', ...)` | `attach` expects a `NativePointer`, not a string | `Interceptor.attach(Module.findExportByName(null, 'open'), ...)` |
| `args[2].toString()` on an ObjC object | `toString()` on `NativePointer` gives hex address | `new ObjC.Object(args[2]).toString()` |
| Hardcoding addresses | Addresses change with ASLR | Always resolve symbols at runtime |
| `retval = ptr(1)` in `onLeave` | Assignment doesn't modify return value | `retval.replace(ptr(1))` |
| Reading freed memory in `onLeave` | Arguments may be freed between `onEnter` and `onLeave` | Save values in `onEnter` using `this.savedValue = ...` |
| Hooking in a loop | Creates duplicate hooks, degrading performance | Hook once at script initialization |
