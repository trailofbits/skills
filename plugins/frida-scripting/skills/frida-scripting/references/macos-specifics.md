# macOS-Specific Frida Guide

## System Integrity Protection (SIP)

SIP restricts which processes can be instrumented, even by root.

### SIP Status

```bash
csrutil status
# "System Integrity Protection status: enabled."
```

### What SIP Blocks

| Restricted | Example | Can Frida Attach? |
|-----------|---------|-------------------|
| Apple-signed system binaries | `/usr/bin/open`, `/usr/sbin/sysctl` | No (with SIP on) |
| Apple system frameworks loaded in protected processes | Safari, Mail | No (with SIP on) |
| Your own apps | `/Applications/MyApp.app` | Yes |
| Apps from other developers (not Apple-signed) | Chrome, Firefox | Yes (with caveats) |
| Processes you spawn yourself | `./my_binary` | Yes |

### Working With SIP Enabled

For most reverse engineering and security research, you can instrument:
- Third-party applications (non-Apple-signed)
- Your own builds and binaries
- Command-line tools you compile yourself
- Apps launched through Frida spawn mode

### Disabling SIP (When Necessary)

Only disable SIP when you must instrument Apple system processes:

1. Boot into Recovery Mode (Intel: Cmd+R at startup; Apple Silicon: hold power button)
2. Open Terminal from Utilities menu
3. `csrutil disable`
4. Reboot

**Re-enable after your analysis**: `csrutil enable`

## Hardened Runtime

macOS apps can opt into the Hardened Runtime, which restricts:
- Dynamic library injection (`DYLD_INSERT_LIBRARIES` ignored)
- `task_for_pid` access (needed for Frida injection)
- Debugger attachment

### Checking Hardened Runtime

```bash
codesign -d --entitlements - /path/to/app 2>&1
```

Look for:
- `com.apple.security.cs.allow-dylib-code-injection` — allows DYLD injection
- `com.apple.security.cs.disable-library-validation` — allows unsigned dylib loading
- `com.apple.security.get-task-allow` — allows debugger/Frida attachment

### Instrumenting Hardened Apps

| Scenario | Approach |
|----------|----------|
| App has `get-task-allow` (debug build) | Frida attaches normally |
| App lacks `get-task-allow` (release build) | Re-sign with entitlement, or use Gadget |
| Apple-signed with Hardened Runtime + SIP | Requires SIP disabled |

### Re-signing with Entitlements

```bash
# Extract current entitlements
codesign -d --entitlements :- /path/to/app > entitlements.plist

# Add get-task-allow
/usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" entitlements.plist

# Re-sign
codesign -f -s "Your Developer ID" --entitlements entitlements.plist /path/to/app
```

## macOS Installation

```bash
# Via pip
pip install frida-tools

# Via Homebrew
brew install frida
```

### Verify

```bash
frida-ps         # List local processes
frida-ps -U      # List USB device processes (for attached iOS device)
```

## macOS Connection Modes

| Mode | Command | Target |
|------|---------|--------|
| Local process by name | `frida Calculator` | macOS app |
| Local process by PID | `frida -p 1234` | macOS process |
| Spawn local app | `frida -f /Applications/App.app/Contents/MacOS/App` | macOS app (fresh) |
| USB-connected iOS device | `frida -U AppName` | iOS app |

## macOS-Specific Patterns

### Hooking Objective-C in macOS Apps

macOS apps (AppKit-based) use the same ObjC runtime as iOS:

```javascript
// Hook NSApplication delegate
Interceptor.attach(
  ObjC.classes.NSApplication['- sendEvent:'].implementation, {
    onEnter(args) {
      const event = new ObjC.Object(args[2]);
      console.log(`Event type: ${event.type()}`);
    }
  }
);
```

### DYLD Interposition (Alternative to Frida for Simple Cases)

For macOS, `DYLD_INSERT_LIBRARIES` can interpose functions without Frida:

```bash
# Only works if app doesn't have Hardened Runtime or has allow-dylib-code-injection
DYLD_INSERT_LIBRARIES=./interpose.dylib /path/to/app
```

When to prefer DYLD interposition over Frida:
- Simple function replacement with no runtime logic
- Need persistence across launches without running Frida
- Lower overhead requirements

When to prefer Frida:
- Dynamic, scriptable analysis
- ObjC runtime introspection
- Need to modify hooks without recompiling

### XPC Service Instrumentation

macOS apps often use XPC services. To hook them:

```javascript
// Find the XPC service process
// frida-ps | grep -i "com.example.app.helper"

// Attach to the XPC service separately
// frida -p <xpc-service-pid> -l xpc_hooks.js

// In xpc_hooks.js:
Interceptor.attach(Module.findExportByName(null, 'xpc_connection_send_message'), {
  onEnter(args) {
    const msg = args[1];
    console.log('XPC message sent');
  }
});
```

### Security Framework Hooks

Common security-related hooks for macOS analysis:

```javascript
// Code signing verification
Interceptor.attach(Module.findExportByName('Security', 'SecCodeCheckValidity'), {
  onEnter(args) {
    console.log('Code signing check');
  },
  onLeave(retval) {
    console.log(`Result: ${retval.toInt32()}`);  // 0 = valid
  }
});

// Authorization Services
Interceptor.attach(Module.findExportByName('Security', 'AuthorizationCreate'), {
  onEnter(args) {
    console.log('Authorization request');
  }
});
```

## macOS Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "Failed to attach: unexpected error" | SIP protecting the process | Check `csrutil status`; use non-Apple targets |
| "Unable to access task for pid" | Hardened Runtime without `get-task-allow` | Re-sign with entitlement or use Gadget |
| Process crashes on attach | Code signing invalidation | Re-sign after Frida detaches, or use spawn mode |
| `DYLD_INSERT_LIBRARIES` ignored | Hardened Runtime or SIP | Use Frida injection instead |
| frida-server not found | Local-mode only on macOS | `frida` (no `-U`) for local; `-U` for iOS via USB |
