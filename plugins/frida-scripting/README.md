# frida-scripting

A Claude Code skill for developing Frida scripts that provide introspection and manipulation of macOS and iOS binaries.

## What It Does

Teaches Claude how to write production-quality Frida scripts for dynamic instrumentation on Apple platforms. Covers the Objective-C and Swift runtimes, Interceptor API, Stalker code tracing, memory operations, and platform-specific constraints (SIP, code signing, jailbreak requirements).

## Skills

| Skill | Type | Description |
|-------|------|-------------|
| [frida-scripting](skills/frida-scripting/SKILL.md) | Tool | Develops Frida scripts for hooking functions, tracing execution, inspecting memory, and interacting with ObjC/Swift runtimes on macOS and iOS |

## Reference Files

| File | Contents |
|------|----------|
| [ios-specifics.md](skills/frida-scripting/references/ios-specifics.md) | iOS setup (jailbroken + stock), Gadget configuration, pinning bypass, jailbreak detection bypass |
| [macos-specifics.md](skills/frida-scripting/references/macos-specifics.md) | SIP, hardened runtime, entitlements, XPC instrumentation, macOS connection modes |
| [objc-swift-patterns.md](skills/frida-scripting/references/objc-swift-patterns.md) | ObjC method dispatch, class enumeration, Swift hooking, blocks, thread safety |
| [script-patterns.md](skills/frida-scripting/references/script-patterns.md) | Reusable patterns: argument logger, module dumper, crypto monitor, network monitor, Stalker tracing |
| [troubleshooting.md](skills/frida-scripting/references/troubleshooting.md) | Connection issues, script errors, hook not firing, crashes, performance, version compatibility |

## Installation

Install this plugin in Claude Code:

```bash
claude plugin add /path/to/frida-scripting
```

## Requirements

- [Frida](https://frida.re/) (`pip install frida-tools`)
- For iOS: USB-connected device (jailbroken or with Gadget-embedded app)
- For macOS: Target process accessible (SIP considerations apply for Apple-signed binaries)
