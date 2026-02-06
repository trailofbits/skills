# frida-ios-security

A Claude Code audit skill for iOS application security assessment using Frida.

## What It Does

Provides a systematic methodology for auditing iOS app security controls at runtime. Covers the full assessment lifecycle: reconnaissance of an app's protection surface, domain-by-domain testing (data storage, network, authentication, anti-tampering, platform, crypto, memory), bypass verification with impact analysis, and evidence-based reporting mapped to OWASP MASVS categories.

## Skills

| Skill | Type | Description |
|-------|------|-------------|
| [frida-ios-security](skills/frida-ios-security/SKILL.md) | Audit | Systematic iOS security assessment using Frida — data protection, network security, authentication, anti-tampering, and platform controls |

## Reference Files

| File | Contents |
|------|----------|
| [protection-bypasses.md](skills/frida-ios-security/references/protection-bypasses.md) | Frida scripts for testing certificate pinning, keychain protection, biometric auth, jailbreak detection, debugger detection, URL schemes, pasteboard |
| [data-extraction.md](skills/frida-ios-security/references/data-extraction.md) | Runtime data extraction: keychain dump, cookies, crypto keys, file protection, memory search, screenshot protection, log analysis |

## Related Skills

| Skill | Relationship |
|-------|-------------|
| [frida-scripting](../frida-scripting/) | Frida API reference (Interceptor, Stalker, ObjC, Memory) — use for general scripting guidance |

## Requirements

- [Frida](https://frida.re/) (`pip install frida-tools`)
- iOS device: jailbroken with frida-server, or target app re-signed with Frida Gadget
- Connection verified: `frida-ps -U` lists device processes
