---
name: frida-ios-security
description: >
  Audits iOS application security controls at runtime using Frida. Systematically
  tests data protection, network security, authentication, platform interactions,
  and anti-tampering mechanisms. Use when performing security assessments of iOS
  apps, verifying protection implementations, or testing bypass resilience.
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Bash
---

# Frida iOS Security Assessment

Systematic methodology for auditing iOS application security controls at runtime using Frida. This skill covers the full assessment lifecycle: reconnaissance of an app's protection surface, runtime testing of each security domain, bypass verification with impact analysis, and evidence-based reporting.

iOS apps implement security controls that static analysis alone cannot verify — certificate pinning may be present in code but bypassed by configuration, jailbreak detection may check files that don't exist on modern jailbreaks, and data protection classes may be set but not enforced. Runtime instrumentation with Frida is the authoritative way to test whether these controls actually work.

## Prerequisites

- **Frida installed** (`pip install frida-tools`) — see **frida-scripting** skill for setup details
- **iOS device connected** — jailbroken with frida-server, or target app re-signed with Frida Gadget
- **Connection verified** — `frida-ps -U` lists device processes
- **Spawn mode** for early hooks: `frida -U -f com.example.app -l script.js`
- **Attach mode** for running apps: `frida -U AppName -l script.js`

## When to Use

- Performing a security assessment of an iOS application (pentest, audit, or review)
- Verifying that an app's security controls resist bypass at runtime
- Testing whether sensitive data is protected at rest, in transit, and in memory
- Assessing anti-tampering and anti-reverse-engineering controls
- Validating compliance with OWASP MASVS requirements via dynamic testing
- Investigating suspicious app behavior by instrumenting runtime operations

## When NOT to Use

- **Static analysis of IPA contents** — Use Ghidra, IDA, or class-dump for binary structure analysis before reaching for Frida
- **Server-side security testing** — This skill covers client-side controls only; use web/API testing tools for backend
- **Android app security** — Android has different runtime primitives; use the appropriate Android methodology
- **Kernel or bootchain analysis** — Frida is user-space only
- **General Frida API usage** — Use the **frida-scripting** skill for Interceptor/Stalker/ObjC API reference
- **App Store compliance review** — This is security testing, not policy compliance

## Rationalizations to Reject

| Rationalization | Why It's Wrong |
|----------------|----------------|
| "The app uses certificate pinning, so the network layer is secure" | Pinning implementations vary wildly — many are bypassable with a single Interceptor hook. Always verify the specific implementation |
| "Jailbreak detection is present, so the app is hardened" | Most jailbreak detection checks 5-10 filesystem paths that are trivially spoofed. Detection without response (crash, wipe) is security theater |
| "The data is encrypted in the Keychain" | Keychain protection class matters — `kSecAttrAccessibleAlways` is effectively no protection. Verify the actual class used at runtime |
| "I bypassed the check, so it's a finding" | Bypass without impact assessment is incomplete. What does bypassing this control actually expose? A cosmetic label change is LOW; accessing auth tokens is CRITICAL |
| "The hook didn't fire, so the protection isn't there" | More likely: wrong method, wrong class, protection runs before your hook attaches, or protection is in a framework you didn't instrument. Investigate before concluding absence |
| "This app is too complex to fully test" | Scope the assessment to specific security domains (MASVS categories). Partial coverage with evidence is better than no coverage with excuses |
| "It works on my jailbroken device, so it's fine" | Jailbroken device behavior differs from stock — anti-tamper controls may not fire, code signing checks may be disabled. Validate on the target environment |
| "The developer says this feature is deprecated" | Deprecated code still runs. If it's in the binary, it's in scope |

## Quick Reference

| Security Domain | What to Test | Severity if Missed |
|----------------|-------------|-------------------|
| Data at rest | Keychain protection classes, file protection, NSUserDefaults secrets | CRITICAL |
| Network security | Certificate pinning, ATS configuration, cleartext traffic | HIGH |
| Authentication | Biometric bypass, token storage, session management | CRITICAL |
| Anti-tampering | Jailbreak detection, integrity checks, debugger detection | MEDIUM |
| Platform security | URL scheme injection, pasteboard leakage, extension data sharing | HIGH |
| Cryptography | Key storage, algorithm strength, random number generation | HIGH |
| Data in memory | Sensitive data persistence, screenshot protection, keyboard cache | MEDIUM |

## Severity Classification

| Severity | Criteria | Example |
|----------|----------|---------|
| CRITICAL | Bypass grants access to authentication material, user credentials, or enables arbitrary actions as the user | Keychain items with auth tokens accessible without biometrics after bypass |
| HIGH | Bypass exposes sensitive user data, PII, or weakens a primary security control | Certificate pinning bypass allows MitM of API calls containing personal data |
| MEDIUM | Bypass weakens defense-in-depth or exposes non-sensitive operational data | Jailbreak detection bypass with no other protections gating sensitive operations |
| LOW | Bypass has minimal security impact or affects only cosmetic/informational controls | Debug logging contains non-sensitive metadata |

## Audit Workflow

Each phase MUST complete before the next. Do not skip reconnaissance.

### Phase 1: Reconnaissance

Map the app's security surface before testing anything.

**Inputs:** Target app installed on device, Frida connected
**Outputs:** Protection inventory with locations and types
**Quality gate:** All 7 security domains in Quick Reference assessed for presence/absence

```javascript
// 1. Enumerate all classes to understand app structure
const appModule = Process.findModuleByName('AppBinary');
ObjC.enumerateLoadedClassesSync({ ownedBy: appModule })
  .forEach(name => console.log(name));

// 2. Identify security-relevant classes
const securityIndicators = [
  'SSL', 'TLS', 'Pinning', 'Certificate',
  'Jailbreak', 'Root', 'Tamper', 'Integrity',
  'Biometric', 'TouchID', 'FaceID', 'LAContext',
  'Keychain', 'SecItem', 'Crypto', 'Encrypt'
];
ObjC.enumerateLoadedClassesSync({ ownedBy: appModule })
  .filter(name => securityIndicators.some(s =>
    name.toLowerCase().includes(s.toLowerCase())))
  .forEach(name => {
    console.log(`\n[Security] ${name}`);
    ObjC.classes[name].$ownMethods.forEach(m => console.log(`  ${m}`));
  });
```

```javascript
// 3. Check Info.plist security settings
// Run from shell: plutil -p /path/to/Info.plist
// Look for: NSAppTransportSecurity, NSAllowsArbitraryLoads,
//           CFBundleURLTypes, LSApplicationQueriesSchemes
```

### Phase 2: Domain Testing

Test each security domain systematically. See [references/protection-bypasses.md](references/protection-bypasses.md) for detailed scripts.

#### Checklist

- [ ] **STORAGE** — Keychain protection classes verified at runtime
- [ ] **STORAGE** — NSUserDefaults checked for sensitive data
- [ ] **STORAGE** — File protection attributes validated
- [ ] **NETWORK** — Certificate pinning tested and bypass attempted
- [ ] **NETWORK** — Cleartext traffic detection
- [ ] **AUTH** — Biometric authentication bypass tested
- [ ] **AUTH** — Token storage and lifecycle examined
- [ ] **PLATFORM** — URL scheme input validation tested
- [ ] **PLATFORM** — Pasteboard data exposure checked
- [ ] **CRYPTO** — Key storage mechanism identified
- [ ] **RESILIENCE** — Jailbreak detection mechanism analyzed
- [ ] **RESILIENCE** — Debugger detection tested
- [ ] **RESILIENCE** — Integrity verification assessed
- [ ] **MEMORY** — Sensitive data persistence in memory checked

### Phase 3: Bypass Verification

For each bypass found, verify it's real and assess impact.

**For each finding:**
1. **Reproduce** — Run the bypass script twice to confirm consistency
2. **Verify impact** — What does the bypass actually enable? Follow the data flow after bypass
3. **Rule out false positives** — Confirm the control was active before your hook (use spawn mode)
4. **Classify severity** — Use the Decision Tree below
5. **Collect evidence** — Script output, screenshots, hexdumps of extracted data

### Phase 4: Reporting

**Finding format:**

```markdown
### [DOMAIN-NNN] Finding Title

**Severity:** CRITICAL/HIGH/MEDIUM/LOW
**MASVS Category:** MASVS-STORAGE | MASVS-NETWORK | MASVS-AUTH | MASVS-PLATFORM | MASVS-RESILIENCE | MASVS-CRYPTO
**Location:** Class/method or binary offset
**Description:** What the security control does and how it fails
**Bypass Method:** Frida script or technique used
**Impact:** What an attacker gains from this bypass
**Evidence:** Script output, extracted data (redacted), or behavior change
**Recommendation:** Specific remediation with code-level guidance
```

## Detection Patterns

### Network Security

| Pattern | What to Look For | Severity |
|---------|-----------------|----------|
| NSURLSession delegate pinning | `-[* URLSession:didReceiveChallenge:completionHandler:]` implementations | HIGH |
| TrustKit/third-party pinning | Classes containing `TrustKit`, `TSKPinningValidator`, `AFSecurityPolicy` | HIGH |
| ATS exceptions | `NSAllowsArbitraryLoads = YES` in Info.plist | MEDIUM |
| Custom TLS validation | `SecTrustEvaluate`, `SecTrustEvaluateWithError` calls | HIGH |

### Data Storage

| Pattern | What to Look For | Severity |
|---------|-----------------|----------|
| Keychain weak protection | `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly` | CRITICAL |
| Secrets in NSUserDefaults | `objectForKey:` with keys like `token`, `password`, `secret`, `key` | CRITICAL |
| Unprotected file writes | `NSFileProtectionNone` or missing protection attribute | HIGH |
| Logging sensitive data | `NSLog`, `os_log` calls containing credentials or PII | MEDIUM |

### Authentication

| Pattern | What to Look For | Severity |
|---------|-----------------|----------|
| Biometric without fallback protection | `LAContext evaluatePolicy:` with no server-side verification | HIGH |
| Hardcoded credentials | String constants matching credential patterns in binary | CRITICAL |
| Weak session tokens | Predictable or non-expiring tokens in Keychain/UserDefaults | HIGH |

See [references/data-extraction.md](references/data-extraction.md) for runtime data extraction scripts.

## Red Flags

| Red Flag | Why It Matters | Action |
|----------|---------------|--------|
| `NSAllowsArbitraryLoads = YES` with no domain exceptions | App allows cleartext to all domains — complete ATS bypass | CRITICAL — verify all API traffic, check for sensitive data in cleartext |
| Keychain items with `kSecAttrAccessibleAlways` | Data accessible even when device is locked — negates device lock protection | CRITICAL — extract and examine what's stored |
| Jailbreak detection with no consequence | Detection without response (app continues normally) is meaningless | Note as defense-in-depth failure, but escalate if sensitive operations follow |
| Biometric auth that only gates UI | LAContext returns YES/NO locally, no server-side binding | HIGH — bypass is trivial and grants full access |
| Secrets in `NSUserDefaults` | Unencrypted plist, readable with trivial filesystem access | CRITICAL — extract and identify what's exposed |

## Decision Tree

```text
Assessing a potential finding?

├─ Does the bypass expose authentication material (tokens, passwords, keys)?
│  └─ Yes → CRITICAL
│
├─ Does the bypass allow interception of sensitive data in transit?
│  ├─ PII, financial data, health data → HIGH
│  └─ Non-sensitive metadata → LOW
│
├─ Does the bypass disable a primary security gate?
│  ├─ Authentication gate (biometric, PIN) → HIGH or CRITICAL
│  ├─ Anti-tamper gate protecting sensitive logic → MEDIUM
│  └─ Informational check with no gated behavior → LOW
│
├─ Does the bypass work on stock (non-jailbroken) devices?
│  ├─ Yes (e.g., via Gadget re-signing) → Escalate one severity level
│  └─ No (requires jailbreak) → Standard severity
│
└─ Is the finding defense-in-depth only?
   ├─ Other controls compensate → LOW with recommendation
   └─ No compensating controls → Escalate to MEDIUM minimum
```

## Quality Checklist

- [ ] All 7 security domains assessed (not just pinning + jailbreak)
- [ ] Every finding has a Frida script or command as evidence
- [ ] Bypass impact verified end-to-end (not just "hook fired")
- [ ] Severity classifications justified using the Decision Tree
- [ ] False positives explicitly ruled out for each finding
- [ ] Spawn mode used for protections that run at launch
- [ ] Findings mapped to MASVS categories
- [ ] Recommendations are specific and actionable
- [ ] Rationalizations in "Rationalizations to Reject" were not used

## Related Skills

### Supporting Tools

| Skill | How It Helps |
|-------|-------------|
| **frida-scripting** | Frida API reference — Interceptor, Stalker, ObjC, Memory patterns for writing assessment scripts |

## Resources

**[OWASP MASVS](https://mas.owasp.org/MASVS/)**
Mobile Application Security Verification Standard — the requirements framework this skill tests against.

**[OWASP MASTG](https://mas.owasp.org/MASTG/)**
Mobile Application Security Testing Guide — detailed test procedures for each MASVS category.

**[Frida JavaScript API](https://frida.re/docs/javascript-api/)**
Complete API reference for writing assessment scripts.
