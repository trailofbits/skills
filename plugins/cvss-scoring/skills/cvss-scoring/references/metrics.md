# CVSS v4.0 Metric Definitions

Complete metric definitions from the [FIRST.org CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document). Use this as a lookup reference when evaluating each metric.

## Base Metrics -- Exploitability (Required)

### Attack Vector (AV)

How the vulnerability is exploited. Measures the furthest distance from which the attack can be launched.

| Value | Abbr | Definition |
|-------|------|------------|
| Network | N | Exploitable via the network stack. The attacker can be anywhere on the internet. Examples: HTTP API, DNS service, SMTP server, any network-facing service. |
| Adjacent | A | Limited to a logically adjacent topology: same shared proximity (Bluetooth, NFC, IEEE 802.11) or logical network (local IP subnet, VLAN). Cannot cross routed boundaries. |
| Local | L | Not bound to the network stack. Attacker exploits via local read/write/execute capabilities -- either directly on the system or through terminal emulation (SSH). Also applies when exploitation requires a user to open a malicious file. |
| Physical | P | Attacker must physically touch or manipulate the vulnerable device. May be brief (evil maid) or persistent. Examples: USB attacks, JTAG debug ports, hardware tampering. |

**Decision guidance:**
- If the attacker sends a packet to a listening service -> N
- If the attacker must be on the same LAN/WiFi/Bluetooth -> A
- If the attacker needs a shell, drops a file, or relies on user opening a file -> L
- If the attacker must physically handle the device -> P

### Attack Complexity (AC)

Whether the attacker must evade or circumvent security-enhancing mechanisms.

| Value | Abbr | Definition |
|-------|------|------------|
| Low | L | No measurable action needed to exploit. No security mechanisms to bypass. This is the default. |
| High | H | Must bypass address space randomization (ASLR), data execution prevention (DEP), or other active defense mechanisms. Or must obtain target-specific secrets before exploitation succeeds. |

**v3.1 migration warning:** In v3.1, AC:H covered race conditions, specific configurations, and MitM positions. In v4.0, those conditions moved to AT. AC:H in v4.0 is strictly about evading security mechanisms.

**Decision guidance:**
- Default to L unless the description explicitly mentions bypassing ASLR, DEP, stack canaries, or needing target-specific secrets
- Race conditions -> AT:P, not AC:H
- Specific configuration required -> AT:P, not AC:H
- MitM / on-path position -> AT:P, not AC:H

### Attack Requirements (AT)

Whether exploitation depends on specific deployment and execution conditions beyond the attacker's control. This metric is NEW in v4.0.

| Value | Abbr | Definition |
|-------|------|------------|
| None | N | No special deployment conditions needed. The attacker can expect to reach the vulnerability and exploit it reliably. |
| Present | P | Exploitation depends on specific conditions: winning a race condition, specific non-default configuration, attacker must be on-path for network injection, or other deployment-dependent prerequisites. |

**Decision guidance:**
- Default to N unless the description mentions conditions the attacker cannot control
- "Requires specific configuration" -> P
- "Race condition" -> P
- "On-path attacker" / "MitM required" -> P
- "Vulnerable only in FIPS mode" -> P
- "Works on any default installation" -> N

### Privileges Required (PR)

Level of privileges the attacker must possess before exploitation.

| Value | Abbr | Definition |
|-------|------|------------|
| None | N | Unauthenticated. No access to settings or files needed. |
| Low | L | Basic capabilities limited to settings/resources of a single low-privileged user. Examples: regular user account, API key with limited scope. |
| High | H | Significant (administrative) control over the vulnerable system. Full access to settings and files. Examples: root, admin, domain admin. |

**Decision guidance:**
- Self-service account or API key that the attacker can provision as part of the attack -> generally N
- API key or authenticated account requiring pre-existing low-level privileges that the attacker cannot grant themselves -> L
- "Admin account required" -> H
- "Kernel-level / ring-0 access" -> H

### User Interaction (UI)

Whether a human user (other than the attacker) must participate.

| Value | Abbr | Definition |
|-------|------|------------|
| None | N | Exploitable without any user interaction. |
| Passive | P | Limited interaction that is involuntary and does not require actively subverting protections. Examples: normal browsing that renders malicious content, receiving an email that loads a resource, running an application that calls a planted malicious binary. |
| Active | A | The user must perform specific, conscious interactions with the vulnerable system and attacker payload, or actively subvert protection mechanisms. Examples: importing a file in a specific manner, placing files in a specific directory before execution, submitting an attacker-supplied string, or accepting a security warning. |

**v3.1 migration warning:** v3.1 had only None (N) and Required (R). v4.0 splits Required into Passive and Active. Determine the actions needed for exploitation; UI:A does not require a protection bypass when specific, conscious interaction with the payload is required.

**Decision guidance:**
- Server-side vulnerability with no user involvement -> N
- User visits a page / opens an email / browses normally -> P
- Running an application that calls a malicious binary planted on the system -> P
- Using an application that generates traffic over an untrusted or compromised network (on-path attacker scenarios) -> P
- User must install malicious software -> A
- User must click "Allow" on a security dialog -> A
- User must paste something into developer console -> A

## Base Metrics -- Vulnerable System Impact (Required)

These measure impact within the vulnerable system. Under FIRST's system-of-interest
model, the boundary contains computing logic with a coherent function and set of
security policies. A component designed exclusively to serve another system belongs
to that same system for scoring. A web application and its dedicated database, or
an embedded library and the application using it, can therefore be one vulnerable
system. Score impacts within that boundary in VC/VI/VA.

### Confidentiality (VC)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Total loss. All information within the vulnerable system is divulged, or access to restricted information has direct, serious impact. Examples: memory dump exposing all data, admin credential theft, full database read. |
| Low | L | Some information exposed but attacker lacks control over what or how much. Examples: partial memory leak, directory listing, error messages revealing internal paths. |
| None | N | No confidentiality impact to the vulnerable system. |

### Integrity (VI)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Total loss. Attacker can modify any data in the vulnerable system, or modification has direct, serious impact. Examples: arbitrary code execution, full database write, firmware modification. |
| Low | L | Limited modification possible. Attacker cannot control what is modified or impact is constrained. Examples: modifying non-critical configuration, limited file writes. |
| None | N | No integrity impact to the vulnerable system. |

### Availability (VA)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Sustained or persistent total loss of availability, or partial loss with a direct, serious consequence to the vulnerable system, such as preventing new connections while existing connections remain available. |
| Low | L | Reduced performance or interrupted availability without a direct, serious consequence; repeated exploitation cannot completely deny service to legitimate users. |
| None | N | No availability impact to the vulnerable system. |

## Base Metrics -- Subsequent System Impact (Required)

These measure impact to systems OUTSIDE the vulnerable system boundary. This replaces v3.1's Scope metric.

A subsequent system is a separate system outside the established boundary that is
affected by exploitation. Receiving data from, depending on, or trusting a vulnerable
component is not sufficient: that component may be inside the same system. Do not
duplicate within-system impacts in SC/SI/SA.

### System Boundary Examples

The subsequent systems below are separate systems outside the established boundary;
only impacts supported by the exploit scenario belong in SC/SI/SA.

| Vulnerable Component | Subsequent System | Why |
|---------------------|-------------------|-----|
| Web application | User's browser | XSS executes in browser context |
| VM guest | Host OS / other guests | VM escape crosses trust boundary |
| DNS resolver | Downstream clients | Poisoned cache affects all clients |
| Auth service | All relying services | Compromised tokens affect downstream |
| Embedded library in an application | None, when impact stays within that application | Library and consumer are part of the same vulnerable system |
| Web application with a dedicated database | None, when only that application's data is affected | Database serves only the application and belongs inside its boundary |
| Network gateway | Devices behind it | Misdirected traffic affects internal hosts |

### Subsequent Confidentiality (SC)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Total loss of confidentiality, or disclosure of restricted information with a direct, serious impact on the subsequent system, such as an administrator password or private encryption key. |
| Low | L | Some information is exposed, but the loss is limited or uncontrolled and has no direct, serious impact on the subsequent system. |
| None | N | No confidentiality impact beyond the vulnerable system. |

### Subsequent Integrity (SI)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Total loss of integrity or protection, or modification of a limited set of data with a direct, serious consequence to the subsequent system. |
| Low | L | Modification is limited or its consequences are uncontrolled, with no direct, serious impact on the subsequent system. |
| None | N | No integrity impact beyond the vulnerable system. |

### Subsequent Availability (SA)

| Value | Abbr | Definition |
|-------|------|------------|
| High | H | Sustained or persistent total loss of availability, or partial loss with a direct, serious consequence to the subsequent system, such as preventing new connections while existing connections remain available. |
| Low | L | Reduced performance or interrupted availability without a direct, serious consequence; repeated exploitation cannot completely deny service to legitimate users. |
| None | N | No availability impact beyond the vulnerable system. |

**Decision guidance for subsequent system metrics:**
- Establish the vulnerable system boundary before selecting SC/SI/SA; dependencies within it are scored in VC/VI/VA
- If exploitation has no impact outside that boundary -> N for all three
- XSS vulnerabilities almost always have SC:L, SI:L (browser is subsequent)
- VM/container/sandbox escape -> consider H for all three
- Compromised auth/trust anchor -> consider H for SC and SI
- When defaulting to N, flag with `[ASSUMED]` if the description does not explicitly rule out subsequent impact

## Threat Metrics (Optional)

### Exploit Maturity (E)

| Value | Abbr | Definition |
|-------|------|------------|
| Not Defined | X | No reliable threat intelligence available. For score calculation, treated as equivalent to Attacked (A) -- assumes worst case. However, X signals "unknown" while A asserts confirmed exploitation. Prefer A when evidence exists. Omit from vector string. |
| Attacked | A | Attacks targeting this vulnerability have been reported, OR exploit toolkits/solutions are publicly or privately available. |
| Proof-of-Concept | P | Public PoC exploit code exists AND no known attacks AND no exploit toolkits available. |
| Unreported | U | No public PoC AND no known attacks AND no exploit solutions available. |

**Decision guidance:**
- "Actively exploited in the wild" -> A
- "Exploit kit available" / "Metasploit module" -> A
- "PoC published on GitHub" -> P
- "Theoretical vulnerability, no known exploitation" -> U
- Description says nothing about exploitation -> omit (X)

## Environmental Metrics (Optional)

These allow deployment-specific adjustments. Skip unless the user provides deployment context.

### Security Requirements

| Metric | Abbr | Values |
|--------|------|--------|
| Confidentiality Requirement | CR | Not Defined (X), High (H), Medium (M), Low (L) |
| Integrity Requirement | IR | Not Defined (X), High (H), Medium (M), Low (L) |
| Availability Requirement | AR | Not Defined (X), High (H), Medium (M), Low (L) |

### Modified Base Metrics

Each base metric has a "Modified" counterpart (MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA) that overrides the base value for a specific deployment. All default to Not Defined (X). MSI and MSA have an additional value: Safety (S), indicating exploitation has safety consequences (human life, physical environment) that elevate the score.

## Supplemental Metrics (Optional, Informational Only)

These do NOT affect the numeric score. Include only for communication purposes.

| Metric | Abbr | Values |
|--------|------|--------|
| Safety | S | Not Defined (X), Present (P), Negligible (N) |
| Automatable | AU | Not Defined (X), Yes (Y), No (N) |
| Recovery | R | Not Defined (X), Automatic (A), User (U), Irrecoverable (I) |
| Value Density | V | Not Defined (X), Diffuse (D), Concentrated (C) |
| Vulnerability Response Effort | RE | Not Defined (X), Low (L), Moderate (M), High (H) |
| Provider Urgency | U | Not Defined (X), Clear, Green, Amber, Red (uses full color names in vector string, e.g., `U:Red`) |

## Vector String Format

```
CVSS:4.0/AV:{v}/AC:{v}/AT:{v}/PR:{v}/UI:{v}/VC:{v}/VI:{v}/VA:{v}/SC:{v}/SI:{v}/SA:{v}[/E:{v}][/CR:{v}/IR:{v}/AR:{v}/MAV:{v}/MAC:{v}/MAT:{v}/MPR:{v}/MUI:{v}/MVC:{v}/MVI:{v}/MVA:{v}/MSC:{v}/MSI:{v}/MSA:{v}][/S:{v}/AU:{v}/R:{v}/V:{v}/RE:{v}/U:{v}]
```

- Prefix: `CVSS:4.0/`
- 11 base metrics in canonical order: AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA (always present)
- Optional metrics appended in order: Threat, Environmental, Supplemental
- Optional metrics with value X (Not Defined) should be omitted from the vector string

## Qualitative Severity Rating Scale

| Score Range | Rating |
|-------------|--------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |
