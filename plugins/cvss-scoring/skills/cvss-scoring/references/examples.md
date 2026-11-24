# CVSS v4.0 Calibration Examples

Scored examples from the [FIRST.org CVSS v4.0 specification](https://www.first.org/cvss/v4.0/examples). Use these as calibration anchors when scoring new vulnerabilities. Compare your vector against the 2-3 most similar examples before finalizing.

## Remote Code Execution

### Log4Shell (CVE-2021-44228) -- CVSS-BT 9.3

JNDI command execution allows unauthenticated remote attacker to execute arbitrary commands with privileges of the service using the vulnerable library.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | N | Network service vulnerability |
| AC | L | Standard web request techniques |
| AT | N | Attacker prepares LDAP server but no target-side conditions needed |
| PR | N | Unauthenticated |
| UI | N | Automatic exploitation |
| VC/VI/VA | H | Arbitrary command execution with service privileges |
| SC/SI/SA | N | Impact contained to vulnerable system |
| E | A | Known active exploitation in the wild |

### Shellshock (CVE-2014-6271) -- CVSS-BT 9.3

GNU Bash processes trailing strings after function definitions in environment variable values, enabling remote code execution via crafted environment.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A
```

Key metrics: Same as Log4Shell -- unauthenticated network RCE with active exploitation.

### NGINX Memory Corruption (CVE-2022-41741) -- CVSS-B 7.3

Local attacker corrupts NGINX worker memory via specially crafted audio/video file, triggering memory errors dependent on system state.

```
CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | L | Local system access needed |
| AT | P | Target-specific reconnaissance needed to craft effective file |
| PR | L | Sufficient privileges to trigger NGINX processing |
| VC/VI/VA | H | Arbitrary code execution with elevated privileges |

### VMware vmnetdhcp Use-After-Free (CVE-2020-3947) -- CVSS-B 9.4

Use-after-free in vmnetdhcp allows code execution on host or DoS from guest VM.

```
CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | L | Local guest VM access |
| PR | N | Unprivileged guest access sufficient |
| VC/VI/VA | H | Hypervisor host code execution |
| SC/SI/SA | H | Other guest VMs compromisable (VM escape) |

## Information Disclosure

### Heartbleed (CVE-2014-0160) -- CVSS-BT 8.7

TLS Heartbeat Extension implementation allows buffer over-read to extract 64KB of server memory including private keys and credentials.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | N | Remote network attack |
| VC | H | Private keys and credentials exposed in memory |
| VI/VA | N | Read-only memory leak, no modification or crash |
| E | A | Active exploitation in the wild |

### Windows DWM Info Disclosure (CVE-2026-20805) -- CVSS-BT 6.8

Authorized attacker discloses sensitive local information through Desktop Windows Manager exposure.

```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | L | Local system access required |
| PR | L | User-level privileges sufficient |
| VC | H | Sensitive information retrieval |
| E | A | CISA reported active exploitation |

## SQL Injection

### PrestaShop SQL Injection (CVE-2023-30545) -- CVSS-B 7.1

User with SQL Manager access can read arbitrary files via LOAD_FILE in SELECT requests.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | N | Remote web application |
| PR | L | Database access (non-root) required |
| VC | H | Arbitrary OS file read |
| VI/VA | N | Read-only, no modification or crash |

## Cross-Site Scripting (XSS)

### Zimbra Calendar XSS (CVE-2022-24682) -- CVSS-B 5.1

HTML with executable JavaScript in element attributes is unescaped, causing markup injection.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| UI | A | User must click a malicious link crafted by the attacker |
| VC/VI/VA | N | No direct application impact |
| SC/SI | L | Browser data access/modification (browser is subsequent system) |

### SharePoint Stored XSS (CVE-2020-0926) -- CVSS-B 5.1

SharePoint does not sanitize crafted web requests, allowing script execution in the user's security context.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| PR | L | Attacker needs account to store payload |
| UI | P | Normal user browsing triggers execution (passive) |
| SC/SI | L | Browser content access/modification |

Note on UI for XSS: The P vs A distinction depends on whether the user encounters the payload through normal browsing (P) or must be directed to a specific attacker-crafted resource (A). SharePoint stored XSS is UI:P because normal page browsing triggers it. Zimbra stored XSS is UI:A because the user must click a crafted link. This is not a blanket stored=P / reflected=A rule.

### RocketChat LiveChat Blind Self-XSS (CVE-2022-21830) -- CVSS-B 5.1

Attacker tricks victim into pasting malicious code in chat instance.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| UI | A | User must consciously paste malicious script |

### Dolibarr Product Module XSS (CVE-2024-55228) -- CVSS-B 8.5

XSS in Product module allows attackers to execute arbitrary scripts via crafted payload in Title parameter, with application-level impact.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| VC/VI/VA | H | Commands execute with user privileges in the application |
| SC/SI | L | Browser data also accessible |

## CSRF

### WordPress Social Share CSRF (CVE-2023-5602) -- CVSS-B 5.1

Missing nonce validation on AJAX actions allows unauthenticated attackers to invoke actions via forged requests.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| UI | A | User must click malicious link |
| VI | L | Application values modifiable via forged request |

## Privilege Escalation

### Cisco ASA/FTD Privilege Escalation (CVE-2022-20759) -- CVSS-B 7.7

Web services interface allows authenticated unprivileged remote attacker to elevate to level 15 (full admin).

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AT | P | HTTP Management Access and IKEv2/WebVPN must be enabled |
| PR | L | Valid VPN credentials needed |
| VC/VI/VA | H | Complete device compromise (level 15) |

### Oracle VirtualBox Host Data Access (CVE-2023-21989) -- CVSS-B 5.9

High-privileged attacker with VM logon accesses host hypervisor data.

```
CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| PR | H | Administrative VM control needed |
| VC/VI/VA | N | VirtualBox application unaffected |
| SC | H | VM host hypervisor data accessible (crosses trust boundary) |

## Authentication / Access Control Bypass

### authentik PKCE Bypass (CVE-2023-48228) -- CVSS-B 9.3

authentik only validates code_verifier when provided, allowing unauthenticated token requests without PKCE verification.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H
```

| Metric | Value | Why |
|--------|-------|-----|
| VC | N | No direct application confidentiality impact |
| VI | H | Arbitrary authentication tokens generated |
| SC/SI/SA | H | Tokens exploit all downstream relying services |

## Denial of Service

### Juniper SIP Memory Leak (CVE-2023-22394) -- CVSS-BT 6.6

Improper handling of SIP call data causes memory leak leading to DoS.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U
```

| Metric | Value | Why |
|--------|-------|-----|
| VA | H | Service resource exhaustion |
| SA | L | Brief downstream device unavailability |
| E | U | No known public exploitation |

## Network / Protocol Attacks

### Juniper Proxy ARP DoS (CVE-2013-6014) -- CVSS-B 6.4

Proxy ARP on unnumbered interface allows ARP cache poisoning and bogus forwarding table entries.

```
CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | A | Network adjacency required |
| VI | L | Routing table modification on gateway |
| SC | H | IP traffic from restricted hosts can be observed |
| SA | H | Rogue routing entries redirect/blackhole traffic |

### Cisco Firepower sftunnel MitM (CVE-2020-3549) -- CVSS-BT 5.2

Insufficient sftunnel negotiation protection allows MitM during initial device registration.

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U
```

| Metric | Value | Why |
|--------|-------|-----|
| AT | P | Must be on-path to intercept |
| UI | P | Logged-in user activity generates interceptable traffic |
| E | U | No known public exploitation |

### Junos OS Improper Initialization (CVE-2022-22186) -- CVSS-B 6.9

Packets on em0 not destined to device are improperly forwarded to egress instead of being discarded.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| VC/VI/VA | N | Gateway device itself unaffected |
| SC | L | Traffic from restricted hosts detectable on egress |
| SI | L | Traffic misdirected to unintended interfaces |

## Cryptographic Weaknesses

### Red Hat OpenShift FIPS Compliance (CVE-2023-3089) -- CVSS-BE 8.1

Non-FIPS-validated cryptographic modules operate in FIPS mode, reducing security guarantees.

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L
```

| Metric | Value | Why |
|--------|-------|-----|
| AT | P | Requires FIPS mode configuration |
| VC | H | Weakened crypto affects confidentiality of protected data |
| VI/VA | L | Encryption still present but weaker guarantees |
| MAC | H | Exploitation still requires spoofing a cryptographically secure certificate, even though the algorithm is not always FIPS-approved. |
| CR | H | FIPS systems have high confidentiality requirements |

### Bosch Firmware Clear-Text Transmission (CVE-2021-23846) -- CVSS-B 8.2

Firmware transmitted in clear text over HTTP, enabling on-path attackers to access user credentials.

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AT | P | Must be on-path to intercept HTTP traffic |
| VC | H | Plain-text credentials fully exposed |

## Physical Access

### Becton Dickinson PCU Infusion Device (CVE-2023-30560) -- CVSS-B 8.3

PCU infusion device allows unauthenticated physical modification with patient safety consequences.

```
CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | P | Physical device access required |
| VC/VI/VA | H | Complete device control |
| SI | H | Patient health integrity at risk |
| S | P | Safety consequences (supplemental, does not affect score) |

### Intel DCI Debug Interface (CVE-2018-3652) -- CVSS-B 8.6

Insufficient DCI access restrictions allow physical attacker to access platform secrets via debug interfaces.

```
CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | P | Physical DCI port access required |
| VC/VI/VA | H | Complete memory/CPU instruction access |

## Firmware / BIOS

### Lenovo ThinkPwn BIOS (CVE-2016-5729) -- CVSS-B 8.4

SmmRuntime BIOS driver allows local admin to execute code with System Management Mode privileges.

```
CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I
```

| Metric | Value | Why |
|--------|-------|-----|
| PR | H | Kernel-level (ring 0) code execution required |
| VC/VI/VA | H | SMM provides complete system control |
| R | I | SMM locking prevents recovery (supplemental) |

### Flash Write Protection S3 Failure (CVE-2015-2890) -- CVSS-B 8.7

UEFI BIOS fails to restore flash write protections on resume from S3 sleep.

```
CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I
```

| Metric | Value | Why |
|--------|-------|-----|
| AT | P | Vulnerability triggers only on S3 resume (deployment condition) |
| PR | H | Kernel-level code execution |
| R | I | BIOS corruption prevents recovery (supplemental) |

## Race Conditions

### regreSSHion (CVE-2024-6387) -- CVSS-BT 8.2

Race condition in OpenSSH sshd signal handling during authentication timeout window.

```
CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P
```

| Metric | Value | Why |
|--------|-------|-----|
| AC | H | Must defeat ASLR and memory defenses |
| AT | P | Race condition exploitation is unreliable |
| E | P | Public PoC available but no known active attacks |

Note: This is a rare case where BOTH AC:H and AT:P apply. AC:H because ASLR must be bypassed. AT:P because the race condition is a deployment-dependent timing issue.

## Warning Bypass / UI Spoofing

### Adobe Acrobat Reader Warning Bypass (CVE-2021-44714) -- CVSS-B 4.6

Warning message omits custom protocols, allowing attackers to mislead users about malicious file origins.

```
CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
```

| Metric | Value | Why |
|--------|-------|-----|
| AV | L | Malicious document must exist on local disk |
| UI | A | User must click "Allow" on warning dialog |
| VC | L | Omitted information enables spoofing (limited info leak) |
