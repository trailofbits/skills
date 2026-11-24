---
name: cvss-scoring
description: "Produces CVSS v4.0 vector strings from plain-text vulnerability descriptions by systematically evaluating base metrics. Use when scoring a vulnerability, generating a CVSS vector, or estimating severity."
allowed-tools:
  - Read
---

# CVSS v4.0 Vector Scoring

Produce a CVSS v4.0 vector string from a plain-text vulnerability description, plus a
[FIRST.org calculator](https://www.first.org/cvss/calculator/4.0) link with that vector
already applied, which is where the numeric score comes from. Do NOT attempt to compute
the numeric score.

## When to Use

- Scoring a vulnerability finding for a security audit report
- Generating a CVSS v4.0 vector from a bug description
- Comparing relative severity of multiple findings
- The user asks "what's the CVSS for this?" or "score this vulnerability"

## When NOT to Use

- CVSS v3.1 is explicitly requested (use the organization's CVSS v3.1 scoring guide instead)
- The description is too vague to assess any metric (ask for clarification first)
- The input does not describe an exploitable security weakness (see Input Validation below)
- Scoring risk (CVSS measures intrinsic severity, not deployment-specific risk)
- Computing the numeric score (direct the user to the FIRST.org calculator)

## Input Validation

Run these checks before scoring any metric. If any check fails, address it before proceeding.

**1. Is this a vulnerability?** A CVSS vector is meaningful only for exploitable security weaknesses. If the input describes a code-quality issue, design concern, or finding with no security impact, refuse and respond:

> This description does not appear to describe an exploitable vulnerability. CVSS measures the severity of security weaknesses; it does not apply to {category}. If you believe there is an exploitable impact, restate the description in terms of attacker capability and re-run.

Do not fabricate metrics to satisfy the request.

**2. Does the input use CVSS v3.1 vocabulary?** Watch for `Scope` (now removed), `User Interaction: Required`, or the unprefixed CIA triad. If detected, surface the version mismatch explicitly in the output before translating:

> Input uses CVSS v3.1 vocabulary; translating to v4.0 semantics. The following mappings were applied: {list}.

Do not translate silently.

## Rationalizations to Reject

These are common scoring errors. Reject this reasoning when you encounter it:

- **"Network accessible means AV:N"** -- AV measures the furthest distance from which the *attack* can launch, not whether the component is on a network. A privilege escalation on a network service is still AV:L if the attacker needs local shell access.
- **"It's serious so all impacts are High"** -- Each impact metric (VC/VI/VA/SC/SI/SA) must be independently justified. An RCE that gives code execution has VI:H (attacker can modify arbitrary data/code) but not necessarily VC:H (unless data is actually exposed) or VA:H (unless the attacker can crash or deny the service).
- **"A dependency is a subsequent system"** -- Component relationships do not define the system boundary. A dedicated database or an application using a vulnerable library can be part of the same vulnerable system; counting that impact again in SC/SI/SA inflates severity.
- **"No mention of subsequent systems means SC/SI/SA are all None"** -- Identify the vulnerable system boundary and consider supported impacts outside it. If that boundary or an external impact is unclear, explain the uncertainty and flag the chosen value with `[ASSUMED]`.
- **"Default to worst case when uncertain"** -- CVSS v4.0 requires *reasonable worst case*, not *absolute worst case*. When uncertain, choose the most defensible value and flag it with `[ASSUMED]`.
- **"AC:H because there are prerequisites"** -- In v4.0, AC measures evasion of security-enhancing mechanisms (ASLR, DEP). Prerequisites like specific configurations or race conditions belong in AT, not AC. This is the most common v3.1-to-v4.0 migration error.
- **"UI:R maps to UI:P or UI:A"** -- v4.0 split v3.1's Required into Passive and Active. Passive means involuntary interaction (browsing a page). Active means the user must consciously perform a specific action (installing software, changing a setting, clicking through a warning). Don't default to Active.

## Input Handling

The input is plain text describing a vulnerability. It may contain severity, difficulty, implementation specifics, exploitation scenarios, and remediation recommendations.

**Before scoring any metric**, extract and list all security-relevant facts:

1. What is the vulnerable component? (software, library, service, device)
2. How is it accessed? (network service, local binary, physical device, adjacent network)
3. What privileges does the attacker need? (unauthenticated, user-level, admin)
4. What does the attacker achieve? (read data, modify data, execute code, crash service, escalate privileges)
5. What is the vulnerable system boundary, including components serving its function? Are systems outside that boundary affected?
6. Are there prerequisites or conditions for exploitation? (specific config, race condition, on-path position)
7. Is user interaction required? If so, what kind?
8. Is there information about exploit maturity? (PoC available, actively exploited, unreported)

This fact extraction prevents anchoring bias from emotional language in the description.

**If any exploitability metric (AV, AC, AT, PR, UI) cannot be confidently determined** from the description, ask the user the fact-extraction questions above before proceeding. These five metrics drive most of the score and are the highest-impact place for a wrong guess. Do not default-and-flag them silently.

**If an impact metric (VC/VI/VA/SC/SI/SA) is ambiguous**, state the ambiguity, explain which values are plausible and why, choose the most defensible default, and flag it with `[ASSUMED]` in the output.

## Scoring Workflow

Score metrics in this exact order. For each metric, read the detailed definitions in
[the metrics reference](references/metrics.md).

### Phase 1: Exploitability Metrics

Evaluate these 5 metrics based on the extracted facts:

**1. Attack Vector (AV):** N / A / L / P
- Network: exploitable remotely via network stack (HTTP, TCP, DNS)
- Adjacent: requires same LAN, Bluetooth, WiFi, or logical subnet
- Local: requires local access (shell, file drop, terminal emulation)
- Physical: requires physically touching/manipulating the device

**2. Attack Complexity (AC):** L / H
- Low (default): no security mechanisms to evade
- High: must bypass ASLR, DEP, or obtain target-specific secrets
- NOTE: race conditions and specific configs go in AT, not AC (v4.0 change from v3.1)

**3. Attack Requirements (AT):** N / P
- None: no special deployment conditions needed
- Present: requires specific configuration, race condition, on-path position, or other deployment-dependent condition
- This metric is NEW in v4.0 -- it absorbs conditions that v3.1 lumped into AC

**4. Privileges Required (PR):** N / L / H
- None: unauthenticated
- Low: basic user account
- High: admin or elevated privileges

**5. User Interaction (UI):** N / P / A
- None: no user action needed
- Passive: user does something involuntary (visits a page, receives a message)
- Active: user must consciously perform a specific action (install software, click through warning, change a setting)
- v4.0 split v3.1's "Required" into Passive and Active -- choose carefully

### Phase 2: Vulnerable System Impact

These measure impact within the vulnerable system. Establish its boundary using
FIRST's system-of-interest model: computing logic with a coherent function and set of
security policies. Components designed exclusively to serve that system belong inside
it, such as a dedicated database or an embedded library and its consuming application.
Score impacts to those components in VC/VI/VA.

**6. Confidentiality (VC):** H / L / N
- High: total loss -- all data in the vulnerable system exposed
- Low: some data exposed but attacker lacks control over what/how much
- None: no confidentiality impact

**7. Integrity (VI):** H / L / N
- High: total loss -- attacker can modify any data in the vulnerable system
- Low: limited modification possible
- None: no integrity impact

**8. Availability (VA):** H / L / N
- High: sustained or persistent total loss, or partial loss with a direct, serious consequence (e.g., preventing new connections while existing connections remain available)
- Low: reduced performance or interrupted availability without a direct, serious consequence; repeated exploitation cannot completely deny service
- None: no availability impact

### Phase 3: Subsequent System Impact

These measure impact to systems *outside* the vulnerable system boundary. This replaces v3.1's Scope metric.

A dependency, data flow, or trust relationship alone does not make a component a
subsequent system. Identify a separate system outside the boundary and the impact
exploitation causes there; do not count the same within-system impact again in
SC/SI/SA. A user's browser affected by web-application XSS or other guests compromised
through a hypervisor vulnerability can be subsequent systems.

**9. Subsequent Confidentiality (SC):** H / L / N

**10. Subsequent Integrity (SI):** H / L / N

**11. Subsequent Availability (SA):** H / L / N

If the description gives no indication of subsequent system impact, default to N but flag with `[ASSUMED]`. Common cases where subsequent impact is non-None:
- XSS: SC:L, SI:L (browser is a subsequent system). UI depends on whether normal browsing triggers the payload (P) or the user must navigate to an attacker-crafted resource (A) -- not on stored vs. reflected.
- VM escape: SC:H, SI:H, SA:H (host/other VMs are subsequent systems)
- DNS poisoning: SI:H, SA:H (downstream resolvers are subsequent systems)
- Compromised auth server: consider SC:H, SI:H for affected relying services outside the vulnerable system boundary

### Phase 4: Optional Metrics

**Threat -- Exploit Maturity (E):** Include ONLY if the description provides evidence.
- Attacked (A): known active exploitation or exploit toolkits available
- Proof-of-Concept (P): public PoC code exists, no known attacks
- Unreported (U): no public PoC, no known attacks
- Not Defined (X): no information available (default -- omit from vector)

**Environmental metrics:** Include only when the source description provides relevant context — i.e., the auditor states the deployed environment's CIA requirements (CR/IR/AR) or describes a compensating control that changes a base metric (modified base: MAV/MAC/MAT/MPR/MUI/MVC/MVI/MVA/MSC/MSI/MSA). Otherwise omit and note: "Environmental metrics omitted -- add if the target environment's CIA requirements differ from defaults."

**Supplemental metrics:** Include only when the source description provides relevant context — i.e., the finding describes a safety impact (S), recovery characteristic (R), or automation potential (AU). These are informational and do not affect the numeric score. Otherwise omit and note: "Supplemental metrics omitted -- add for communication purposes if needed."

See the Vector String section below for canonical ordering when these are included.

## Output Format

Present the output in three parts:

### Part 1: Metric Justification Table

```
| Metric | Value | Justification |
|--------|-------|---------------|
| AV     | N     | Exploitable via HTTP API without local access |
| AC     | L     | No security mechanisms to evade |
| AT     | N     | No deployment-specific conditions required |
| PR     | N     | Unauthenticated endpoint |
| UI     | N     | No user interaction needed |
| VC     | H     | Attacker gains read access to all application data |
| VI     | H     | Attacker can modify arbitrary records |
| VA     | N     | No availability impact observed |
| SC     | N     | No evidence of downstream system impact [ASSUMED] |
| SI     | N     | No evidence of downstream system impact [ASSUMED] |
| SA     | N     | No evidence of downstream system impact [ASSUMED] |
```

Flag any assumed values with `[ASSUMED]`.

### Part 2: Vector String

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

Format: `CVSS:4.0/` prefix, then all 11 base metrics in canonical order (AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA), separated by `/`. Append optional metrics only if scored: `E` first, then environmental in canonical order (CR/IR/AR/MAV/MAC/MAT/MPR/MUI/MVC/MVI/MVA/MSC/MSI/MSA), then supplemental (S/AU/R/V/RE/U).

Immediately below the vector, emit the calculator link with the vector as the URL fragment, so the user gets the numeric score in one click:

```
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

Append the vector verbatim after `#` — no URL-encoding, since `:` and `/` are both legal in a fragment. The calculator reads the fragment on load and preselects every metric button.

The link only works if the vector is well-formed: the calculator requires the literal `CVSS:4.0` prefix and rejects metrics that arrive out of canonical order, silently leaving the buttons unset. That is the same ordering rule stated above, so a vector that satisfies it produces a working link.

### Part 3: Calibration Check

Before presenting the final vector, read [the examples reference](references/examples.md) and find
the 2-3 most similar vulnerability types. Compare your vector against these calibration anchors. If
your vector diverges significantly from similar examples, either:
- Explain why the divergence is justified (the vulnerability has a specific characteristic the examples don't), or
- Adjust the metric that seems miscalibrated

State which examples you compared against and whether the vector is consistent.

## Self-Check Checklist

Before presenting the final output, verify:
- [ ] Input describes an exploitable security weakness (not a code-quality, design, or informational finding)
- [ ] Any CVSS v3.1 vocabulary in the input was acknowledged in the output before translation
- [ ] All 11 base metrics are present in the vector
- [ ] Each metric uses valid CVSS v4.0 values (not v3.1 -- e.g., UI uses N/P/A not N/R; no Scope metric)
- [ ] Vector string follows canonical metric ordering (base, then E, then environmental, then supplemental)
- [ ] Every metric has a text justification from the input description
- [ ] Subsequent system metrics (SC/SI/SA) are not confused with vulnerable system metrics (VC/VI/VA)
- [ ] AT and AC are not conflated (AT = deployment conditions; AC = security mechanism evasion)
- [ ] Calibration check against examples was performed
- [ ] Ambiguous impact metrics are flagged with `[ASSUMED]`; ambiguous exploitability metrics were resolved by asking the user

## Calculator

The numeric score comes from the official calculator, which the Part 2 link opens with
the vector already applied. Do not compute the score yourself: CVSS v4.0 uses a
lookup-table algorithm (`cvss_lookup.js` on FIRST.org), not a formula, so any score you
derive by hand is a guess.

If the user wants the bare calculator without a vector applied:
https://www.first.org/cvss/calculator/4.0
