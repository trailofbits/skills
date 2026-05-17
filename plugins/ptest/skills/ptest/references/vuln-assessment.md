---
name: vuln-assessment
description: Threat modeling and vulnerability assessment — map attack paths, run targeted scans, and prioritize exploitation vectors.
version: 3.0.0
metadata:
  category: assessment
  phase: 5
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Threat Modeling & Vulnerability Assessment

## When to Use
- After attack surface mapping is complete (Gateway 4 PASSED).
- When you need to identify and prioritize vulnerabilities before exploitation.

## Purpose

This phase has two sub-phases:
- **5A: Threat Modeling** — map attack paths from the attacker's perspective
- **5B: Vulnerability Assessment** — run targeted scanning and manual verification

The output is a prioritized list of exploitation vectors that feeds directly into Phase 6.

---

## 5A: Threat Modeling (Attack-Tree Approach)

### Methodology

For each high-priority asset (from Phase 4 asset inventory), build an attack tree:

```
[Goal: What the attacker wants to achieve]
├── [Path 1: Entry point → Technique → Impact]
│   ├── Prerequisite: ...
│   ├── Likelihood: High/Medium/Low
│   └── Impact: Critical/High/Medium/Low
├── [Path 2: ...]
└── [Path 3: ...]
```

### Steps

1. **Identify attacker goals** per asset:
   - Unauthorized access to admin panels
   - Data exfiltration (customer data, credentials)
   - Service disruption
   - Lateral movement to internal systems
   - Privilege escalation

2. **Map attack paths** from discovered entry points:
   - What entry points exist? (from Phase 4 entry-points.md)
   - What techniques could exploit each entry point?
   - What's the path of least resistance?
   - What's the maximum impact achievable?

3. **Assess likelihood × impact** for each path:
   - **Likelihood:** Based on exposure, complexity, and required prerequisites
   - **Impact:** Based on data sensitivity, business criticality, and blast radius

4. **Prioritize vectors** — rank by: `likelihood × impact`

### Output Format

```markdown
# Attack Tree: [Asset Name]

## Goal: [Attacker objective]

### Path 1: [Short description]
- **Entry Point:** [URL/endpoint]
- **Technique:** [Attack type — SQLi, auth bypass, SSRF, etc.]
- **Prerequisites:** [What's needed — valid account, specific parameter, etc.]
- **Likelihood:** High / Medium / Low
- **Impact:** Critical / High / Medium / Low
- **Priority Score:** [L×I — e.g., High×Critical = P1]

### Path 2: ...
```

---

## 5B: Vulnerability Assessment

### 1. Automated Vulnerability Scanning (MANDATORY: nuclei)

Run nuclei against ALL confirmed-live web targets.
```bash
# Full scan against all live hosts
nuclei -l ./ptest-output/recon-passive/live-urls.txt -o ./ptest-output/vuln-assessment/nuclei-full.txt -severity info,low,medium,high,critical

# Targeted scan against priority targets
nuclei -u https://priority-target.com -t cves/ -t vulnerabilities/ -t misconfiguration/ -o ./ptest-output/vuln-assessment/nuclei-priority.txt

# Technology-specific templates
nuclei -u https://target.com -t technologies/ -t exposures/ -o ./ptest-output/vuln-assessment/nuclei-tech.txt
```

**Requirements:**
- Nuclei MUST be run against all live web hosts
- Results must be manually verified (eliminate false positives)
- If nuclei is unavailable, document the gap

### 2. Web Server Scanning (Recommended: nikto)
```bash
# Nikto scan
nikto -h https://target.com -o ./ptest-output/vuln-assessment/nikto.txt -Format txt

# Multiple hosts
nikto -h ./ptest-output/recon-passive/live-urls.txt -o ./ptest-output/vuln-assessment/nikto-all.txt
```

### 3. SSL/TLS Assessment (Recommended: testssl.sh)
```bash
# Full SSL/TLS analysis
testssl.sh --html --csvfile ./ptest-output/vuln-assessment/testssl.csv https://target.com

# Quick check
testssl.sh --fast https://target.com
```

### 4. CVE Mapping
Match discovered service versions against known vulnerabilities.
```bash
# Search for CVEs based on identified versions
searchsploit "pimcore"
searchsploit "php 8.1"
searchsploit "keycloak"
searchsploit "nginx"

# Check NVD/CVE databases
# Cross-reference: service version from Phase 2 → known CVEs → exploitability
```

### 5. Manual Verification

**Every scanner finding must be manually verified before being added to the findings log.**

For each scanner result:
1. Reproduce the finding manually (curl, browser, or tool)
2. Confirm it's a true positive (not a false positive)
3. Assess actual exploitability in this specific context
4. Assign severity using CVSS 3.1

**False positives** → document in `./ptest-output/vuln-assessment/false-positives.md`
**Confirmed findings** → add to `./ptest-output/findings-log.md`

### 6. Prioritized Vector List

Combine threat model paths with confirmed vulnerabilities into a final prioritized exploitation list:

```markdown
# Prioritized Exploitation Vectors

| Priority | Target | Vector | Technique | Likelihood | Impact | Status |
|----------|--------|--------|-----------|-----------|--------|--------|
| P1 | target.com/admin | Auth bypass | Credential brute-force | High | Critical | Ready |
| P2 | api.target.com | Injection | SQLi in search param | Medium | High | Ready |
| P3 | ... | ... | ... | ... | ... | ... |
```

This list becomes the input for Phase 6 (Exploitation).

---

## Scope Type Adjustments

- **web/API:** Focus on OWASP Top 10, API-specific vulns (BOLA, mass assignment, rate limiting).
- **network:** Focus on CVE mapping for service versions, default credentials, misconfigurations.
- **cloud:** Focus on IAM misconfigurations, storage permissions, metadata exposure, SSRF to cloud endpoints.
- **mobile:** Focus on API-level vulnerabilities, certificate pinning bypass, insecure data storage.

## Output

Document in `./ptest-output/vuln-assessment/`:
- `attack-trees.md` — attack trees per high-priority asset
- `nuclei-*.txt` — raw nuclei output
- `nikto-*.txt` — raw nikto output (if run)
- `testssl-*.csv` — SSL/TLS results (if run)
- `cve-mapping.md` — service versions mapped to known CVEs
- `false-positives.md` — scanner results dismissed as false positives
- `vectors-prioritized.md` — final ranked exploitation vector list

Write `./ptest-output/vuln-assessment/checklist.md`:

```markdown
# Vulnerability Assessment Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Threat Modeling (attack trees) | PENDING | |
| 2 | Nuclei Scan (MANDATORY) | PENDING | |
| 3 | Nikto Scan | PENDING | |
| 4 | SSL/TLS Assessment | PENDING | |
| 5 | CVE Mapping | PENDING | |
| 6 | Manual Verification of Findings | PENDING | |
| 7 | Prioritized Vector List | PENDING | |
```

Mark each technique as `DONE` or `SKIPPED (reason)` after execution.

## Exit Criteria
- [ ] Attack trees documented for all high-priority assets.
- [ ] Nuclei scan completed on all live web hosts.
- [ ] All scanner findings manually verified (no unverified findings in final list).
- [ ] CVEs mapped to discovered service versions.
- [ ] Exploitation vectors prioritized by likelihood × impact.
- [ ] Mandatory tool (nuclei) was run — or gap documented.
- [ ] Checklist shows all applicable techniques executed.
