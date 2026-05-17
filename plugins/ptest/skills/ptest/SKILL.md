---
name: ptest
description: "Structured penetration testing framework with gated phases. Guides methodical progression from recon through exploitation to reporting."
version: 3.0.0
author: n4igme
license: MIT
allowed-tools: Read Write Edit Bash(*)
argument-hint: <command: start|preflight|status|resume|next|escalate|cleanup|recon-passive|recon-active|enumerate|attack-surface|vuln-assess|exploit|post-exploit|report>
---

# Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement.

## Commands

$ARGUMENTS

| Command | Action |
|---------|--------|
| `start` | Initialize engagement — scope, targets, authorization, preflight |
| `preflight` | Check/install mandatory tools (see `references/preflight.md`) |
| `status` | Show current gateway state and progress |
| `resume` | Resume interrupted engagement from last checkpoint |
| `next` | Advance to next phase (runs exit criteria check) |
| `escalate` | Critical finding escalation (see `references/escalate-finding.md`) |
| `cleanup` | Archive output, sanitize sensitive data |
| `recon-passive` | Phase 1 — `references/recon-passive.md` |
| `recon-active` | Phase 2 — `references/recon-active.md` |
| `enumerate` | Phase 3 — `references/enumeration.md` |
| `attack-surface` | Phase 4 — `references/attack-surface.md` |
| `vuln-assess` | Phase 5 — `references/vuln-assessment.md` |
| `exploit` | Phase 6 — `references/exploit.md` |
| `post-exploit` | Phase 7 — `references/post-exploit.md` |
| `report` | Phase 8 — `references/report.md` |

If no command given, show status and suggest next action.

## Gateway Map

| Gate | Phase | Exit Criteria |
|------|-------|---------------|
| 1 | Passive Recon | Attack surface mapped, subdomains validated, technologies identified |
| 2 | Active Recon | All hosts port-scanned, services detected, topology mapped |
| 3 | Enumeration | Applications enumerated, APIs mapped, parameters discovered |
| 4 | Attack Surface | Asset inventory confirmed with user, entry points mapped |
| 5 | Vuln Assessment | Attack trees documented, vuln scans complete, vectors prioritized |
| 6 | Exploitation | Prioritized vulnerabilities exploited with PoC |
| 7 | Post-Exploitation | Privilege escalation & lateral movement attempted |
| 8 | Reporting | Final report delivered |

## Initialization (`start`)

1. Run `preflight` automatically
2. Collect: target scope, scope type (web/network/cloud/mobile/mixed), rules of engagement
3. Confirm written authorization exists — refuse to proceed without it
4. Create `./ptest-output/` with `state.yaml` and phase subdirectories

## Execution Loop

1. Read `./ptest-output/state.yaml` → active gateway
2. Read phase `checklist.md` → pending techniques
3. Execute technique → document findings → update checklist
4. Repeat until exit criteria met → request user sign-off → advance gateway

## Finding Template

```markdown
## [FINDING-{ID}] {Title}
**Severity:** Critical / High / Medium / Low / Info
**CVSS 3.1:** {score} ({vector})
**Affected Asset:** {host/endpoint}
**Phase Discovered:** {phase}
**Verification Status:** Confirmed / Unverified

### Description
### Steps to Reproduce
### Evidence
### Impact
### Remediation
```

- **Confirmed** = direct proof (HTTP response, command output). Goes in final report.
- **Unverified** = indirect evidence only. Goes in "Potential Issues" appendix for next phase to validate.

## Guardrails

- Strict sequence — never skip phases
- Scope enforcement — re-read `scope.md` before each technique
- Evidence required — every finding needs reproducible proof
- Mandatory tools must be run per phase (document gaps if unavailable)
- Human sign-off required at every gateway transition
- Authorization first — refuse without it
