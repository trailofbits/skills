---
name: report
description: Compile all findings into a structured penetration test report.
version: 3.0.0
metadata:
  category: reporting
  phase: 8
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Pentest Report Generation

## When to Use
- After post-exploitation is complete (Gateway 7 PASSED).
- Final phase of the engagement.

## Report Structure
1. **Executive Summary:** High-level overview for non-technical stakeholders.
2. **Scope & Methodology:** What was tested, rules of engagement, tools used, 8-phase methodology.
3. **Attack Surface Overview:** Asset inventory, network topology, technology stack (from Phase 4).
4. **Threat Model:** Attack trees and prioritized vectors (from Phase 5).
5. **Findings Summary:** Table of all findings with severity ratings.
6. **Detailed Findings:** For each vulnerability (use Finding Template from SKILL.md):
   - Title and severity (Critical/High/Medium/Low/Info)
   - Affected asset
   - Description
   - Steps to reproduce
   - Evidence (screenshots, logs, PoC)
   - Impact
   - Remediation recommendation
   - CVSS score
7. **Attack Narrative:** Story of the engagement from recon to final impact.
8. **Remediation Roadmap:** Prioritized fix list.
9. **Appendices:**
   - A: Full asset inventory
   - B: Dismissed assets and false positives
   - C: Tool output summaries
   - D: Vulnerability scan results

## Procedure
1. **Aggregate:** Collect all findings from all phases (Phases 1-7).
2. **Include Escalations:** Merge any findings from `./ptest-output/escalations/`.
3. **Deduplicate:** Merge related findings.
4. **Classify:** Assign final severity ratings (CVSS 3.1).
5. **Draft:** Write the report following the structure above.
6. **Review:** Self-check for completeness and accuracy.
7. **Format for Jira:** For individual findings that need Jira tickets, use `/parse-finding` to generate copy-paste-ready HTML with numbered images.

## Jira Integration

Individual findings can be exported to Jira using the `/parse-finding` skill:
1. Write each finding to `./finding/{finding-name}/` in markdown format.
2. Include screenshots as separate image files.
3. Run `/parse-finding {finding-name}` to generate HTML + renamed images.
4. Copy HTML text into Jira, drag-drop images.

## Output

Final report in `./ptest-output/report/pentest-report.md`.

Optionally generate:
- `./ptest-output/report/executive-summary.md` — standalone exec summary
- `./ptest-output/report/remediation-roadmap.md` — prioritized fix list for engineering
- `./ptest-output/report/attack-narrative.md` — full attack story

## Exit Criteria
- [ ] All findings included with evidence.
- [ ] Severity ratings assigned (CVSS 3.1).
- [ ] Remediation recommendations provided.
- [ ] Executive summary written.
- [ ] Attack narrative complete.
- [ ] Attack surface overview included.
- [ ] Threat model / attack trees included.
- [ ] Report reviewed for completeness.
