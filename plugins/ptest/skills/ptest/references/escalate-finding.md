---
name: escalate-finding
description: Immediately escalate critical/P1 findings that require urgent client notification.
version: 2.1.0
metadata:
  category: escalation
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Escalate Finding

## When to Use
- Critical vulnerability discovered (RCE, auth bypass, data breach in progress).
- Finding that poses immediate risk to the client.
- Any finding that per rules of engagement requires immediate disclosure.

## Severity Classification

| Severity | CVSS Range | Examples |
|----------|-----------|----------|
| Critical | 9.0 - 10.0 | RCE, unauthenticated admin access, active data breach |
| High | 7.0 - 8.9 | Auth bypass, SQLi with data access, privilege escalation |
| Medium | 4.0 - 6.9 | Stored XSS, IDOR with limited data, information disclosure |
| Low | 0.1 - 3.9 | Reflected XSS (limited), verbose errors, missing headers |

## Procedure
1. **Document Finding:** Full description using the Finding Template from SKILL.md.
2. **Classify Severity:** Use CVSS 3.1 calculator — assign vector string and score.
3. **Assess Immediate Risk:**
   - Is data actively being exposed to the internet?
   - Is there evidence of active exploitation by third parties?
   - Could this be weaponized trivially (no auth required, public-facing)?
4. **Prepare Notification:** Draft a concise escalation report:
   ```markdown
   # ESCALATION: [Title]

   **Severity:** Critical
   **CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
   **Affected Asset:** [host/endpoint]
   **Discovered:** [timestamp]

   ## Summary
   [2-3 sentences on what was found and why it's urgent]

   ## Immediate Risk
   [What could happen if this is not addressed NOW]

   ## Recommended Immediate Action
   [Specific steps to mitigate — e.g., disable endpoint, rotate credentials, block IP]

   ## Evidence
   [Key evidence — keep brief, full details in finding file]
   ```
5. **Write to file:** Save as `./ptest-output/escalations/escalation-{ID}.md`.
6. **Alert User:** Flag for immediate client communication.
7. **Update State:** Increment `escalations_count` in `state.yaml`.
8. **Pause Gateway:** Current gateway remains OPEN until escalation is acknowledged.

## Post-Acknowledgment
Once the user acknowledges the escalation:
- Record acknowledgment timestamp in the escalation file.
- Resume normal gateway progression.
- Include escalation in final report with timeline.

## Verification
- [ ] Finding is fully documented with evidence.
- [ ] Severity is classified with CVSS vector.
- [ ] Immediate risk assessed.
- [ ] User has been notified.
- [ ] Gateway is paused pending acknowledgment.
