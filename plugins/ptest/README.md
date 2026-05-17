# ptest — Penetration Testing Framework

Structured pentest engagement with mandatory quality gates preventing premature phase advancement. Guides methodical progression from reconnaissance through exploitation to reporting.

## Usage

```
/ptest start          # Initialize new engagement
/ptest status         # Show current gateway state
/ptest next           # Advance to next phase
/ptest escalate       # Escalate a critical finding
/ptest recon-passive  # Run passive recon techniques
/ptest recon-active   # Run active enumeration
/ptest exploit        # Run exploitation techniques
/ptest post-exploit   # Run post-exploitation
/ptest report         # Generate final report
```

## Phases

| # | Phase | Gate Requirement |
|---|-------|-----------------|
| 1 | Passive Recon | Attack surface mapped without target contact |
| 2 | Active Recon | Services enumerated, versions fingerprinted |
| 3 | Enumeration | Applications enumerated, APIs mapped |
| 4 | Attack Surface | Asset inventory confirmed, entry points mapped |
| 5 | Vuln Assessment | Attack trees documented, vectors prioritized |
| 6 | Exploitation | At least one vuln exploited with PoC |
| 7 | Post-Exploitation | Privesc and lateral movement assessed |
| 8 | Reporting | Final report with all findings delivered |

## Requirements

- Written authorization for the target engagement
- Standard pentest tools (nmap, gobuster, nuclei, etc.) — use `preflight` to check
