# corellium-workflows

A Claude Code tool skill for managing Corellium virtual iOS devices for security research and malware analysis.

## What It Does

Provides operational guidance for using Corellium's virtual iOS devices as isolated analysis environments. Covers device provisioning, snapshot-based safe detonation workflows, built-in network monitoring with HTTPS interception, CoreTrace syscall tracing, Frida integration (web UI and local client), and REST API automation for batch analysis.

## Skills

| Skill | Type | Description |
|-------|------|-------------|
| [corellium-workflows](skills/corellium-workflows/SKILL.md) | Tool | Corellium virtual device management — snapshots, network monitoring, CoreTrace, Frida integration, API automation |

## Reference Files

| File | Contents |
|------|----------|
| [api-automation.md](skills/corellium-workflows/references/api-automation.md) | REST API operations, Python/JavaScript SDK examples, batch analysis workflows |
| [evidence-collection.md](skills/corellium-workflows/references/evidence-collection.md) | Network capture export, CoreTrace log analysis, Frida output collection, filesystem artifact capture |

## Related Skills

| Skill | Relationship |
|-------|-------------|
| [frida-scripting](../frida-scripting/) | Write Frida scripts to run on Corellium virtual devices |
| [frida-ios-security](../frida-ios-security/) | iOS security assessment methodology using Corellium as the test environment |
| [ios-malware-analysis](../ios-malware-analysis/) | Malware analysis methodology using Corellium as the isolated detonation lab |

## Requirements

- Corellium account (Individual or Enterprise)
- API token for automation workflows
- USBFlux (optional, for local Frida client over USB-like connection)
