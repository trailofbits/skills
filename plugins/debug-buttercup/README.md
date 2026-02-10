# debug-buttercup

Debug the Buttercup CRS (Cyber Reasoning System) running on Kubernetes.

## Skills

| Skill | Description |
|-------|-------------|
| [debug-buttercup](skills/debug-buttercup/SKILL.md) | Diagnose pod crashes, restart loops, resource pressure, and service misbehavior for Buttercup Kubernetes deployments |

## What It Covers

- **Triage workflow**: systematic approach starting with pod status, events, and warnings
- **Cascade detection**: identifying shared-dependency failures (especially Redis) before investigating individual pods
- **Redis debugging**: AOF issues, queue inspection, consumer group lag, memory diagnostics
- **Resource pressure**: OOM kills, disk saturation, CPU throttling
- **Service-specific patterns**: DinD failures, health check staleness, init container blocks
- **Diagnostic script**: automated snapshot of cluster state, queue depths, and Redis health

## Installation

```
/plugins install debug-buttercup
```
