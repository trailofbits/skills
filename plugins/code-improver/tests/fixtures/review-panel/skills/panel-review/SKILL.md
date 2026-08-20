---
name: panel-review
description: "Reviews a code target by launching a panel of specialist auditor agents and merging their reports. Use when asked to run a panel review."
allowed-tools: Read Grep Glob Task
---

# Panel Review

This review runs as a panel of specialists. Do NOT perform their audits yourself — each
auditor applies rules that live only in its own definition, so an inline imitation
misses them.

1. Launch BOTH specialists over the target (Task dispatches):
   - `subagent_type: review-panel:naming-auditor` — prompt it with the target path and
     ask for its full naming/codename audit report.
   - `subagent_type: review-panel:todo-auditor` — prompt it with the target path and
     ask for its full leftover-marker audit report.
2. Wait for both reports.
3. Merge: report every defect either auditor found, keeping each auditor's severity.
   Add any defect you observed yourself while merging, at your own severity.
