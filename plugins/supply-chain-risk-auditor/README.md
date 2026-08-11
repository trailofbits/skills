# Supply Chain Risk Auditor

Generate a supply-chain risk report for a project's direct dependencies across npm,
PyPI, and Go, plus a known-advisory sweep of everything the lockfile resolves. A
deterministic collector queries registries and advisory databases; a renderer turns the
artifact into a Markdown report; the model adds narrative and remediation judgment on
top, clearly separated from what was measured.

**Author:** Spencer Michaels (original), Eric Quintero (current design)

## What it measures

| Criterion | Depth | Where it is measurable |
|---|---|---|
| Known advisories, version-matched (OSV) | direct + full lockfile tree | all three ecosystems |
| Deprecated / yanked releases | direct | npm, PyPI |
| Archived or abandoned upstream repository | direct | any GitHub-hosted repo |
| Publisher concentration (registry publish ACL) | direct | npm only — PyPI and Go publish no ACL |
| Install-time script execution | direct | npm (Go has none by design) |
| Dangerous CI workflows, checked-in binaries (OpenSSF Scorecard individual checks) | direct | repos Scorecard covers |
| Download volume, publish provenance, security policy | direct, informational — measured, never flagged | varies |

Every criterion resolves to assessed-clean, assessed-flagged, or
unassessable-with-a-reason, and the report carries a coverage table stating what could
and could not be measured. Two rules are enforced by the code rather than by
convention: unavailable data is never treated as evidence of risk, and an absent
measurement is never a clean verdict — a run that measures nothing refuses to produce
a report.

## Usage

Ask Claude to "audit this project's dependencies" or "assess the supply-chain risk of
this repo", or run the scripts directly:

```sh
cd skills/supply-chain-risk-auditor/scripts
uv run collect.py <project-dir> --json findings.json
uv run render.py findings.json --out report.md
```

Requirements: `uv` (the scripts are stdlib-only Python). Authenticated `gh` is strongly
recommended — unauthenticated GitHub allows 60 requests/hour against 5,000, and the
collector makes several per dependency. HTTP responses are cached (six-hour freshness
bound) under the system temp directory; `--offline` reruns from cache alone.

## Scope and audience

Written for the reader who owns or is engaged on the audited project. Direct
dependencies carry the full criteria set; the transitive tree is checked for advisories
only, and only where a lockfile (`package-lock.json`/`npm-shrinkwrap.json`, `uv.lock`,
or a go 1.17+ `go.mod`) resolves it. `yarn.lock`, `pnpm-lock.yaml`, and `poetry.lock`
are not read; the report notes their presence and versions fall back to manifest pins
or the latest release. Dependencies that resolve from outside their public registry
(workspace, git, vendored) are reported as unassessable rather than looked up by name.
The report states what was not examined rather than leaving it to be inferred.

The audit is designed to be useful given nothing more than a list of dependencies: it
reads manifests and lockfiles, and never installs, builds, or executes the project or
its packages. Whether the pinned set actually installs or imports cleanly is out of
scope, as are scanning the target's own source, reading dependency source, and license
compliance.

## Installation

```
/plugin install trailofbits/skills/plugins/supply-chain-risk-auditor
```
