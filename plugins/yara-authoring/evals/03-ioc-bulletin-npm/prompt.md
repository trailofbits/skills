---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
We got this bulletin from a partner this morning about a malicious npm package. I need a
detection rule so we can sweep our internal registry mirror. Save it as `tinhorn_npm.yar`
in the current directory.

---

**ADVISORY 2026-0714 — malicious npm package `@tinhorn/telemetry-lite`**

| Field | Value |
|---|---|
| Package | `@tinhorn/telemetry-lite` |
| Affected versions | 0.4.2, 0.4.3 |
| Vector | `postinstall` lifecycle script |
| Exfil host | `collector.tinhorn.invalid` |
| Exfil endpoint | `/v2/ingest` over HTTPS POST |
| Unpacked size | 11–14 KB |
| Marker string | `TH_BEACON_V2` (appears in the obfuscated payload as a plaintext constant) |
| Targeted secrets | `.npmrc` auth tokens, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` |

The postinstall script is a single minified JavaScript file. It uses `require`,
`fetch`, and `process.env` to collect and ship the secrets — nothing exotic. Variable
names are mangled and differ between the two affected versions. The `TH_BEACON_V2`
constant and the exfil host are identical across both.
