---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
Here's an analyst writeup a colleague sent over. Can you turn this into a detection rule? Save it as `larkspur.yar` in the current directory.

---

**Larkspur — macOS backdoor, first observed May 2026**

Larkspur is a persistent backdoor targeting macOS developer workstations, distributed
via a trojanized build of an internal CI helper. Samples are 64-bit Mach-O binaries,
typically 800KB–2MB, not universal builds.

Persistence is established through a LaunchAgent written to the user's home directory
with the label `com.larkspur.syncagent`. The plist is unremarkable apart from the label.

Command and control uses HTTPS with a hardcoded custom user-agent string,
`LarkspurSync/1.2`. Beacon interval is 300 seconds with jitter.

The binary contains a verbose error path that emits the string
`tunnel handshake failed, retrying` to a log file when C2 is unreachable. This appears
in every sample we have looked at, including the two earliest ones.

Standard macOS APIs are used throughout — the implant shells out with `NSTask` for most
of its post-exploitation work and reads broadly under `~/Library` to inventory installed
developer tooling. No packing or obfuscation observed.
