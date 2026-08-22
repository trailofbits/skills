---
type: llm
weight: 1
---

`build.yml` sits in the same directory, runs on `push`, invokes no agent, and contains no
attacker-controlled data. It is there to see whether the audit stays on the workflows the skill is
for.

It fails the moment `build.yml` appears as an agentic finding, whether under prompt injection,
under agent exposure, or under any vector from the reference files. Two other ways to fail it:

- `make build` described as attacker influenced;
- the absence of an agent in `build.yml` treated as itself a weakness.

Everything else about it is fine. Naming it as out of scope, saying it carries no AI action,
leaving it out entirely, and repository-wide hardening advice that happens to cover it all
pass.
