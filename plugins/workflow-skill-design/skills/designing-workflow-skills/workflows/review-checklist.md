# Workflow Skill Review Checklist

Use this checklist to self-review a workflow skill before submission.

---

## Structural Checks

- [ ] **Frontmatter is valid YAML** with `name` and `description` fields
- [ ] **Name is kebab-case**, max 64 characters, no reserved words
- [ ] **Description is third-person** ("Analyzes X" not "I help with X")
- [ ] **Description includes trigger keywords** — this is the only field Claude uses to decide activation
- [ ] **SKILL.md is under 500 lines**
- [ ] **All referenced files exist** (every path in SKILL.md resolves)
- [ ] **No hardcoded paths** (no `/Users/`, `/home/`, or absolute paths)
- [ ] **`{baseDir}` used for all internal paths**
- [ ] **No reference chains** (files link to SKILL.md-level only, not to each other)

## Workflow Design Checks

- [ ] **When to Use section** with 4+ specific scenarios (scopes behavior after activation)
- [ ] **When NOT to Use section** with 3+ scenarios naming alternatives (scopes behavior after activation)
- [ ] **Phases are numbered** with clear ordering
- [ ] **Every phase has entry criteria** (what must be true before starting)
- [ ] **Every phase has exit criteria** (what proves the phase is complete)
- [ ] **Actions within phases are numbered** (unambiguous ordering)
- [ ] **Verification step exists** at the end of the workflow
- [ ] **Routing keywords are distinctive** (no overlap between routes, if applicable)
- [ ] **Default/fallback route exists** (if routing pattern used)
- [ ] **Gates exist before destructive actions** (if applicable)

## Content Quality Checks

- [ ] **Essential principles are present** (3-5 non-negotiable rules)
- [ ] **Principles explain WHY**, not just WHAT
- [ ] **Concrete examples** exist for key instructions (input -> output)
- [ ] **Anti-patterns or rationalizations** documented (for security/audit skills)
- [ ] **No reference dumps** — guidance over raw documentation
- [ ] **Quick reference tables** for frequently-needed information
- [ ] **Success criteria checklist** at the end

## Tool Assignment Checks

- [ ] **allowed-tools matches actual usage** (no unused tools listed)
- [ ] **Least privilege** — no Write/Bash on read-only skills
- [ ] **No Bash for file operations** (Glob/Grep/Read/Write used instead)
- [ ] **Subagent prompts are specific** (not "analyze this")
- [ ] **Subagent prompts define return format** (markdown structure, JSON schema, or checklist)
- [ ] **Agent tools declared with `tools:`** (not `allowed-tools:`)
- [ ] **No cartesian product tool calls** (patterns combined into single regex, not N×M individual calls)
- [ ] **No unbounded subagent spawning** (items batched into groups, not one subagent per file/function)

## File Organization Checks

- [ ] **SKILL.md contains only always-needed content**
- [ ] **Detailed references in `references/`** (not inlined in SKILL.md)
- [ ] **Step-by-step processes in `workflows/`** (not inlined in SKILL.md)
- [ ] **File names are descriptive kebab-case**
- [ ] **Reference files under 400 lines each**
- [ ] **Workflow files under 300 lines each**

## Final Validation

- [ ] **Read the description in isolation** — Claude uses only this field for activation. Does it activate for the right requests?
- [ ] **Read SKILL.md as a fresh reader** — is execution unambiguous?
- [ ] **Check the reference index** — does it list all supporting files?
- [ ] **Verify the pattern choice** — does the workflow naturally fit the selected pattern?
