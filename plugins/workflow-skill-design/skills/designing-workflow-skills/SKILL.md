---
name: designing-workflow-skills
description: >-
  Guides the design and structuring of workflow-based Claude Code skills
  with multi-step phases, decision trees, subagent delegation, and
  progressive disclosure. Use when creating skills that involve
  sequential pipelines, routing patterns, safety gates, task tracking,
  phased execution, or any multi-step workflow. Also applies when
  reviewing or refactoring existing workflow skills for quality.
allowed-tools:
  - Read
  - Glob
  - Grep
  - TodoRead
  - TodoWrite
---

# Designing Workflow Skills

Build workflow-based skills that execute reliably by following structural patterns, not prose.

## Essential Principles

<essential_principles>

<principle name="description-is-the-trigger">
**The `description` field is the only thing that controls when a skill activates.**

Claude decides whether to load a skill based solely on its frontmatter `description`. The body of SKILL.md — including "When to Use" and "When NOT to Use" sections — is only read AFTER the skill is already active. Put your trigger keywords, use cases, and exclusions in the description. A bad description means wrong activations or missed activations regardless of what the body says.

"When to Use" and "When NOT to Use" sections still serve a purpose: they scope the LLM's behavior once active. "When NOT to Use" should name specific alternatives: "use Semgrep for simple pattern matching" not "not for simple tasks."
</principle>

<principle name="numbered-phases">
**Phases must be numbered with entry and exit criteria.**

Unnumbered prose instructions produce unreliable execution order. Every phase needs:
- A number (Phase 1, Phase 2, ...)
- Entry criteria (what must be true before starting)
- Numbered actions (what to do)
- Exit criteria (how to know it's done)
</principle>

<principle name="tools-match-executor">
**Tools must match the executor.**

Skills use `allowed-tools:` in frontmatter. Agents use `tools:` in frontmatter. Subagents get tools from their `subagent_type`. Never list tools the component doesn't use. Never use Bash for operations that have dedicated tools (Glob, Grep, Read, Write, Edit).

Most skills and agents should include `TodoRead` and `TodoWrite` in their tool list — these enable progress tracking during multi-step execution and are useful even for skills that don't explicitly manage tasks.
</principle>

<principle name="progressive-disclosure">
**Progressive disclosure is structural, not optional.**

SKILL.md stays under 500 lines. It contains only what the LLM needs for every invocation: principles, routing, quick references, and links. Detailed patterns go in `references/`. Step-by-step processes go in `workflows/`. One level deep — no reference chains.
</principle>

<principle name="scalable-tool-patterns">
**Instructions must produce tool-calling patterns that scale.**

Every workflow instruction becomes tool calls at runtime. If a workflow searches N files for M patterns, combine into one regex — not N×M calls. If a workflow spawns subagents per item, use batching — not one subagent per file. Apply the 10,000-file test: mentally run the workflow against a large repo and check that tool call count stays bounded. See [anti-patterns.md](references/anti-patterns.md) AP-18 and AP-19.
</principle>

<principle name="degrees-of-freedom">
**Match instruction specificity to task fragility.**

Not every step needs the same level of prescription. Calibrate per step:
- **Low freedom** (exact commands, no variation): Fragile operations — database migrations, crypto, destructive actions. "Run exactly this script."
- **Medium freedom** (pseudocode with parameters): Preferred patterns where variation is acceptable. "Use this template and customize as needed."
- **High freedom** (heuristics and judgment): Variable tasks — code review, exploration, documentation. "Analyze the structure and suggest improvements."

A skill can mix freedom levels. A security audit skill might use high freedom for the discovery phase ("explore the codebase for auth patterns") and low freedom for the reporting phase ("use exactly this severity classification table").
</principle>

</essential_principles>

## When to Use

- Designing a new skill with multi-step workflows or phased execution
- Creating a skill that routes between multiple independent tasks
- Building a skill with safety gates (destructive actions requiring confirmation)
- Structuring a skill that uses subagents or task tracking
- Reviewing or refactoring an existing workflow skill for quality
- Deciding how to split content between SKILL.md, references/, and workflows/

## When NOT to Use

- Simple single-purpose skills with no workflow (just guidance) — write the SKILL.md directly
- Writing the actual domain content of a skill (this teaches structure, not domain expertise)
- Plugin configuration (plugin.json, hooks, commands) — use plugin development guides
- Non-skill Claude Code development — this is specifically for skill architecture

## Pattern Selection

Choose the right pattern for your skill's structure. Read the full pattern description in [workflow-patterns.md](references/workflow-patterns.md).

```
How many distinct paths does the skill have?
|
+-- One path, always the same
|   +-- Does it perform destructive actions?
|       +-- YES -> Safety Gate Pattern
|       +-- NO  -> Linear Progression Pattern
|
+-- Multiple independent paths from shared setup
|   +-- Routing Pattern
|
+-- Multiple dependent steps in sequence
    +-- Do steps have complex dependencies?
        +-- YES -> Task-Driven Pattern
        +-- NO  -> Sequential Pipeline Pattern
```

### Pattern Summary

| Pattern | Use When | Key Feature |
|---------|----------|-------------|
| **Routing** | Multiple independent tasks from shared intake | Routing table maps intent to workflow files |
| **Sequential Pipeline** | Dependent steps, each feeding the next | Auto-detection may resume from partial progress |
| **Linear Progression** | Single path, same every time | Numbered phases with entry/exit criteria |
| **Safety Gate** | Destructive/irreversible actions | Two confirmation gates before execution |
| **Task-Driven** | Complex dependencies, partial failure tolerance | TaskCreate/TaskUpdate with dependency tracking |

## Structural Anatomy

Every workflow skill needs this skeleton, regardless of pattern:

```markdown
---
name: kebab-case-name
description: "Third-person description with trigger keywords — this is how Claude decides to activate the skill"
allowed-tools:
  - [minimum tools needed]
# Optional fields — see tool-assignment-guide.md for full reference:
# disable-model-invocation: true    # Only user can invoke (not Claude)
# user-invocable: false             # Only Claude can invoke (hidden from / menu)
# context: fork                     # Run in isolated subagent context
# agent: Explore                    # Subagent type (requires context: fork)
# model: [model-name]               # Switch model when skill is active
# argument-hint: "[filename]"       # Hint shown during autocomplete
---

# Title

## Essential Principles
[3-5 non-negotiable rules with WHY explanations]

## When to Use
[4-6 specific scenarios — scopes behavior after activation]

## When NOT to Use
[3-5 scenarios with named alternatives — scopes behavior after activation]

## [Pattern-Specific Section]
[Routing table / Pipeline steps / Phase list / Gates]

## Quick Reference
[Compact tables for frequently-needed info]

## Reference Index
[Links to all supporting files]

## Success Criteria
[Checklist for output validation]
```

Skills support three types of string substitutions: dollar-prefixed variables for arguments and session ID, and exclamation-backtick syntax for shell preprocessing. The skill loader processes these before Claude sees the file — even inside code fences — so never use the raw syntax in documentation text. See [tool-assignment-guide.md](references/tool-assignment-guide.md) for the full variable reference and usage guidance.

## Anti-Pattern Quick Reference

The most common mistakes. Full catalog with before/after fixes in [anti-patterns.md](references/anti-patterns.md).

| AP | Anti-Pattern | One-Line Fix |
|----|-------------|-------------|
| AP-1 | Missing goals/anti-goals | Add When to Use AND When NOT to Use sections |
| AP-2 | Monolithic SKILL.md (>500 lines) | Split into references/ and workflows/ |
| AP-3 | Reference chains (A -> B -> C) | All files one hop from SKILL.md |
| AP-4 | Hardcoded paths | Use `{baseDir}` for all internal paths |
| AP-5 | Broken file references | Verify every path resolves before submitting |
| AP-6 | Unnumbered phases | Number every phase with entry/exit criteria |
| AP-7 | Missing exit criteria | Define what "done" means for every phase |
| AP-8 | No verification step | Add validation at the end of every workflow |
| AP-9 | Vague routing keywords | Use distinctive keywords per workflow route |
| AP-11 | Wrong tool for the job | Use Glob/Grep/Read, not Bash equivalents |
| AP-12 | Overprivileged tools | Remove tools not actually used |
| AP-13 | Vague subagent prompts | Specify what to analyze, look for, and return |
| AP-15 | Reference dumps | Teach judgment, not raw documentation |
| AP-16 | Missing rationalizations | Add "Rationalizations to Reject" for audit skills |
| AP-17 | No concrete examples | Show input -> output for key instructions |
| AP-18 | Cartesian product tool calls | Combine patterns into single regex, grep once, then filter |
| AP-19 | Unbounded subagent spawning | Batch items into groups, one subagent per batch |
| AP-20 | Description summarizes workflow | Description = triggering conditions only, never workflow steps |

*AP-10 (No Default/Fallback Route), AP-14 (Missing Tool Justification in Agents), and AP-20 (Description Summarizes Workflow) are in the [full catalog](references/anti-patterns.md). AP-20 is included in the quick reference above due to its high impact.*

## Tool Assignment Quick Reference

Map your component type to the right tool set. Full guide in [tool-assignment-guide.md](references/tool-assignment-guide.md).

| Component Type | Typical Tools |
|---------------|---------------|
| Read-only analysis skill | Read, Glob, Grep, TodoRead, TodoWrite |
| Interactive analysis skill | Read, Glob, Grep, AskUserQuestion, TodoRead, TodoWrite |
| Code generation skill | Read, Glob, Grep, Write, Bash, TodoRead, TodoWrite |
| Pipeline skill | Read, Write, Glob, Grep, Bash, AskUserQuestion, Task, TaskCreate, TaskList, TaskUpdate, TodoRead, TodoWrite |
| Read-only agent | Read, Grep, Glob, TodoRead, TodoWrite |
| Action agent | Read, Grep, Glob, Write, Bash, TodoRead, TodoWrite |

**Key rules:**
- Use Glob (not `find`), Grep (not `grep`), Read (not `cat`) — always prefer dedicated tools
- Skills use `allowed-tools:` — agents use `tools:`
- List only tools that instructions actually reference
- Read-only components should never have Write or Bash

## Rationalizations to Reject

When designing workflow skills, reject these shortcuts:

| Rationalization | Why It's Wrong |
|-----------------|----------------|
| "It's obvious which phase comes next" | LLMs don't infer ordering from prose. Number the phases. |
| "Exit criteria are implied" | Implied criteria are skipped criteria. Write them explicitly. |
| "One big SKILL.md is simpler" | Simpler to write, worse to execute. The LLM loses focus past 500 lines. |
| "The description doesn't matter much" | The description is how the skill gets triggered. A bad description means wrong activations or missed activations. |
| "Bash can do everything" | Bash file operations are fragile. Dedicated tools handle encoding, permissions, and formatting better. |
| "The LLM will figure out the tools" | It will guess wrong. Specify exactly which tool for each operation. |
| "I'll add details later" | Incomplete skills ship incomplete. Design fully before writing. |

## Reference Index

| File | Content |
|------|---------|
| [workflow-patterns.md](references/workflow-patterns.md) | 5 patterns with structural skeletons and examples |
| [anti-patterns.md](references/anti-patterns.md) | 20 anti-patterns with before/after fixes |
| [tool-assignment-guide.md](references/tool-assignment-guide.md) | Tool selection matrix, component comparison, subagent guidance |
| [progressive-disclosure-guide.md](references/progressive-disclosure-guide.md) | Content splitting rules, the 500-line rule, sizing guidelines |

| Workflow | Purpose |
|----------|---------|
| [design-a-workflow-skill.md](workflows/design-a-workflow-skill.md) | 6-phase creation process from scope to self-review |
| [review-checklist.md](workflows/review-checklist.md) | Structured self-review checklist for submission readiness |

## Success Criteria

A well-designed workflow skill:

- [ ] Has When to Use AND When NOT to Use sections
- [ ] Uses a recognizable pattern (routing, pipeline, linear, safety gate, or task-driven)
- [ ] Numbers all phases with entry and exit criteria
- [ ] Lists only the tools it actually uses (least privilege)
- [ ] Keeps SKILL.md under 500 lines with details in references/workflows
- [ ] Has no hardcoded paths (uses `{baseDir}`)
- [ ] Has no broken file references
- [ ] Has no reference chains (all links one hop from SKILL.md)
- [ ] Includes a verification step at the end of the workflow
- [ ] Has a description that triggers correctly (third-person, specific keywords)
- [ ] Includes concrete examples for key instructions
- [ ] Explains WHY, not just WHAT, for essential principles
