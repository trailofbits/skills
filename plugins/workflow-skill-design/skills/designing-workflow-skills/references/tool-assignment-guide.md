# Tool Assignment Guide

How to choose the right tools for skills, agents, and subagents.

---

## Skills vs Agents vs Subagents

| Component | What it is | When to use | How it's triggered |
|-----------|-----------|-------------|-------------------|
| **Skill** | Knowledge/guidance (SKILL.md) | Teaching patterns, providing domain expertise, guiding decisions | Auto-activated when frontmatter `description` matches user intent |
| **Agent** | Autonomous executor (agents/*.md) | Tasks that run independently, produce structured output | Spawned via Task tool with `subagent_type` |
| **Subagent** | Agent spawned by another agent | Delegating subtasks within a larger workflow | Parent agent uses Task tool |
| **Command** | User-invoked action (commands/*.md) | Explicit operations the user triggers with `/command-name` | User types the slash command |
| **Hook** | Event-driven interceptor (hooks/) | Validating or transforming tool calls automatically | System events (PreToolUse, PostToolUse, etc.) |

**Decision:** If the user should invoke it explicitly, make it a command. If it should trigger automatically based on context, make it a skill. If it runs autonomously to produce output, make it an agent.

---

## Tool Inventory

| Tool | Purpose | Use for |
|------|---------|---------|
| **Read** | Read file contents | Examining specific files by path |
| **Glob** | Find files by pattern | Discovering files (`**/*.py`, `**/SKILL.md`) |
| **Grep** | Search file contents | Finding patterns across files |
| **Write** | Create/overwrite files | Generating output files |
| **Edit** | Modify existing files | Targeted changes to existing files |
| **Bash** | Execute shell commands | Running tools, scripts, git operations |
| **AskUserQuestion** | Get user input | Disambiguation, confirmation, preferences |
| **Task** | Spawn subagents | Delegating complex subtasks |
| **TaskCreate/TaskUpdate/TaskList** | Track progress | Multi-step workflows with dependencies |
| **TodoRead/TodoWrite** | Track progress via todo list | Most skills and agents — enables progress tracking during execution |
| **WebFetch** | Fetch URL content | Reading web pages |
| **WebSearch** | Search the web | Finding current information |

---

## Tool Selection Matrix

Map the operation you need to the correct tool:

| Operation | Correct Tool | NOT this |
|-----------|-------------|----------|
| Find files by name/pattern | **Glob** | `find` via Bash |
| Search file contents | **Grep** | `grep`/`rg` via Bash |
| Read a file | **Read** | `cat`/`head`/`tail` via Bash |
| Write a new file | **Write** | `echo`/`cat <<EOF` via Bash |
| Edit an existing file | **Edit** | `sed`/`awk` via Bash |
| Run a shell command | **Bash** | — |
| Run a Python script | **Bash** (`uv run`) | — |
| Get user confirmation | **AskUserQuestion** | Printing and hoping |
| Delegate analysis | **Task** (subagent) | Doing everything inline |

**Rule:** If a dedicated tool exists for the operation, use it. Only use Bash for operations that genuinely require shell execution (running programs, git commands, build tools).

---

## Assigning Tools to Components

### Read-Only Analysis Skills

Skills that examine code without modifying it:

```yaml
allowed-tools:
  - Read
  - Glob
  - Grep
  - TodoRead
  - TodoWrite
```

### Interactive Analysis Skills

Skills that need user input during execution:

```yaml
allowed-tools:
  - Read
  - Glob
  - Grep
  - AskUserQuestion
  - TodoRead
  - TodoWrite
```

### Code Generation Skills

Skills that produce output files:

```yaml
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Bash
  - TodoRead
  - TodoWrite
```

### Pipeline Skills (Multi-Step)

Skills that orchestrate complex workflows:

```yaml
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
  - AskUserQuestion
  - Task
  - TaskCreate
  - TaskList
  - TaskUpdate
  - TodoRead
  - TodoWrite
```

### Agents

Agents declare tools in frontmatter with `tools:` (not `allowed-tools:`):

```yaml
---
name: my-agent
description: "What it does"
tools: Read, Grep, Glob, TodoRead, TodoWrite
---
```

**Agent tool principle:** Agents should have the minimum tools needed for their specific task. A read-only analysis agent should not have Write or Bash. Most agents should include `TodoRead` and `TodoWrite` for progress tracking.

---

## Subagent Context Passing

When spawning a subagent via the Task tool, include:

1. **What to analyze** — specific file paths, function names, or patterns
2. **What to look for** — explicit criteria, not vague "analyze this"
3. **What format to return** — markdown structure, JSON schema, or checklist
4. **What tools to use** — specify the subagent_type so it has appropriate tools

**Good prompt:**
```
Read all files in plugins/my-skill/skills/my-skill/. Check that:
1. SKILL.md has valid YAML frontmatter with name and description
2. All file paths referenced in SKILL.md exist
3. SKILL.md is under 500 lines
4. No hardcoded paths (/Users/, /home/)
Return a pass/fail checklist with details for each failure.
```

**Bad prompt:**
```
Review the skill and tell me if it's good.
```

---

## Common Tool Assignment Mistakes

| Mistake | Problem | Fix |
|---------|---------|-----|
| Listing `Bash` for file operations | Fragile, verbose, permission issues | Use Read/Write/Glob/Grep |
| Listing `Write` on a read-only skill | Principle of least privilege violation | Remove Write if skill never creates files |
| Listing `Task` without using subagents | Unused tools clutter the permission model | Only list tools you actually use |
| Agent with `Bash` for `grep` | Dedicated Grep tool is more reliable | Use Grep tool instead |
| No `AskUserQuestion` on interactive skill | Skill can't get user confirmation | Add AskUserQuestion if any gate/confirmation exists |
| Missing `TaskCreate`/`TaskUpdate` on pipeline | Can't track multi-step progress | Add task tools for pipeline patterns |
| Grep per-file per-pattern | N×M tool calls, agent shortcuts and misses results | Combine patterns into single regex, grep once |
| One subagent per file | Context exhaustion, agent refuses or degrades | Batch into groups of 10-20 per subagent |

---

## Scaling Tool Calls

Instructions must produce tool-calling patterns that stay efficient regardless of codebase size. Apply the **10,000-file test**: mentally run the workflow against a 10,000-file repo. If the number of tool calls grows with input size, redesign.

### Combine-Then-Filter for Searches

When a workflow searches for multiple patterns across multiple files, combine all patterns into a single regex and grep the entire codebase once.

**Wrong:** "For each of these 10 patterns, grep all `.sol` files." (10 patterns × N files = 10N calls)

**Right:** "Grep the codebase for `pattern1|pattern2|...|pattern10`. Filter results to exclude test paths." (1 call)

The agent can then Read specific files of interest from the grep results, but the discovery step is a single call.

### Batching for Subagent Work

When a workflow needs to process many items (files, functions, findings), batch them into fixed-size groups instead of spawning one subagent per item.

**Wrong:** "Spawn a subagent for each discovered file." (N files = N subagents)

**Right:** "Batch files into groups of 10-20. Spawn one subagent per batch." (N/15 subagents, capped)

Always specify the batch size explicitly. Without a number, the agent picks its own grouping (or doesn't batch at all).

### The 10,000-File Test

Before finalizing any workflow, ask: "What happens if this runs against a 10,000-file repo?"

- **Grep calls** should be O(1) or O(patterns), not O(files) or O(files × patterns)
- **Subagent count** should be O(1) or O(batches), not O(files) or O(functions)
- **Read calls** should target specific files from search results, not enumerate all files
