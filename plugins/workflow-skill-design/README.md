# Workflow Skill Design

A Claude Code plugin that teaches design patterns for building workflow-based skills and provides a review agent for auditing existing skills.

## Components

### Skills

- **designing-workflow-skills** — Guides the design and structuring of workflow-based Claude Code skills with multi-step phases, decision trees, subagent delegation, and progressive disclosure.

### Agents

- **workflow-skill-reviewer** — Reviews workflow-based skills for structural quality, pattern adherence, tool assignment correctness, and anti-pattern detection. Produces a graded audit report.

## What This Plugin Teaches

Five workflow patterns for structuring skills:

| Pattern | Use When |
|---------|----------|
| **Routing** | Multiple independent tasks from shared intake |
| **Sequential Pipeline** | Dependent steps, each feeding the next |
| **Linear Progression** | Single path, same every time |
| **Safety Gate** | Destructive/irreversible actions needing confirmation |
| **Task-Driven** | Complex dependencies with progress tracking |

Plus: anti-pattern detection, tool assignment rules, and progressive disclosure guidance.

## Installation

```
/plugin install trailofbits/skills:workflow-skill-design
```

## Usage

### Designing a New Skill

Ask Claude to help design a workflow skill — the skill triggers automatically when the request involves multi-step workflows, phased execution, routing patterns, or skill architecture.

### Reviewing an Existing Skill

The `workflow-skill-reviewer` agent can be spawned to audit any skill:

```
Review the skill at plugins/my-plugin/skills/my-skill/ for quality issues.
```

## File Structure

```
plugins/workflow-skill-design/
  .claude-plugin/
    plugin.json
  skills/
    designing-workflow-skills/
      SKILL.md
      references/
        workflow-patterns.md
        anti-patterns.md
        tool-assignment-guide.md
        progressive-disclosure-guide.md
      workflows/
        design-a-workflow-skill.md
        review-checklist.md
  agents/
    workflow-skill-reviewer.md
  README.md
```
