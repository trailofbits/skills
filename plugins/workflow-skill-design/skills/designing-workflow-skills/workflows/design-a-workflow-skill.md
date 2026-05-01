# Designing a Workflow Skill

A 6-phase process for creating a workflow-based skill from scratch.

---

## Phase 1: Define Scope

**Entry:** You have a task domain in mind (e.g., "audit smart contracts", "triage findings").

**Actions:**

1. **Draft the `description` first — this is the most important field.** Claude decides whether to activate a skill based solely on the `description` in frontmatter. Third-person voice, include trigger keywords and exclusions. Test it: would this description cause the skill to activate for the right requests and stay silent for wrong ones?

2. **Write the "When to Use" section.** List 4-6 specific scenarios where the skill applies. These scope the LLM's behavior after activation — be concrete: "when auditing Solidity for reentrancy" not "when doing security."

3. **Write the "When NOT to Use" section.** List 3-5 scenarios where a different approach is better. Name the alternative: "use Semgrep for simple pattern matching" not "not for simple cases." These help the LLM redirect once active, but do not affect whether the skill activates.

4. **Define 3-5 essential principles.** These are non-negotiable rules that apply to every invocation. Ask: "What mistake would ruin the output if the LLM made it?" Each principle guards against a specific failure mode.

**Exit:** You have a draft description, When to Use, When NOT to Use, and essential principles.

---

## Phase 2: Choose Pattern

**Entry:** Phase 1 complete. You understand the skill's scope.

**Actions:**

1. **Count the distinct tasks** the skill handles. One task? Multiple independent tasks? A sequence of dependent steps?

2. **Map to a pattern** using this decision tree:

```
How many distinct paths does the skill have?
├─ One path, always the same
│  └─ Does it perform destructive actions?
│     ├─ YES -> Safety Gate Pattern
│     └─ NO  -> Linear Progression Pattern
├─ Multiple independent paths from shared setup
│  └─ Routing Pattern
├─ Multiple dependent steps in sequence
│  └─ Do steps have complex dependencies?
│     ├─ YES -> Task-Driven Pattern
│     └─ NO  -> Sequential Pipeline Pattern
└─ Unsure
   └─ Start with Linear Progression, refactor if needed
```

3. **Read the pattern description** in `references/workflow-patterns.md`. Study the structural skeleton.

4. **Validate the choice.** Does your skill's workflow naturally fit the skeleton? If you're forcing it, try a different pattern.

**Exit:** Pattern selected and validated against your skill's structure.

---

## Phase 3: Design Phases

**Entry:** Phase 2 complete. Pattern selected.

**Actions:**

1. **List every step** the skill must perform, in execution order.

2. **Group steps into phases.** Each phase should have a single responsibility. A phase that does two unrelated things should be split.

3. **For each phase, define:**
   - **Entry criteria:** What must be true before this phase starts?
   - **Actions:** Numbered list of specific steps.
   - **Exit criteria:** What artifact or state proves this phase is complete?

4. **Identify gates** (if using Safety Gate pattern). Where must execution pause for user confirmation? Gates go between analysis and action, never within either.

5. **Add a verification phase at the end.** What checks confirm the overall output is correct?

6. **Check dependencies.** Can any phases run in parallel? Must any phases always run in sequence? Document these constraints.

**Exit:** Complete phase list with entry/exit criteria for each phase.

---

## Phase 4: Assign Tools

**Entry:** Phase 3 complete. Phases designed.

**Actions:**

1. **For each action in each phase**, identify the tool it needs:
   - Finding files -> Glob
   - Searching content -> Grep
   - Reading files -> Read
   - Creating files -> Write
   - Editing files -> Edit
   - Running commands -> Bash
   - User confirmation -> AskUserQuestion
   - Delegating work -> Task
   - Tracking steps -> TaskCreate/TaskUpdate/TaskList

2. **Compile the unique tool list.** This becomes your `allowed-tools` in frontmatter.

3. **Audit for least privilege.** Remove any tool not actually used. Ask: "If I removed this tool, would any instruction break?"

4. **Check for Bash misuse.** Any action using Bash for file operations (grep, find, cat) should use the dedicated tool instead.

5. **For agents**, repeat this process for the agent's tool list. Agent tools are specified with `tools:` not `allowed-tools:`.

See `references/tool-assignment-guide.md` for the complete tool selection matrix.

**Exit:** Validated tool list for each component (skill, agents).

---

## Phase 5: Write Content

**Entry:** Phase 4 complete. Tools assigned.

**Actions:**

1. **Start with SKILL.md skeleton:**
   ```
   Frontmatter (name, description, allowed-tools)
   Essential Principles
   When to Use / When NOT to Use
   Pattern-specific routing or workflow
   Quick Reference Tables
   Reference Index
   Success Criteria
   ```

2. **Write reference files first.** These are the foundation that SKILL.md summarizes and links to.

3. **Write workflow files.** Each workflow follows the phase structure from Phase 3.

4. **Write SKILL.md last.** It summarizes and routes to the reference and workflow files.

5. **Check line counts:**
   - SKILL.md: under 500 lines
   - Reference files: under 400 lines each
   - Workflow files: under 300 lines each

6. **Verify progressive disclosure:** SKILL.md contains only what's needed for every invocation. Details are in linked files.

See `references/progressive-disclosure-guide.md` for the splitting heuristic.

**Exit:** All content files written, line counts within limits.

---

## Phase 6: Self-Review

**Entry:** Phase 5 complete. All files written.

**Actions:**

1. **Run the review checklist** in `workflows/review-checklist.md`.

2. **Check anti-patterns** against `references/anti-patterns.md`. Scan for each one.

3. **Validate file references.** Every path in SKILL.md must resolve to an existing file.

4. **Test the description.** Read it in isolation — this is the only thing Claude uses to decide activation. Would it cause the skill to activate for the right requests and stay silent for wrong ones?

5. **Check for hardcoded paths.** Search for `/Users/`, `/home/`, any absolute path.

6. **Verify frontmatter.** Valid YAML, kebab-case name, description present, tools list matches actual usage.

7. **Read SKILL.md as if you've never seen it.** Is the execution order unambiguous? Could an LLM follow it without your context?

**Exit:** All checks pass. Skill is ready for submission.
