# Workflow Patterns

Five patterns for structuring workflow-based skills. Choose based on your skill's decision structure, not its domain.

---

## 1. Routing Pattern

**When to use:** The skill handles multiple independent tasks that share common setup but diverge into separate paths.

**Key characteristics:**
- Intake form collects context upfront
- Router maps user intent to a specific workflow file
- Each workflow is self-contained and independent
- Adding a new capability means adding a new workflow file, not modifying existing ones

**Structural skeleton:**

```markdown
<intake>
Step 1: What data do you have?
- Option A -> Proceed
- Option B -> Extract first, then proceed
- No data -> Ask user to provide it

Step 2: What would you like to do?
1. Task One - brief description
2. Task Two - brief description
3. Task Three - brief description
</intake>

<routing>
| Response | Workflow |
|----------|----------|
| 1, "keyword", "phrase" | `workflows/task-one.md` |
| 2, "keyword", "phrase" | `workflows/task-two.md` |
| 3, "keyword", "phrase" | `workflows/task-three.md` |

**After reading the workflow, follow it exactly.**
</routing>
```

**Key design decisions:**
- Intake MUST validate prerequisites before routing (e.g., "do you have the required data?")
- Routing table uses both numeric options AND keyword synonyms for fuzzy matching
- Each workflow file stands alone — no cross-workflow dependencies
- The routing instruction "follow it exactly" prevents the LLM from improvising

**Common mistakes:**
- Routing based on vague keywords that overlap between workflows
- Forgetting to handle the "none of the above" case
- Putting workflow logic in SKILL.md instead of separate files
- Missing the "follow it exactly" instruction, causing the LLM to paraphrase instead of execute

---

## 2. Sequential Pipeline Pattern

**When to use:** The skill executes a series of dependent steps where each step's output feeds the next. Skipping steps produces bad results.

**Key characteristics:**
- Steps must execute in order
- Each step has entry criteria (what must be true) and exit criteria (what it produces)
- Auto-detection logic determines which step to start from
- Task tracking (TaskCreate/TaskUpdate) coordinates multi-step execution

**Structural skeleton:**

```markdown
## Quick Start

For the common case ("do the standard thing"):
1. Verify prerequisites are installed
2. Check for existing artifacts from prior runs

Then execute the full pipeline: step1 -> step2 -> step3

## Workflow Selection

| Workflow | Purpose |
|----------|---------|
| [step-one](workflows/step-one.md) | First phase description |
| [step-two](workflows/step-two.md) | Second phase description |
| [step-three](workflows/step-three.md) | Third phase description |

### Auto-Detection Logic

| Condition | Action |
|-----------|--------|
| No artifacts exist | Execute full pipeline (step1 -> step2 -> step3) |
| Step 1 complete | Execute step2 -> step3 |
| Steps 1-2 complete | Ask user: run step3 on existing, or restart? |
```

**Key design decisions:**
- Auto-detection prevents redundant work when partial results exist
- Each workflow file documents its own entry/exit criteria
- The decision prompt asks the user only when the correct action is ambiguous
- Pipeline dependencies are explicit — "step2 requires output from step1"

**Common mistakes:**
- No auto-detection, forcing users to always start from scratch
- Steps that silently fail without checking their own prerequisites
- Missing the "ask user" case when existing artifacts may be stale
- Workflow files that assume prior steps ran without checking

---

## 3. Linear Progression Pattern

**When to use:** A single start-to-finish process with no branching. Every execution follows the same numbered phases.

**Key characteristics:**
- One path, no routing decisions
- Phases are strictly numbered and sequential
- Each phase has clear completion criteria
- The user follows the entire flow every time

**Structural skeleton:**

```markdown
## Workflow

### Phase 1: Setup
**Entry:** User has provided [input]
**Actions:**
1. Validate input
2. Check prerequisites
**Exit:** [Specific artifact] exists and is valid

### Phase 2: Analysis
**Entry:** Phase 1 exit criteria met
**Actions:**
1. Perform analysis step A
2. Perform analysis step B
**Exit:** [Analysis result] is complete

### Phase 3: Output
**Entry:** Phase 2 exit criteria met
**Actions:**
1. Generate output
2. Validate output
**Exit:** [Final deliverable] ready for user
```

**Key design decisions:**
- Entry/exit criteria on every phase prevent skipping
- Actions within phases are numbered for unambiguous ordering
- No conditional branching — if you need branches, use Routing or Sequential Pipeline
- Verification at the end catches errors from any phase

**Common mistakes:**
- Phases without exit criteria ("do analysis" — how do you know it's done?)
- Mixing phases that should be separate (analysis + output in one phase)
- No verification step at the end
- Using this pattern when the skill actually needs routing (forcing a linear flow on branching logic)

---

## 4. Safety Gate Pattern

**When to use:** The skill performs destructive or irreversible actions. User confirmation is required before any such action.

**Key characteristics:**
- Analysis phase gathers all information before any action
- Explicit confirmation gates (usually two: review + execute)
- Exact commands shown to user before execution
- Individual action execution (so partial failures don't block remaining work)

**Structural skeleton:**

```markdown
## Core Principle: SAFETY FIRST

**Never [perform action] without explicit user confirmation.**

## Workflow

### Phase 1: Comprehensive Analysis
Gather ALL information upfront before any action.
[Data gathering commands]

### Phase 2: Categorize
[Decision tree for categorizing items]
| Category | Meaning | Action |
|----------|---------|--------|
| SAFE | Verified safe | Standard action |
| RISKY | Needs review | User decides |
| KEEP | Active/needed | No action |

### GATE 1: Present Complete Analysis
Present everything in ONE comprehensive view.
[Formatted summary with categories]
Use AskUserQuestion with clear options.
**Do not proceed until user responds.**

### GATE 2: Final Confirmation with Exact Commands
Show the EXACT commands that will run.
**Confirm? (yes/no)**

### Phase 3: Execute
Run each action as a **separate command**.
Report result of each. Continue on individual failure.

### Phase 4: Report
[Summary of what was done and what remains]
```

**Key design decisions:**
- Two gates, not one: first to review the plan, second to approve exact commands
- Analysis MUST complete before any gate — no incremental "analyze then ask"
- Individual execution means one failure doesn't block the rest
- Report phase shows both what changed and what was left untouched

**Common mistakes:**
- Only one confirmation gate (user approves without seeing exact commands)
- Interleaving analysis and confirmation (asking after each item instead of all at once)
- Batch execution where one failure aborts everything
- Missing the report phase, leaving the user unsure what happened

---

## 5. Task-Driven Pattern

**When to use:** Complex multi-step workflows where steps have dependencies, can partially fail, and need progress tracking.

**Key characteristics:**
- TaskCreate/TaskUpdate/TaskList for state management
- Explicit dependency declarations (blockedBy/blocks)
- Each task is independently completable
- Progress is visible and resumable

**Structural skeleton:**

```markdown
## Workflow

### Phase 1: Plan
Analyze inputs and create task list:

- TaskCreate: "Step A" (no dependencies)
- TaskCreate: "Step B" (blockedBy: Step A)
- TaskCreate: "Step C" (blockedBy: Step A)
- TaskCreate: "Step D" (blockedBy: Step B, Step C)

### Phase 2: Execute
For each unblocked task:
1. TaskUpdate: set to in_progress
2. Execute the task
3. TaskUpdate: set to completed
4. TaskList: check for newly unblocked tasks

### Phase 3: Report
TaskList to show final status.
Report completed vs failed tasks.
```

**Key design decisions:**
- Dependencies are declared upfront, not discovered during execution
- Tasks that don't depend on each other can execute in parallel
- Failed tasks block dependents but don't abort unrelated tasks
- TaskList provides natural progress reporting

**Common mistakes:**
- Creating tasks without dependency declarations, then executing in wrong order
- Not checking TaskList after completing a task (missing newly unblocked work)
- Marking tasks complete before verifying they actually succeeded
- Using task tracking for linear workflows where it adds overhead without value

---

## Cross-Pattern Guidance: Feedback Loops

Any pattern can incorporate a validation loop — not just a final check.

**When to use:** The workflow modifies state iteratively and intermediate results can be validated.

**Structure:**
```
Execute step → Validate → Pass? → Next step
                       → Fail? → Fix → Re-validate
```

**Examples:**
- TDD: write test → run → fail → write code → run → pass → refactor → run → pass
- PR iteration: push → CI checks → fix failures → push → re-check
- Form filling: map fields → validate mapping → fix errors → re-validate → fill

**Key design decisions:**
- Define a maximum loop count (e.g., "if 3+ attempts fail, stop and ask for help")
- Each loop iteration must make the validation command explicit ("Run: `python validate.py`")
- Distinguish between "fix and retry" loops (automated) and "escalate" exits (human intervention)

**Common mistakes:**
- Verification only at the end, not after each mutation
- No loop bound, causing infinite retry spirals
- Loop body that doesn't re-run the same validation command
