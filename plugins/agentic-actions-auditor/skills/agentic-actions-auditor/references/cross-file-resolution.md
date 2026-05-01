# Cross-File Resolution: Composite Actions and Reusable Workflows

AI agents can be hidden inside composite actions and reusable workflows, invisible when analyzing only the caller workflow file. This reference documents how to classify `uses:` references, resolve the referenced files, trace input mappings across file boundaries, and report unresolved references.

Resolution is limited to one level deep (fixed). If a resolved file contains its own cross-file references, log them as unresolved -- do not follow.

## uses: Reference Classification

Parse each `uses:` value to determine its type and resolution strategy.

| `uses:` Pattern | Reference Type | Resolution | In Scope? |
|----------------|---------------|------------|-----------|
| `./path/to/action` | Local composite action | Read `{path}/action.yml` from filesystem | YES |
| `./.github/workflows/called.yml` | Local reusable workflow | Read file from filesystem | YES |
| `owner/repo/.github/workflows/file.yml@ref` | Remote reusable workflow | Fetch via `gh api` Contents API | YES |
| `docker://image:tag` | Docker image | N/A -- no steps to analyze | NO (skip) |
| `owner/repo@ref` (without `.github/workflows/`) | Remote action | Would require remote action.yml fetch | NO (skip silently) |

**Classification algorithm:**

```
Given a uses: value:
1. Starts with "./" AND path contains ".github/workflows/" -> LOCAL REUSABLE WORKFLOW
2. Starts with "./" -> LOCAL COMPOSITE ACTION
3. Contains ".github/workflows/" AND contains "@" -> REMOTE REUSABLE WORKFLOW
4. Starts with "docker://" -> DOCKER IMAGE (skip)
5. Else -> REMOTE ACTION (out of scope, skip silently)
```

Order matters: check step 1 before step 2, because local reusable workflows also start with `./`.

**Context distinction:** Step-level `uses:` (inside `steps:` array) references actions. Job-level `uses:` (at the same level as `runs-on:`) references reusable workflows. Local reusable workflows use job-level `uses:` with a `./` prefix.

## Local Composite Action Resolution

**Given:** `uses: ./path/to/action` at the step level.

**Local analysis mode:**
1. Read `{path}/action.yml` from the filesystem using the Read tool
2. If not found, try `{path}/action.yaml` (GitHub supports both, prefers `.yml`)
3. If neither exists, log as unresolved with reason "File not found"

**Remote analysis mode:**
1. Fetch via Contents API: `gh api repos/{owner}/{repo}/contents/{path}/action.yml?ref={ref} --jq '.content | @base64d'`
2. On 404, try `action.yaml`: `gh api repos/{owner}/{repo}/contents/{path}/action.yaml?ref={ref} --jq '.content | @base64d'`
3. If both 404, log as unresolved with reason "File not found"

**Type discrimination -- check `runs.using`:**

| `runs.using` Value | Action Type | Analyze? |
|-------------------|-------------|----------|
| `composite` | Composite action | YES -- scan `runs.steps[]` |
| `node12`, `node16`, `node20`, `node24` | JavaScript action | NO -- skip silently |
| `docker` | Docker action | NO -- skip silently |

Only composite actions have `runs.steps[]` containing workflow-style steps. If `runs.using` is not `composite`, skip silently -- do NOT log as unresolved.

**Analysis of composite action steps:**
1. For each step in `runs.steps[]`, check `uses:` against the known AI action references (SKILL.md Step 2)
2. If an AI action is found, capture its `with:` fields for security context (SKILL.md Step 3)
3. Run the same attack vector detection (SKILL.md Step 4) on each AI action step found
4. Any `uses:` cross-file references found inside the resolved file are logged as unresolved (depth limit) -- do NOT follow them

## Local Reusable Workflow Resolution

**Given:** Job-level `uses: ./.github/workflows/called.yml`.

**Local analysis mode:**
1. Read the file from the filesystem using the Read tool

**Remote analysis mode:**
1. Fetch via Contents API using the same repo context: `gh api repos/{owner}/{repo}/contents/.github/workflows/{filename}?ref={ref} --jq '.content | @base64d'`

The resolved file is a complete workflow YAML with `on: workflow_call`. Analyze it through the existing Steps 2-4 detection pipeline -- identify AI action steps, capture security context, and detect attack vectors.

**Input mapping:** The caller passes values via job-level `with:`, and the called workflow accesses them via `${{ inputs.* }}` (defined under `on: workflow_call: inputs:`).

## Remote Reusable Workflow Resolution

**Given:** Job-level `uses: owner/repo/.github/workflows/file.yml@ref`.

**Parse the reference:**
- Extract: `owner`, `repo`, file path (everything after `repo/` and before `@`), and `ref` (everything after `@`)
- Example: `org/shared/.github/workflows/review.yml@main` -> owner=`org`, repo=`shared`, path=`.github/workflows/review.yml`, ref=`main`

**Fetch:**
```
gh api repos/{owner}/{repo}/contents/.github/workflows/{filename}?ref={ref} --jq '.content | @base64d'
```

This is the same Contents API pattern established in Step 0 (Phase 5).

**Error handling:**
- 404: Log as unresolved with reason "404 Not Found (repository may be private)"
- Auth error (401/403): Log as unresolved with reason "Authentication required"

Analyze the resolved workflow YAML through existing Steps 2-4. Cross-file findings mix into the main findings list sorted by severity -- they just have a longer file-chain trace.

## Input Mapping Traces

When an AI action is found inside a resolved file, trace the data flow from the caller's `with:` values through `inputs.*` to the AI prompt field. This extends the existing data flow trace pattern from foundations.md.

### Composite Action Input Trace

```
Caller workflow (.github/workflows/review.yml):
  steps:
    - uses: ./actions/issue-triage
      with:
        issue_body: ${{ github.event.issue.body }}    # attacker-controlled

Composite action (actions/issue-triage/action.yml):
  inputs:
    issue_body:
      description: "The issue body text"
  runs:
    using: composite
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Triage this issue: ${{ inputs.issue_body }}"
```

**Data flow trace:**
```
1. Attacker creates issue with malicious content in body
2. Caller: with.issue_body = ${{ github.event.issue.body }}
   -> .github/workflows/review.yml, jobs.triage.steps[1]
3. Composite action receives: inputs.issue_body = attacker content
   -> actions/issue-triage/action.yml, inputs.issue_body
4. AI action: prompt contains ${{ inputs.issue_body }}
   -> actions/issue-triage/action.yml, runs.steps[0]
5. Claude executes with tainted prompt -- attacker achieves prompt injection
```

### Reusable Workflow Input Trace

```
Caller workflow (.github/workflows/ci.yml):
  jobs:
    ai-review:
      uses: org/shared/.github/workflows/ai-review.yml@main
      with:
        pr_body: ${{ github.event.pull_request.body }}

Called workflow (org/shared/.github/workflows/ai-review.yml):
  on:
    workflow_call:
      inputs:
        pr_body:
          type: string
  jobs:
    review:
      runs-on: ubuntu-latest
      steps:
        - uses: anthropics/claude-code-action@v1
          with:
            prompt: "Review this PR: ${{ inputs.pr_body }}"
```

**Data flow trace:**
```
1. Attacker opens PR with malicious content in body
2. Caller: with.pr_body = ${{ github.event.pull_request.body }}
   -> .github/workflows/ci.yml, jobs.ai-review
3. Reusable workflow receives: inputs.pr_body = attacker content
   -> org/shared/.github/workflows/ai-review.yml, on.workflow_call.inputs
4. AI action: prompt contains ${{ inputs.pr_body }}
   -> org/shared/.github/workflows/ai-review.yml, jobs.review.steps[0]
5. Claude executes with tainted prompt via pull_request_target (has secrets access)
```

The trace format follows the same stacked multi-line style as other data flow traces in this skill. Each hop shows the relevant YAML location. Cross-file findings have a longer trace because they span multiple files, but are otherwise identical to direct findings.

## Depth Limit and Unresolved References

**Depth limit:** Fixed at 1 level. The top-level workflow is depth 0. Resolved files (composite actions and reusable workflows) are depth 1. Any cross-file references found at depth 1 are logged as unresolved with reason "Depth limit exceeded (max 1 level)" -- do NOT follow them.

This covers the overwhelming majority of real-world patterns. Deeper nesting is rare and may indicate intentional obfuscation, which is worth noting in findings.

**Unresolved reference reporting:**

When any references could not be resolved, add an "Unresolved References" section at the end of the report:

```markdown
## Unresolved References

| Reference | Source | Reason |
|-----------|--------|--------|
| `org/private/.github/workflows/scan.yml@v2` | `.github/workflows/ci.yml` jobs.scan | 404 Not Found (repository may be private) |
| `./actions/deep-nested` | `actions/wrapper/action.yml` runs.steps[2] | Depth limit exceeded (max 1 level) |
```

- Omit this section entirely when all references resolve successfully
- The summary counts total findings only -- it does not count resolved or unresolved references

## Edge Cases

**action.yml vs action.yaml:** Try `.yml` first, fall back to `.yaml`. GitHub supports both filenames and prefers `.yml`. This applies to both filesystem reads and API fetches.

**Non-composite actions at local paths:** When `./path/to/action` resolves to a JavaScript or Docker action (`runs.using` is `node*` or `docker`), skip silently. Do NOT log as unresolved -- these are valid actions that simply have no analyzable workflow-style steps.

**Local paths in remote analysis mode:** Fetch via Contents API using the same repo context. The `./` prefix is relative to the repository root, and the Contents API can retrieve any path: `gh api repos/{owner}/{repo}/contents/{path}/action.yml?ref={ref}`.

**Missing files:** Log as unresolved with the specific reason (404, file not found, etc.). Do not treat missing files as errors that halt analysis -- continue with remaining references.

**Circular references:** The depth-1 limit prevents infinite resolution. Even if Action A references Action B and Action B references Action A, the skill only follows one level. References found at depth 1 are logged as unresolved, not followed.

**Job-level vs step-level `uses:`:** Job-level `uses:` (same indent level as `runs-on:`) indicates a reusable workflow call. Step-level `uses:` (inside a `steps:` array) indicates an action reference. The classification algorithm handles this distinction: reusable workflows are resolved as complete workflow files; composite actions are resolved via `action.yml`.
