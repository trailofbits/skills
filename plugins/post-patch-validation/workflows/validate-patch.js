export const meta = {
  name: 'validate-patch',
  description:
    'Build and execute an evidence plan for an existing security patch, then return findings, validation gaps, and independent coverage concerns',
  whenToUse:
    'Use after a security patch exists. Pass finding, baseRef, and patchRef or patchFile. The workflow runs local project code and cannot ask for missing input after launch.',
  phases: [
    { title: 'Inventory', detail: 'Pin the finding, baseline, patch, diff hash, and changed files' },
    { title: 'Coverage', detail: 'Map variants, behavior, adjacent security, and test infrastructure' },
    { title: 'Plan', detail: 'Create executable checks and pass the machine plan validator' },
    { title: 'Execute', detail: 'Run checks in isolated worktrees and record findings and gaps' },
    { title: 'Review', detail: 'Flag omitted paths or evidence that did not exercise real code' },
  ],
}

const INVENTORY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'planPath',
    'baseCommit',
    'patchSha256',
    'changedFiles',
    'evidenceLevel',
    'submodules',
    'findingSummary',
  ],
  properties: {
    planPath: { type: 'string' },
    baseCommit: { type: 'string' },
    patchedCommit: { type: ['string', 'null'] },
    patchSha256: { type: 'string' },
    changedFiles: { type: 'array', items: { type: 'string' } },
    evidenceLevel: { enum: ['source', 'build', 'runtime'] },
    submodules: { type: 'array', items: { type: 'string' } },
    findingSummary: { type: 'string' },
  },
}

const PROPOSAL_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['lens', 'observations', 'proposals'],
  properties: {
    lens: { type: 'string' },
    observations: { type: 'array', items: { type: 'string' } },
    proposals: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'kind', 'rationale', 'covers', 'strategy'],
        properties: {
          id: { type: 'string' },
          kind: {
            enum: ['control', 'exploit', 'variant', 'behavior', 'regression', 'security', 'suite'],
          },
          rationale: { type: 'string' },
          covers: { type: 'array', items: { type: 'string' } },
          strategy: { type: 'string' },
        },
      },
    },
  },
}

const PLAN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'complete',
    'planPath',
    'checkCount',
    'coverage',
    'evidenceLevel',
    'validationOutput',
  ],
  properties: {
    complete: { type: 'boolean' },
    planPath: { type: 'string' },
    checkCount: { type: 'integer' },
    coverage: {
      type: 'array',
      items: { enum: ['control', 'exploit', 'variant', 'behavior', 'regression', 'security', 'suite'] },
    },
    evidenceLevel: { enum: ['source', 'build', 'runtime'] },
    validationOutput: { type: 'string' },
    blocker: { type: 'string' },
    allowEnv: { type: 'array', items: { type: 'string' } },
  },
}

const ASSESSMENT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['status', 'findings', 'gaps', 'human_review_required'],
  properties: {
    status: { enum: ['complete', 'incomplete'] },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['check_id', 'kind', 'message'],
        properties: {
          check_id: { type: 'string' },
          kind: { enum: ['exploit', 'variant', 'behavior', 'regression', 'security', 'suite'] },
          message: { type: 'string' },
        },
      },
    },
    gaps: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['check_id', 'reason'],
        properties: {
          check_id: { type: ['string', 'null'] },
          reason: { type: 'string' },
        },
      },
    },
    human_review_required: { const: true },
  },
}

const EXECUTION_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['hasResult', 'evidenceVerified'],
  properties: {
    hasResult: { type: 'boolean' },
    evidenceVerified: { type: 'boolean' },
    blocker: { type: 'string' },
    resultPath: { type: 'string' },
    reportPath: { type: 'string' },
    assessment: ASSESSMENT_SCHEMA,
    evidenceLevel: { enum: ['source', 'build', 'runtime'] },
  },
}

const REVIEW_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['lens', 'approved', 'concerns', 'evidenceRead'],
  properties: {
    lens: { type: 'string' },
    approved: { type: 'boolean' },
    concerns: { type: 'array', items: { type: 'string' } },
    // A reviewer that read nothing cannot approve anything. Without minItems an agent could
    // return approved:true with empty arrays and approve a result having inspected no evidence.
    evidenceRead: { type: 'array', items: { type: 'string' }, minItems: 1 },
  },
}

function normalizeArgs(raw) {
  const trim = value => (typeof value === 'string' ? value.trim() : '')
  const source = typeof raw === 'string' ? { finding: raw } : raw && typeof raw === 'object' ? raw : {}
  const patchFile = trim(source.patchFile)
  const explicitPatchRef = trim(source.patchRef)
  return {
    finding: trim(source.finding),
    baseRef: trim(source.baseRef),
    patchRef: explicitPatchRef || (patchFile ? '' : 'HEAD'),
    patchFile,
    workdir: trim(source.workdir) || 'post-patch-validation',
  }
}

function argProblems(value) {
  const problems = []
  if (!value.finding) problems.push('finding')
  if (!value.baseRef) problems.push('baseRef')
  if (!value.patchRef && !value.patchFile) problems.push('patchRef or patchFile')
  if (value.patchRef && value.patchFile) problems.push('only one of patchRef or patchFile')
  if (
    value.workdir.startsWith('/') ||
    value.workdir.split('/').some(part => part === '..' || part === '')
  ) {
    problems.push('workdir (must be a non-empty relative path without ..)')
  }
  return problems
}

function finalStatus(assessment, reviews) {
  if (assessment.findings.length) return 'NEEDS_REPAIR'
  if (assessment.status !== 'complete' || assessment.gaps.length) return 'BLOCKED'
  if (!Array.isArray(reviews) || reviews.length !== 2) return 'REVIEW_REQUIRED'
  if (reviews.some(review => !review || !review.approved)) return 'REVIEW_REQUIRED'
  // Approval only counts when the reviewer names what it read. An empty evidenceRead is a
  // reviewer that rubber-stamped, which is indistinguishable from no review at all.
  if (reviews.some(review => !Array.isArray(review.evidenceRead) || !review.evidenceRead.length)) {
    return 'REVIEW_REQUIRED'
  }
  return 'READY_FOR_HUMAN_REVIEW'
}

const input = normalizeArgs(args)
const problems = argProblems(input)
if (problems.length) {
  log(`BLOCKED: missing or unsafe workflow input: ${problems.join(', ')}`)
  return {
    status: 'BLOCKED',
    humanReviewRequired: true,
    reason: `Supply structured args before launch: ${problems.join(', ')}`,
  }
}

phase('Inventory')

// Exact argv arrays for the two mechanical phases: the agent only replaces two placeholders and
// copies back what the script printed, so it runs on Haiku at low effort.
const inventoryArgv = [
  'uv', 'run', '{baseDir}/scripts/post_patch_validation.py', 'scaffold', '--repo', '.',
  '--base-ref', input.baseRef,
  ...(input.patchFile ? ['--patch-file', input.patchFile] : ['--patched-ref', input.patchRef]),
  '--finding-id', '<stable finding ID>', '--finding-summary', '<root cause and impact>',
  '--evidence-level', 'source', '--output', `${input.workdir}/plan.json`,
]

const inventory = await agent(
  `Load the post-patch-validation skill and perform only its scaffold step in the current Git
repository. This is a local validation; do not use the network and do not modify tracked project
files. Read the finding if it is a path, reduce it to one root-cause-and-impact sentence, and run
the bundled Python script. Run exactly this argv array after replacing the two angle-bracket
placeholders from the finding; do not use pipes, shell strings, or chained operators:

${JSON.stringify(inventoryArgv)}

The finding is: ${input.finding}

Use the finding's stable ID when one exists; otherwise use "patch-finding". Return the values
printed by scaffold.`,
  { schema: INVENTORY_SCHEMA, label: 'inventory', phase: 'Inventory', model: 'haiku', effort: 'low' },
)

if (!inventory) {
  return {
    status: 'BLOCKED',
    humanReviewRequired: true,
    reason: 'inventory agent returned no pinned plan',
  }
}

phase('Coverage')

const LENSES = [
  {
    key: 'root-cause',
    brief:
      'Trace the vulnerable invariant through every sibling caller and alternate entry/output path. Propose the original exploit assertion plus at least one meaningfully distinct root-cause variant. Include error and teardown paths when ownership or lifetime is involved.',
  },
  {
    key: 'behavior',
    brief:
      'Identify stable benign behavior that must remain byte-identical, plus targeted non-security regressions at the boundaries changed by the patch. Avoid outputs containing time, randomness, addresses, or unordered collections.',
  },
  {
    key: 'adjacent-security',
    brief:
      'Look specifically for a new vulnerability introduced by the patch: ownership, cleanup, authorization, bounds, concurrency, error handling, and state-transition regressions. Propose checks that should pass on both base and patch.',
  },
  {
    key: 'harness',
    brief:
      'Find the smallest deterministic project-native build/test command, sanitizer, or bounded fixed-seed fuzz corpus. Also propose a benign harness control that proves both worktrees can execute the relevant component.',
  },
]

const proposals = await parallel(
  LENSES.map(lens => () =>
    agent(
      `Read the finding, the pinned plan at ${inventory.planPath}, the changed-file names, and the
relevant ${input.baseRef}...${input.patchRef || 'patch'} hunks with git diff -U3. Read adjacent
source only when a hunk identifies it. Do not check either revision out over the user's working
tree. Work read-only.

Your coverage lens is ${lens.key}: ${lens.brief}

Return concrete check proposals for the post-patch-validation plan. Each proposal needs a stable
ID, one supported kind, a falsifiable rationale, the exact code path/invariant it covers, and an
implementation strategy. Do not claim a path is covered merely because the diff mentions it.
Do not write tests yet; the Plan phase owns all artifacts.`,
      { schema: PROPOSAL_SCHEMA, label: `coverage:${lens.key}`, phase: 'Coverage' },
    ),
  ),
)

if (proposals.length !== LENSES.length || proposals.some(value => !value)) {
  return {
    status: 'BLOCKED',
    humanReviewRequired: true,
    reason: 'one or more fixed coverage lenses returned no result',
  }
}

phase('Plan')

const planned = await agent(
  `Load the post-patch-validation skill. Turn the fixed-lens proposals below into a complete,
executable validation plan at ${inventory.planPath}. You may write helper test artifacts only
under ${input.workdir}/checks; do not edit tracked project files or the patch.

PROPOSALS
${JSON.stringify(proposals, null, 2)}

Run the bundled script's print-schema command before editing the plan. Use argv arrays and the
{checkout}, {plan_dir}, {scratch}, and {side} placeholders; never use shell command strings, pipes,
redirections, or chained commands, and write only under {scratch}. The {side} placeholder and
PPV_SIDE are unavailable to exploit and variant checks. Every helper must invoke real project code.
Sort checks by ID and supply every required kind. Exploit and variant safety
assertions must fail on the vulnerable base and pass on the patch, and each must print PPV_REACHED
flushed immediately before its assertion or that check leaves a validation gap. Security checks
must pass on both revisions. Behavior checks cover only contracts that should remain unchanged,
and their output must be stable enough for exact comparison. Suite checks run on the patch first.
If a suite completes and fails, the runner also runs it on baseline to assess attribution.

Replace the scaffolded source evidence_level with the highest level the completed checks honestly
support: keep source when only source or patch invariants run, use build when target code is
compiled or analyzed without executing the reported behavior, and use runtime only when the
exploit and variant checks execute the affected component. Return that value as evidenceLevel.
Exploit and variant assertions must
test only the security invariant; put liveness, exact error type, timing, and compatibility in
behavior or regression checks. Preserve the scaffolded submodules list unless another pinned
submodule is demonstrably required.

Checks run under a fixed minimal environment. If the project's toolchain needs host variables
beyond PATH and HOME, list their names in allowEnv rather than hardcoding host paths into the
plan. Never list a credential; the values are recorded in result.json.

Run validate-plan when done. If the evidence cannot honestly cover every required kind, do not
invent a check: return complete=false with the blocker and preserve the incomplete plan.`,
  { schema: PLAN_SCHEMA, label: 'plan', phase: 'Plan' },
)

if (!planned || !planned.complete) {
  return {
    status: 'BLOCKED',
    humanReviewRequired: true,
    reason: planned ? planned.blocker || planned.validationOutput : 'plan agent returned nothing',
    planPath: planned ? planned.planPath : inventory.planPath,
  }
}

phase('Execute')

const allowEnvArgv = (Array.isArray(planned.allowEnv) ? planned.allowEnv : [])
  .filter(name => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name))
  .flatMap(name => ['--allow-env', name])
const executionArgv = [
  'uv', 'run', '{baseDir}/scripts/post_patch_validation.py', 'run', '--plan', planned.planPath,
  '--output', `${input.workdir}/results`, ...allowEnvArgv,
]
const verifyArgv = [
  'uv', 'run', '{baseDir}/scripts/verify_evidence.py', '--results', `${input.workdir}/results`,
]

const execution = await agent(
  `Load the post-patch-validation skill. Run the evidence runner exactly once using this argv array;
then run the deterministic verifier using the second argv array. Do not use pipes, shell strings,
or chained operators:

runner: ${JSON.stringify(executionArgv)}
verifier: ${JSON.stringify(verifyArgv)}

The runner exits 0 for complete checks without findings, 1 for complete checks with findings,
10 for incomplete validation, and 64 for invalid inputs. An incomplete result can still contain
supported findings. A nonzero Bash result is not a reason to rerun it. Read result.json and return
hasResult=true with its exact assessment object, evidence level, and artifact paths. Preserve
every finding and gap. Set evidenceVerified=true only when the verifier exits 0. If the runner
produced no result artifact or the verifier failed, return hasResult=false with its error as blocker.
Do not invent an assessment for a run that did not produce one.
Do not edit the plan, patch, checks, or result.`,
  { schema: EXECUTION_SCHEMA, label: 'execute', phase: 'Execute', model: 'haiku', effort: 'low' },
)

if (
  !execution || !execution.hasResult || !execution.assessment ||
  !execution.resultPath || !execution.reportPath || !execution.evidenceLevel ||
  !execution.evidenceVerified
) {
  return {
    status: 'BLOCKED',
    humanReviewRequired: true,
    reason: execution?.blocker || 'execution agent returned no machine result',
    planPath: planned.planPath,
  }
}

phase('Review')

const REVIEW_LENSES = [
  {
    key: 'surface-completeness',
    brief:
      'Try to find a root-cause sibling, alternate entry/output path, error path, boundary, or teardown path omitted from the declared covers fields. Read the relevant source rather than trusting the plan summary.',
  },
  {
    key: 'evidence-integrity',
    brief:
      'Read result.json, patch.diff, plan.snapshot.json, the raw logs, and the relevant content-addressed helper artifacts referenced by argv_files (including scripts passed to interpreters, not only argv[0]). verify_evidence.py has already confirmed that archived bytes match the recorded hashes: judge only whether a helper is a mock, reimplements vulnerable logic, never invokes real project code, has empty output, prints the marker without exercising the vulnerable path, or does not support its declared check kind. A relevant helper whose argv_files record has no artifact is a concern.',
  },
]

const reviews = await parallel(
  REVIEW_LENSES.map(lens => () =>
    agent(
      `Review the completed post-patch evidence read-only under ${input.workdir}/results.

Your lens is ${lens.key}: ${lens.brief}

The runner assessment is ${JSON.stringify(execution.assessment)}. Preserve this recorded result.
Keep reviewer concerns separate from its findings and gaps. Set approved=false when the supplied
evidence is incomplete or invalid under your lens, list concrete
concerns with file/function/check IDs, and list every artifact you actually read. Missing evidence
is a concern, not consent. Do not run the validation again and do not edit artifacts.`,
      { schema: REVIEW_SCHEMA, label: `review:${lens.key}`, phase: 'Review' },
    ),
  ),
)

const status = finalStatus(execution.assessment, reviews)
return {
  status,
  assessment: execution.assessment,
  evidenceLevel: execution.evidenceLevel,
  humanReviewRequired: true,
  planPath: planned.planPath,
  resultPath: execution.resultPath,
  reportPath: execution.reportPath,
  reviews: reviews.filter(Boolean),
}
