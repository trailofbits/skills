export const meta = {
  name: 'git-cleanup-analysis',
  description:
    'Read-only triage of local git branches and worktrees: survey state, investigate ambiguous branches, then try to refute every delete candidate.',
  whenToUse:
    'Invoked by the git-cleanup skill before its first safety gate. Analysis only — it never deletes a branch or removes a worktree.',
  phases: [
    { title: 'Survey', detail: 'one agent inventories branches, worktrees, and merge history' },
    { title: 'Investigate', detail: 'batched agents hunt merge evidence for the ambiguous branches' },
    { title: 'Refute', detail: 'batched skeptics try to prove each delete candidate still holds unique work' },
  ],
}

// Branches that must never be analyzed, recommended, or deleted. Filtered here in
// JavaScript rather than in an agent prompt: an agent can be talked out of a rule,
// a regex cannot.
const PROTECTED = /^(main|master|develop|release\/.*)$/

// Verdicts that put a branch on the deletion list, and therefore must survive a
// refutation pass before the user ever sees them.
const DELETE_CATEGORIES = new Set(['SAFE_TO_DELETE', 'SQUASH_MERGED', 'SUPERSEDED'])

// Agent-count bounds. Past MAX_* batches we grow the batch, not the fleet, so a repo
// with 200 stale branches costs the same number of agents as one with 20.
const MIN_UNITS_PER_BATCH = 3
const MAX_INVESTIGATORS = 5

const repoPath = (args && args.repoPath) || '.'
const pluginDir = (args && args.pluginDir) || ''

const evidenceRef = pluginDir
  ? `Read ${pluginDir}/references/merge-evidence.md first — it defines the evidence standard for every category, and the commands that produce that evidence.`
  : 'Evidence standard: a branch counts as merged only when you can name the commit or PR in the default branch that carries its work.'

const READ_ONLY = [
  'HARD CONSTRAINT: you are read-only. Run only git commands that inspect state',
  '(log, branch --list, rev-list, show, status, merge-base, cherry, worktree list).',
  'Never run branch -d/-D, worktree remove, push, reset, checkout, rebase, or gc.',
  'A deletion decision belongs to the user, who has not been asked yet.',
].join(' ')

const SURVEY_SCHEMA = {
  type: 'object',
  required: ['defaultBranch', 'currentBranch', 'branches', 'worktrees', 'mergeLog'],
  additionalProperties: false,
  properties: {
    defaultBranch: { type: 'string' },
    currentBranch: { type: 'string' },
    branches: {
      type: 'array',
      items: {
        type: 'object',
        required: [
          'name',
          'merged',
          'tracking',
          'remoteGone',
          'unpushedCommits',
          'uniqueCommits',
          'lastCommit',
        ],
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          merged: { type: 'boolean', description: 'listed by git branch --merged <default>' },
          tracking: { type: 'string', description: 'upstream ref, or "" when untracked' },
          remoteGone: { type: 'boolean', description: 'git branch -vv marks it [gone]' },
          unpushedCommits: {
            type: 'integer',
            description: 'count of git log <upstream>..<branch>; -1 when untracked',
          },
          uniqueCommits: { type: 'integer', description: 'count of git log <default>..<branch>' },
          lastCommit: { type: 'string', description: 'short sha and subject' },
          worktreePath: { type: 'string', description: 'checkout path, or "" when none' },
        },
      },
    },
    worktrees: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'branch', 'dirty', 'dirtyFiles'],
        additionalProperties: false,
        properties: {
          path: { type: 'string' },
          branch: { type: 'string' },
          dirty: { type: 'boolean' },
          dirtyFiles: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    mergeLog: {
      type: 'array',
      description: 'recent default-branch subjects carrying a PR number, newest first',
      items: { type: 'string' },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['verdicts'],
  additionalProperties: false,
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['branch', 'category', 'evidence'],
        additionalProperties: false,
        properties: {
          branch: { type: 'string' },
          category: {
            type: 'string',
            enum: ['SQUASH_MERGED', 'SUPERSEDED', 'REMOTE_GONE', 'LOCAL_WORK'],
          },
          evidence: {
            type: 'string',
            description:
              'the specific PR number, commit sha, or superseding branch that justifies the category; "none found" when there is none',
          },
          group: { type: 'string', description: 'shared prefix when part of a related group, else ""' },
        },
      },
    },
  },
}

const REFUTE_SCHEMA = {
  type: 'object',
  required: ['refutations'],
  additionalProperties: false,
  properties: {
    refutations: {
      type: 'array',
      items: {
        type: 'object',
        required: ['branch', 'refuted', 'reason'],
        additionalProperties: false,
        properties: {
          branch: { type: 'string' },
          refuted: {
            type: 'boolean',
            description: 'true when the branch still holds work you cannot find in the default branch',
          },
          reason: { type: 'string', description: 'the commit you could not account for, or why the claim holds' },
        },
      },
    },
  },
}

// ---------------------------------------------------------------- phase 1: survey

phase('Survey')

const survey = await agent(
  [
    `Inventory the local git state of the repository at ${repoPath}. ${READ_ONLY}`,
    '',
    'Run, in order:',
    '  git -C REPO fetch --prune            # sync remote-deleted state (network only, no writes to refs you own)',
    '  git -C REPO symbolic-ref refs/remotes/origin/HEAD   # default branch; fall back to main',
    '  git -C REPO branch -vv               # tracking info, [gone] markers',
    '  git -C REPO branch --merged DEFAULT  # branches git can already prove are merged',
    '  git -C REPO worktree list --porcelain',
    '  git -C REPO log --oneline DEFAULT | grep -iE "#[0-9]+" | head -40',
    '',
    'Then for every local branch, quote the name and collect:',
    '  git -C REPO log --oneline "DEFAULT..BRANCH" | wc -l      -> uniqueCommits',
    '  git -C REPO log --oneline "UPSTREAM..BRANCH" | wc -l     -> unpushedCommits (-1 if untracked)',
    'and for every worktree, using the ABSOLUTE path `git worktree list --porcelain`',
    'printed for it — do not build a path relative to the repo, the two are unrelated:',
    '  git -C "<that absolute worktree path>" status --porcelain  -> dirty, dirtyFiles',
    '',
    'If a worktree status command fails for any reason, report dirty=true with',
    'dirtyFiles=["status could not be read"]. Never report dirty=false for a worktree you',
    'did not successfully inspect: dirty=false authorizes removing it, and the changes go',
    'with it. "Could not check" and "clean" are different answers.',
    '',
    'Branch names can contain characters that break shell expansion — always quote them.',
    'Report every local branch including main/master/develop; the caller filters protected names itself.',
    'Report counts you actually measured. Never estimate a commit count.',
  ].join('\n'),
  { label: 'survey', schema: SURVEY_SCHEMA },
)

if (!survey) throw new Error('survey agent failed; no analysis is possible')

// A repository always has at least the checked-out branch. Zero means the survey
// failed to read anything, which must not be reported as "nothing to clean up".
if (!survey.branches || survey.branches.length === 0) {
  throw new Error('survey returned zero local branches — the inventory failed rather than finding a clean repo')
}

// The default branch is protected whatever it is called: `git branch --merged trunk`
// lists `trunk` itself, so a repo not using one of the conventional names would
// otherwise see its own trunk recommended for deletion.
const isProtected = (name) =>
  PROTECTED.test(name) || name === survey.defaultBranch || name === survey.currentBranch

const branches = survey.branches.filter((b) => !isProtected(b.name))
log(
  `${survey.branches.length} local branches; ${survey.branches.length - branches.length} protected or checked out, ${branches.length} in scope`,
)

// ------------------------------------------------------- deterministic triage

// Two branches are iterations of one effort when they share at least two leading name
// segments: feature/api, feature/api-v2 and feature/api-refactor cluster, and
// feature/login does not join them merely by starting "feature".
//
// Two segments is the floor precisely because clustering is transitive. A one-segment
// match would make a branch named `feature` related to every feature/* branch at once,
// bridging them into a single cluster and handing unrelated local-only work to an agent
// told they are iterations of one effort. Single-segment names therefore never cluster —
// they settle as LOCAL_WORK, which is the safe direction. Branch names are
// attacker-influenced in any repo that fetches contributor branches, so this floor is a
// safety property, not a tuning constant.
const segments = (name) => name.split(/[-/]/).filter(Boolean)

function related(a, b) {
  const sa = segments(a)
  const sb = segments(b)
  let shared = 0
  while (shared < sa.length && shared < sb.length && sa[shared] === sb[shared]) shared++
  return shared >= 2
}

// Clustering is transitive: a branch related to any member joins that cluster, and a
// branch bridging two clusters merges them.
const clusters = []
for (const b of branches) {
  const hits = clusters.filter((c) => c.some((o) => related(o.name, b.name)))
  for (const h of hits) clusters.splice(clusters.indexOf(h), 1)
  clusters.push([...hits.flat(), b])
}
const inGroup = new Set(clusters.filter((c) => c.length > 1).flatMap((c) => c.map((b) => b.name)))

const settled = []
const ambiguous = []

for (const b of branches) {
  if (b.merged) {
    // Reported by the survey agent as listed in `git branch --merged`. This is the one
    // delete category that skips investigation and refutation, so it is NOT independently
    // verified here — `git branch -d` re-derives the merge and refuses if it is wrong,
    // which is why this category is pinned to `-d` and never to `-D`.
    settled.push({
      ...b,
      category: 'SAFE_TO_DELETE',
      evidence: `reported merged into ${survey.defaultBranch}; git branch -d re-checks`,
      command: 'git branch -d',
    })
  } else if (b.unpushedCommits > 0) {
    settled.push({ ...b, category: 'UNPUSHED_WORK', evidence: `${b.unpushedCommits} commits not on ${b.tracking}` })
  } else if (b.remoteGone) {
    ambiguous.push(b) // remote deleted: work is either squash-merged or abandoned
  } else if (b.tracking) {
    settled.push({ ...b, category: 'SYNCED_WITH_REMOTE', evidence: `up to date with ${b.tracking}` })
  } else if (inGroup.has(b.name)) {
    ambiguous.push(b) // untracked, but a sibling branch may have superseded it
  } else {
    settled.push({ ...b, category: 'LOCAL_WORK', evidence: `${b.uniqueCommits} commits, no remote` })
  }
}

log(`triage: ${settled.length} decided from git state, ${ambiguous.length} need investigation`)

if (ambiguous.length === 0) {
  log('no ambiguous branches — skipping the investigate and refute phases')
  return report(settled, [])
}

// ------------------------------------------------- batching (bounded fleet size)

// Clustered branches travel together: supersession is only visible when one agent sees
// the whole cluster at once. `context` carries the siblings that triage already settled —
// usually the newer, still-tracked branch that superseded the others. Withholding them
// would ask the agent to name the superseding branch while hiding it. They are shown to
// the agent but no verdict is accepted for them.
const pending = new Set(ambiguous.map((b) => b.name))
const units = clusters
  .map((c) => ({
    decide: c.filter((b) => pending.has(b.name)),
    context: c.filter((b) => !pending.has(b.name)),
  }))
  .filter((u) => u.decide.length > 0)

const batchCount = Math.min(MAX_INVESTIGATORS, Math.max(1, Math.ceil(units.length / MIN_UNITS_PER_BATCH)))
const sized = Array.from({ length: batchCount }, () => [])
units.forEach((u, i) => sized[i % batchCount].push(u))
// Indices into `batches` are reused below to attribute a failed agent back to the
// branches it was carrying, so drop the empties here rather than mid-pipeline.
const batches = sized.filter((b) => b.length > 0)

log(`${units.length} units (${ambiguous.length} branches) across ${batches.length} investigators`)

// ------------------------------------ phases 2 & 3: investigate, then try to refute

const context = [
  `Default branch: ${survey.defaultBranch}.`,
  `Recent ${survey.defaultBranch} merge subjects:`,
  ...survey.mergeLog.slice(0, 40).map((s) => `  ${s}`),
].join('\n')

const results = await pipeline(
  batches,
  (batch, _orig, i) =>
    agent(
      [
        `Investigate whether the work on these local branches of ${repoPath} already lives in ${survey.defaultBranch}. ${READ_ONLY}`,
        '',
        evidenceRef,
        '',
        context,
        '',
        'Branches, grouped — branches in the same group share a name prefix and are likely iterations of one effort:',
        ...batch.map((unit, n) => {
          const line = (b) =>
            `  - ${b.name} | ${b.uniqueCommits} commits not in ${survey.defaultBranch} | ` +
            `${b.remoteGone ? 'remote deleted' : b.tracking || 'untracked'} | last: ${b.lastCommit}`
          const ctx = unit.context.length
            ? `\n  Context only — already settled, do NOT return a verdict for these; they are the\n  candidates for "a named newer branch that contains all of its commits":\n` +
              unit.context.map(line).join('\n')
            : ''
          return `Group ${n + 1}:\n` + unit.decide.map(line).join('\n') + ctx
        }),
        '',
        'For each branch return exactly one category:',
        '  SQUASH_MERGED — you found the specific commit or PR in the default branch that carries this work',
        '  SUPERSEDED    — a named PR merged it, or a named newer branch contains all of its commits',
        '  REMOTE_GONE   — the remote is gone but you could not find the work in the default branch',
        '  LOCAL_WORK    — the branch holds commits that exist nowhere else',
        '',
        'A shared name prefix is not evidence of supersession. Two branches named alike can hold',
        'unrelated work. Cite a PR number, a commit sha, or a superseding branch, or use REMOTE_GONE.',
        'When you cannot find the work, say so — REMOTE_GONE is the correct answer, not a failure.',
      ].join('\n'),
      { label: `investigate:${i + 1}`, phase: 'Investigate', schema: VERDICT_SCHEMA },
    ),
  (result, _batch, i) => {
    if (!result) return null
    const candidates = result.verdicts.filter((v) => DELETE_CATEGORIES.has(v.category))
    if (candidates.length === 0) return { verdicts: result.verdicts, refutations: [] }
    return agent(
      [
        `Try to REFUTE these claims about branches in ${repoPath}. ${READ_ONLY}`,
        '',
        evidenceRef,
        '',
        'Each claim says a branch can be deleted because its work is already in',
        `${survey.defaultBranch}. Your job is to find the counterexample: a commit on the branch`,
        'whose content you cannot locate in the default branch. `git cherry -v` and',
        '`git log --cherry-pick --right-only` find work that survived a squash or rebase.',
        '',
        ...candidates.map((v) => `  - ${v.branch}: claimed ${v.category} because "${v.evidence}"`),
        '',
        'Set refuted=true when any commit is unaccounted for, and name that commit.',
        'A refuted branch is not deleted, so a wrong "refuted" costs the user a second look',
        'while a wrong "confirmed" costs them their work. Default to refuted=true when unsure.',
      ].join('\n'),
      { label: `refute:${i + 1}`, phase: 'Refute', schema: REFUTE_SCHEMA },
    ).then((r) => ({ verdicts: result.verdicts, refutations: r ? r.refutations : null }))
  },
)

// ------------------------------------------------------------------- assemble

const investigated = []
const dropped = []

// A refutation counts as refuting unless it says `refuted: false` outright. An omitted
// or malformed field is not a clearance — this gate has to fail closed, because a wrong
// "confirmed" costs the user work that exists nowhere else.
const isRefuted = (x) => x.refuted !== false

results.forEach((r, i) => {
  const batchBranches = new Map(batches[i].flatMap((u) => u.decide).map((b) => [b.name, b]))
  if (!r) {
    dropped.push(...batchBranches.keys())
    return
  }
  // A refutation agent that died leaves its batch unverified. Unverified is not
  // confirmed: those branches fall back to needing a human look.
  const unverified = r.refutations === null

  // Duplicate refutations for one branch resolve toward refusal, never toward deletion:
  // a plain Map build would let a trailing `refuted: false` erase a named counterexample.
  const byBranch = new Map()
  for (const x of r.refutations || []) {
    const prev = byBranch.get(x.branch)
    if (!prev || (isRefuted(x) && !isRefuted(prev))) byBranch.set(x.branch, x)
  }

  const seen = new Set()
  for (const v of r.verdicts) {
    // Scoped to this agent's own batch: a verdict naming another investigator's branch is
    // not a decision this agent was asked to make, and accepting it would let one branch
    // land in two buckets at once.
    const source = batchBranches.get(v.branch)
    if (!source) continue // agent named a branch that was not in its batch
    if (seen.has(v.branch)) continue // first verdict wins; a repeat cannot add a candidate
    seen.add(v.branch)
    const refutation = byBranch.get(v.branch)
    const isCandidate = DELETE_CATEGORIES.has(v.category)

    if (isCandidate && (unverified || !refutation || isRefuted(refutation))) {
      investigated.push({
        ...source,
        category: 'REMOTE_GONE',
        evidence: unverified
          ? `claimed ${v.category} (${v.evidence}) but verification did not complete`
          : refutation
            ? `claimed ${v.category}, refuted: ${refutation.reason}`
            : `claimed ${v.category} (${v.evidence}) but was never verified`,
        group: v.group || '',
      })
    } else {
      investigated.push({
        ...source,
        category: v.category,
        evidence: isCandidate ? `${v.evidence} (verified: ${refutation.reason})` : v.evidence,
        command: isCandidate ? 'git branch -D' : undefined,
        group: v.group || '',
      })
    }
  }
})

if (dropped.length > 0) {
  log(`NOT ANALYZED — ${dropped.length} branches lost to agent failure: ${dropped.join(', ')}`)
}

const missing = ambiguous
  .filter((b) => !investigated.some((v) => v.name === b.name) && !dropped.includes(b.name))
  .map((b) => b.name)
if (missing.length > 0) log(`NOT ANALYZED — no verdict returned for: ${missing.join(', ')}`)

return report(settled, investigated, [...dropped, ...missing])

// -------------------------------------------------------------------- reporting

// `git worktree list --porcelain` reports `refs/heads/<name>` while `git branch -vv`
// reports the short name. Both reach this script through the survey, so normalize before
// comparing or a worktree never matches its own branch. Declared as a function, not a
// const: `report()` is called from the early return above, where a const is still in TDZ.
function shortRef(ref) {
  return String(ref || '').replace(/^refs\/heads\//, '')
}

function report(decided, checked, unanalyzed = []) {
  const all = [...decided, ...checked]
  const pick = (...cats) => all.filter((b) => cats.includes(b.category))

  // SQUASH_MERGED and SUPERSEDED entries survived a refutation attempt. SAFE_TO_DELETE
  // did not: it rests on the survey's `merged` flag and on `git branch -d` refusing at
  // execution time if that flag was wrong.
  const deleteCandidates = pick('SAFE_TO_DELETE', 'SQUASH_MERGED', 'SUPERSEDED').map((b) => ({
    branch: b.name,
    category: b.category,
    evidence: b.evidence,
    // Never default to force-delete. A candidate that reached here without an explicit
    // command is a bug, and `-d` fails safe where `-D` would not.
    command: b.command || 'git branch -d',
    group: b.group || '',
    worktreePath: b.worktreePath || '',
  }))
  const deletable = new Set(deleteCandidates.map((c) => c.branch))

  return {
    defaultBranch: survey.defaultBranch,
    currentBranch: survey.currentBranch,
    // Presented at gate 1 as the recommended deletions.
    deleteCandidates,
    needsReview: pick('REMOTE_GONE').map((b) => ({
      branch: b.name,
      evidence: b.evidence,
      lastCommit: b.lastCommit,
      uniqueCommits: b.uniqueCommits,
    })),
    keep: pick('UNPUSHED_WORK', 'LOCAL_WORK', 'SYNCED_WITH_REMOTE').map((b) => ({
      branch: b.name,
      category: b.category,
      evidence: b.evidence,
    })),
    worktrees: survey.worktrees.map((w) => ({
      ...w,
      branch: shortRef(w.branch),
      // A worktree holding uncommitted changes is never stale, whatever its branch's
      // category: `git worktree remove` would take those changes with it, and this is the
      // one place that has the dirty flag in hand.
      stale: !w.dirty && deletable.has(shortRef(w.branch)),
    })),
    // Branches the analysis could not decide. The caller must surface this list rather
    // than let a partial run read as a complete one.
    unanalyzed,
  }
}
