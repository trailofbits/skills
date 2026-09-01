// Exercises the deterministic core of analyze-branches.js — triage, clustering,
// batching, and result assembly — with every agent stubbed. Run: node <this file>
//
// The safety-critical assertions are the negative ones: a refuted candidate, an
// unverified candidate, and a branch lost to a dead agent must all fail to reach
// deleteCandidates. A run that asserts nothing is a failing run, so the counter at
// the bottom fails the process when fewer assertions execute than are written.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, '..', 'workflows', 'analyze-branches.js'), 'utf8').replace(
  'export const meta',
  'const meta',
)

const AsyncFn = Object.getPrototypeOf(async () => {}).constructor

async function run({ survey, investigate, refute }) {
  const logs = []
  const labels = []
  const prompts = []
  const fn = new AsyncFn('agent', 'pipeline', 'phase', 'log', 'args', src)
  const out = await fn(
    async (prompt, opts) => {
      labels.push(opts.label)
      if (opts.label === 'survey') return survey
      if (opts.label.startsWith('investigate')) { prompts.push(prompt); return investigate(prompt, opts) }
      return refute(prompt, opts)
    },
    async (items, ...stages) =>
      Promise.all(
        items.map(async (item, i) => {
          let v = item
          for (const s of stages) {
            try {
              v = await s(v, item, i)
            } catch {
              return null
            }
          }
          return v
        }),
      ),
    () => {},
    (m) => logs.push(m),
    { repoPath: '/repo', pluginDir: '/plugin' },
  )
  return { out, logs, labels, prompts }
}

const b = (name, o = {}) => ({
  name,
  merged: false,
  tracking: '',
  remoteGone: false,
  unpushedCommits: -1,
  uniqueCommits: 3,
  lastCommit: 'abc1234 wip',
  worktreePath: '',
  ...o,
})

const survey = {
  defaultBranch: 'main',
  currentBranch: 'main',
  mergeLog: ['aaa1111 Add API (#29)', 'bbb2222 API v2 (#45)'],
  worktrees: [{ path: '/wt/auth', branch: 'feature/auth', dirty: true, dirtyFiles: ['M src/a.js'] }],
  branches: [
    b('main'),
    b('master'),
    b('release/1.0'),
    b('develop'),
    b('fix/typo', { merged: true, tracking: 'origin/fix/typo' }),
    b('wip/thing', { tracking: 'origin/wip/thing', unpushedCommits: 5 }),
    b('synced/thing', { tracking: 'origin/synced/thing', unpushedCommits: 0 }),
    b('solo/local'),
    b('feature/login', { remoteGone: true, tracking: 'origin/feature/login', unpushedCommits: 0 }),
    b('experiment/old', { remoteGone: true, tracking: 'origin/experiment/old', unpushedCommits: 0 }),
    b('feature/api'),
    b('feature/api-v2'),
    b('feature/api-refactor'),
  ],
}

// Bump when you add an assertion. The check at the bottom is what makes a suite that
// silently stopped running most of itself fail instead of reporting a pass.
const EXPECTED_ASSERTIONS = 61
let ran = 0
let failures = 0

const assert = (label, cond, extra = '') => {
  ran++
  if (!cond) failures++
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : '  <<< ' + extra}`)
  if (!cond) process.exitCode = 1
}

// ---- case 1: happy path, refuter confirms everything except experiment/old
{
  const verdictFor = (name) =>
    name === 'experiment/old'
      ? { branch: name, category: 'REMOTE_GONE', evidence: 'none found', group: '' }
      : name === 'feature/login'
        ? { branch: name, category: 'SQUASH_MERGED', evidence: 'PR #42', group: '' }
        : { branch: name, category: 'SUPERSEDED', evidence: 'PR #29', group: 'feature/api' }

  const { out, logs, prompts } = await run({
    survey,
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => verdictFor(m[1])),
    }),
    refute: (p) => ({
      refutations: [...p.matchAll(/^ {2}- (\S+): claimed/gm)].map((m) => ({
        branch: m[1],
        refuted: false,
        reason: 'all commits accounted for',
      })),
    }),
  })

  const names = (l) => l.map((x) => x.branch).sort()
  // Excluded from ANALYSIS, not from the report: a protected branch must never be a
  // delete candidate and must never be silently absent either.
  assert(
    'protected branches are excluded from every delete path',
    !out.deleteCandidates.some((c) => c.branch === 'release/1.0') &&
      !out.needsReview.some((c) => c.branch === 'release/1.0'),
    JSON.stringify(names(out.deleteCandidates)),
  )
  assert(
    'protected branches are still reported, under keep/PROTECTED',
    out.keep.some((k) => k.branch === 'release/1.0' && k.category === 'PROTECTED'),
    JSON.stringify(out.keep.filter((k) => k.category === 'PROTECTED')),
  )
  assert(
    'delete candidates',
    JSON.stringify(names(out.deleteCandidates)) ===
      JSON.stringify(['feature/api', 'feature/api-refactor', 'feature/api-v2', 'feature/login', 'fix/typo']),
    JSON.stringify(names(out.deleteCandidates)),
  )
  assert(
    'merged branch uses -d, squash uses -D',
    out.deleteCandidates.find((c) => c.branch === 'fix/typo').command === 'git branch -d' &&
      out.deleteCandidates.find((c) => c.branch === 'feature/login').command === 'git branch -D',
  )
  assert('needsReview', JSON.stringify(names(out.needsReview)) === JSON.stringify(['experiment/old']))
  assert(
    'keep, analyzed entries',
    JSON.stringify(names(out.keep.filter((k) => k.category !== 'PROTECTED'))) ===
      JSON.stringify(['solo/local', 'synced/thing', 'wip/thing']),
    JSON.stringify(names(out.keep)),
  )
  assert(
    'keep, protected entries',
    JSON.stringify(names(out.keep.filter((k) => k.category === 'PROTECTED'))) ===
      JSON.stringify(['develop', 'main', 'master', 'release/1.0']),
    JSON.stringify(names(out.keep.filter((k) => k.category === 'PROTECTED'))),
  )
  assert('dirty worktree preserved', out.worktrees[0].dirty === true)
  assert('nothing unanalyzed', out.unanalyzed.length === 0, JSON.stringify(out.unanalyzed))
  assert(
    'three units: two singletons plus the api cluster',
    logs.some((l) => l.includes('3 units (5 branches)')),
    JSON.stringify(logs),
  )
  const groupsOf = (p) =>
    p.split(/^Group \d+:$/m).slice(1).map((g) => [...g.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => m[1]))
  const allGroups = prompts.flatMap(groupsOf)
  assert(
    'api iterations share one unit',
    allGroups.some(
      (g) =>
        g.length === 3 &&
        ['feature/api', 'feature/api-v2', 'feature/api-refactor'].every((n) => g.includes(n)),
    ),
    JSON.stringify(allGroups),
  )
  assert(
    'feature/login is not clustered with feature/api',
    !allGroups.some((g) => g.includes('feature/login') && g.includes('feature/api')),
    JSON.stringify(allGroups),
  )
}

// ---- case 2: refuter refutes -> candidate must be downgraded, never deleted
{
  const { out } = await run({
    survey,
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => ({
        branch: m[1],
        category: 'SQUASH_MERGED',
        evidence: 'PR #42',
        group: '',
      })),
    }),
    refute: (p) => ({
      refutations: [...p.matchAll(/^ {2}- (\S+): claimed/gm)].map((m) => ({
        branch: m[1],
        refuted: true,
        reason: 'commit def5678 not found in main',
      })),
    }),
  })
  assert(
    'refuted candidates are not deletable',
    out.deleteCandidates.every((c) => c.category === 'SAFE_TO_DELETE'),
    JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
  )
  assert('refuted land in needsReview', out.needsReview.length === 5, String(out.needsReview.length))
  assert(
    'refutation reason surfaced',
    out.needsReview.every((r) => r.evidence.includes('def5678')),
  )
}

// ---- case 3: refuter dies -> unverified, must not be deletable
{
  const { out } = await run({
    survey,
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => ({
        branch: m[1],
        category: 'SQUASH_MERGED',
        evidence: 'PR #42',
        group: '',
      })),
    }),
    refute: () => null,
  })
  assert(
    'unverified candidates are not deletable',
    out.deleteCandidates.every((c) => c.category === 'SAFE_TO_DELETE'),
  )
  // Anchor the count first. `[].every(...)` is true, so without this the case also passes
  // when the branches are dropped from the report entirely instead of downgraded — the
  // failure it exists to catch.
  assert('unverified branches all land in needsReview', out.needsReview.length === 5, String(out.needsReview.length))
  assert(
    'unverified is explained',
    out.needsReview.length > 0 &&
      out.needsReview.every((r) => r.evidence.includes('verification did not complete')),
  )
}

// ---- case 3b: refutation object omitting `refuted` must fail closed, not read as clear
{
  const { out } = await run({
    survey,
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => ({
        branch: m[1],
        category: 'SQUASH_MERGED',
        evidence: 'PR #42',
        group: '',
      })),
    }),
    refute: (p) => ({
      refutations: [...p.matchAll(/^ {2}- (\S+): claimed/gm)].map((m) => ({
        branch: m[1],
        reason: 'checked',
      })),
    }),
  })
  assert(
    'missing `refuted` field is treated as refuted',
    out.deleteCandidates.every((c) => c.category === 'SAFE_TO_DELETE'),
    JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
  )
  assert('fail-closed branches reach needsReview', out.needsReview.length === 5, String(out.needsReview.length))
}

// ---- case 3c: duplicate refutations resolve toward refusal, not toward deletion
{
  const { out } = await run({
    survey,
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => ({
        branch: m[1],
        category: 'SQUASH_MERGED',
        evidence: 'PR #42',
        group: '',
      })),
    }),
    refute: (p) =>
      [...p.matchAll(/^ {2}- (\S+): claimed/gm)]
        .map((m) => m[1])
        .reduce(
          (acc, br) => {
            acc.refutations.push({ branch: br, refuted: true, reason: 'commit def5678 MISSING from main' })
            acc.refutations.push({ branch: br, refuted: false, reason: 'second look, fine' })
            return acc
          },
          { refutations: [] },
        ),
  })
  assert(
    'a trailing refuted:false cannot erase a refutation',
    out.deleteCandidates.every((c) => c.category === 'SAFE_TO_DELETE'),
    JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
  )
  assert(
    'the named counterexample reaches the user',
    out.needsReview.length === 5 && out.needsReview.every((r) => r.evidence.includes('def5678')),
    JSON.stringify(out.needsReview.map((r) => r.evidence)),
  )
}

// ---- case 4: investigator dies -> branches reported as unanalyzed, not silently gone
{
  const { out, logs } = await run({ survey, investigate: () => null, refute: () => null })
  assert(
    'lost branches are listed as unanalyzed',
    out.unanalyzed.length === 5,
    JSON.stringify(out.unanalyzed),
  )
  assert(
    'loss is logged loudly',
    logs.some((l) => l.startsWith('NOT ANALYZED')),
    JSON.stringify(logs),
  )
  assert('lost branches are not delete candidates', out.deleteCandidates.length === 1)
}

// ---- case 5: empty survey must throw, not report a clean repo
{
  try {
    await run({ survey: { ...survey, branches: [] }, investigate: () => null, refute: () => null })
    assert('empty survey throws', false, 'no throw')
  } catch (e) {
    assert('empty survey throws', /zero local branches/.test(e.message), e.message)
  }
}

// ---- case 6: clean repo (only protected branches) returns empty, spawns no investigators
{
  const { out, labels, logs } = await run({
    survey: { ...survey, branches: [b('main'), b('develop'), b('fix/typo', { merged: true })] },
    investigate: () => null,
    refute: () => null,
  })
  assert('no investigators spawned', labels.length === 1, JSON.stringify(labels))
  assert('merged branch still reported', out.deleteCandidates.length === 1)
  assert(
    'skip is logged',
    logs.some((l) => l.includes('no ambiguous branches')),
  )
}

// ---- case 7: the default branch is protected whatever it is named
{
  const { out } = await run({
    survey: {
      ...survey,
      defaultBranch: 'trunk',
      currentBranch: 'feature/wip',
      branches: [b('trunk', { merged: true }), b('feature/wip'), b('fix/typo', { merged: true })],
    },
    investigate: () => null,
    refute: () => null,
  })
  const listed = [...out.deleteCandidates, ...out.needsReview, ...out.keep].map((x) => x.branch)
  assert(
    'default branch named trunk is never a delete candidate',
    !out.deleteCandidates.some((c) => c.branch === 'trunk') &&
      !out.needsReview.some((c) => c.branch === 'trunk') &&
      !out.unanalyzed.includes('trunk'),
    JSON.stringify(listed),
  )
  assert(
    'the default branch is reported as protected rather than omitted',
    out.keep.some((k) => k.branch === 'trunk' && k.category === 'PROTECTED'),
    JSON.stringify(out.keep),
  )
  assert('other merged branches still reported', out.deleteCandidates.length === 1)
}

// ---- case 7b: a fully qualified defaultBranch still protects the trunk
// `git symbolic-ref refs/remotes/origin/HEAD` prints `refs/remotes/origin/mainline`, not
// `mainline`. Before normalization the name comparison missed and the repo's own default
// branch reached deleteCandidates with a verifyWith that returns 0.
{
  for (const reported of ['refs/remotes/origin/mainline', 'origin/mainline', 'mainline']) {
    const { out } = await run({
      survey: {
        ...survey,
        defaultBranch: reported,
        currentBranch: 'refs/heads/feature/wip',
        branches: [b('mainline', { merged: true }), b('feature/wip'), b('fix/typo', { merged: true })],
      },
      investigate: () => null,
      refute: () => null,
    })
    assert(
      `defaultBranch reported as "${reported}" protects the trunk`,
      !out.deleteCandidates.some((c) => c.branch === 'mainline') &&
        out.keep.some((k) => k.branch === 'mainline' && k.category === 'PROTECTED'),
      JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
    )
    assert(
      `verifyWith names the short default for "${reported}"`,
      out.deleteCandidates[0].verifyWith === "git merge-base --is-ancestor 'refs/heads/fix/typo' 'mainline'",
      JSON.stringify(out.deleteCandidates[0].verifyWith),
    )
  }
  const { out } = await run({
    survey: {
      ...survey,
      defaultBranch: 'main',
      currentBranch: 'refs/heads/feature/wip',
      branches: [b('main'), b('feature/wip', { merged: true }), b('fix/typo', { merged: true })],
    },
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'a fully qualified currentBranch is still recognized as checked out',
    !out.deleteCandidates.some((c) => c.branch === 'feature/wip') &&
      out.keep.some((k) => k.branch === 'feature/wip' && k.category === 'PROTECTED'),
    JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
  )
}

// ---- case 7c: a protected branch carrying unpushed work is reported, not swallowed
// It used to land in no output array at all, so Safety Rule 7 had nothing to fire on.
{
  const { out, logs } = await run({
    survey: {
      ...survey,
      branches: [
        b('main'),
        b('staging', { tracking: 'origin/staging', unpushedCommits: 7 }),
        b('fix/typo', { merged: true }),
      ],
    },
    investigate: () => null,
    refute: () => null,
  })
  const entry = out.keep.find((k) => k.branch === 'staging')
  assert(
    'a protected branch with unpushed work appears in keep',
    entry !== undefined && entry.category === 'PROTECTED',
    JSON.stringify(out.keep),
  )
  assert(
    'its evidence names the unpushed count',
    entry.evidence.includes('7 commits not on origin/staging'),
    JSON.stringify(entry.evidence),
  )
  assert(
    'unpushed work on a protected branch is logged',
    logs.some((l) => l.includes('unpushed commits: staging')),
    JSON.stringify(logs),
  )
}

// ---- case 7d: the trimmed names are analyzable again
{
  const { out } = await run({
    survey: {
      ...survey,
      branches: [b('main'), b('test', { merged: true }), b('demo', { merged: true }), b('sandbox', { merged: true })],
    },
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'test/demo/sandbox are no longer force-protected',
    JSON.stringify(out.deleteCandidates.map((c) => c.branch).sort()) === JSON.stringify(['demo', 'sandbox', 'test']),
    JSON.stringify(out.deleteCandidates.map((c) => c.branch)),
  )
}

// ---- case 8: a verdict for another investigator's branch is rejected
{
  const gone = (n) => b(n, { remoteGone: true, tracking: 'origin/' + n, unpushedCommits: 0 })
  const brs = [b('main'), ...['aa/1', 'bb/2', 'cc/3', 'dd/4', 'ee/5', 'ff/6', 'gg/7', 'hh/8', 'ii/9'].map(gone)]
  let call = 0
  const { out } = await run({
    survey: { ...survey, branches: brs, worktrees: [] },
    investigate: () => {
      call++
      // Investigator 1 dies; investigator 2 claims a branch that belonged to batch 1.
      return call === 1
        ? null
        : { verdicts: [{ branch: 'aa/1', category: 'SQUASH_MERGED', evidence: 'PR #7', group: '' }] }
    },
    refute: () => ({ refutations: [{ branch: 'aa/1', refuted: false, reason: 'ok' }] }),
  })
  const delNames = out.deleteCandidates.map((c) => c.branch)
  assert('out-of-batch verdict is not accepted', !delNames.includes('aa/1'), JSON.stringify(delNames))
  assert('no branch is both deletable and unanalyzed', !delNames.some((n) => out.unanalyzed.includes(n)))
  assert('no duplicate delete rows', delNames.length === new Set(delNames).size, JSON.stringify(delNames))
}

// ---- case 9: a short branch name must not bridge unrelated branches into one cluster
{
  const brs = [b('main'), b('feature/login'), b('feature/api'), b('feature/billing'), b('chore/deps')]
  const { out, labels } = await run({
    survey: { ...survey, branches: [...brs, b('feature')], worktrees: [] },
    investigate: () => null,
    refute: () => null,
  })
  assert('bare `feature` spawns no investigators', labels.length === 1, JSON.stringify(labels))
  assert(
    'local-only siblings stay in keep',
    out.keep.filter((k) => k.category !== 'PROTECTED').length === 5 && out.unanalyzed.length === 0,
    JSON.stringify({ keep: out.keep.map((k) => k.branch), unanalyzed: out.unanalyzed }),
  )
}

// ---- case 10: a settled sibling travels with its cluster as context
{
  const brs = [
    b('main'),
    b('feature/api'),
    b('feature/api-v2'),
    b('feature/api-v3', { tracking: 'origin/feature/api-v3', unpushedCommits: 0 }),
  ]
  const { prompts } = await run({
    survey: { ...survey, branches: brs, worktrees: [] },
    investigate: () => ({ verdicts: [] }),
    refute: () => ({ refutations: [] }),
  })
  assert(
    'the superseding branch is shown to the investigator',
    prompts.length === 1 && prompts[0].includes('feature/api-v3') && prompts[0].includes('Context only'),
    JSON.stringify(prompts),
  )
}

// ---- case 11: worktree staleness respects dirt and ref-name format
{
  const wt = (o) => ({ path: '/wt/auth', branch: 'feature/auth', dirty: false, dirtyFiles: [], ...o })
  const survey2 = (worktrees) => ({
    ...survey,
    branches: [b('main'), b('feature/auth', { merged: true })],
    worktrees,
  })
  const dirty = await run({
    survey: survey2([wt({ dirty: true, dirtyFiles: ['M src/a.js'] })]),
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'a dirty worktree is never stale',
    dirty.out.worktrees[0].stale === false,
    JSON.stringify(dirty.out.worktrees),
  )
  const porcelain = await run({
    survey: survey2([wt({ branch: 'refs/heads/feature/auth' })]),
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'a full refs/heads ref still matches its branch',
    porcelain.out.worktrees[0].stale === true,
    JSON.stringify(porcelain.out.worktrees),
  )
}

// ---- case 12: long-lived environment branches are protected on both paths
{
  const names = ['staging', 'production', 'dev', 'hotfix/urgent', 'Staging', 'release/1.0', 'support/2.x']
  const mergedPath = await run({
    survey: { ...survey, worktrees: [], branches: [b('main'), ...names.map((n) => b(n, { merged: true }))] },
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'environment branches are never merged-path delete candidates',
    mergedPath.out.deleteCandidates.length === 0,
    JSON.stringify(mergedPath.out.deleteCandidates.map((c) => c.branch)),
  )
  const gonePath = await run({
    survey: {
      ...survey,
      worktrees: [],
      branches: [b('main'), ...names.map((n) => b(n, { remoteGone: true, tracking: 'origin/' + n, unpushedCommits: 0 }))],
    },
    investigate: (p) => ({
      verdicts: [...p.matchAll(/^ {2}- (\S+) \|/gm)].map((m) => ({
        branch: m[1],
        category: 'SQUASH_MERGED',
        evidence: 'PR #1',
        group: '',
      })),
    }),
    refute: (p) => ({
      refutations: [...p.matchAll(/^ {2}- (\S+): claimed/gm)].map((m) => ({
        branch: m[1],
        refuted: false,
        reason: 'ok',
      })),
    }),
  })
  assert(
    'environment branches never reach the remote-gone force-delete path',
    gonePath.out.deleteCandidates.length === 0 && gonePath.out.unanalyzed.length === 0,
    JSON.stringify(gonePath.out.deleteCandidates.map((c) => c.branch)),
  )
}

// ---- case 13: SAFE_TO_DELETE ships a checkable precondition, not a bare assertion
{
  const { out } = await run({
    survey: {
      ...survey,
      worktrees: [],
      branches: [b('main'), b('fix/typo', { merged: true, lastCommit: 'abc1234 fix a typo' })],
    },
    investigate: () => null,
    refute: () => null,
  })
  const c = out.deleteCandidates.find((x) => x.branch === 'fix/typo')
  assert(
    'evidence names the tip commit',
    c.evidence.includes('abc1234'),
    JSON.stringify(c.evidence),
  )
  assert(
    'verifyWith tests ancestry of the BRANCH, not the reported sha',
    c.verifyWith === "git merge-base --is-ancestor 'refs/heads/fix/typo' 'main'",
    JSON.stringify(c.verifyWith),
  )
}

// ---- case 13b: verifyWith stays a safe shell command for hostile refnames, and stays
// buildable when the survey reports no tip commit at all. Both are execution-time
// properties: the main session pastes this string into a shell verbatim.
{
  const { out } = await run({
    survey: {
      ...survey,
      defaultBranch: 'main',
      branches: [
        b('main'),
        b("evil$(id)", { merged: true, lastCommit: 'dead123 whatever' }),
        b('quiet/branch', { merged: true, lastCommit: '' }),
      ],
    },
    investigate: () => null,
    refute: () => null,
  })
  const evil = out.deleteCandidates.find((x) => x.branch === "evil$(id)")
  assert(
    'a refname containing $(...) is single-quoted in verifyWith',
    evil.verifyWith === "git merge-base --is-ancestor 'refs/heads/evil$(id)' 'main'",
    JSON.stringify(evil.verifyWith),
  )
  const quiet = out.deleteCandidates.find((x) => x.branch === 'quiet/branch')
  assert(
    'a missing tip commit leaves verifyWith a valid command',
    quiet.verifyWith === "git merge-base --is-ancestor 'refs/heads/quiet/branch' 'main'",
    JSON.stringify(quiet.verifyWith),
  )
  assert(
    'a missing tip commit is stated rather than rendered as (unknown)',
    quiet.evidence.includes('tip commit not reported') && !quiet.evidence.includes('(unknown)'),
    JSON.stringify(quiet.evidence),
  )
}

// ---- case 14: worktree ordering survives a survey that omits the optional worktreePath
{
  const { out } = await run({
    survey: {
      ...survey,
      branches: [b('main'), b('feature/auth', { merged: true })],
      worktrees: [{ path: '/wt/auth', branch: 'refs/heads/feature/auth', dirty: false, dirtyFiles: [] }],
    },
    investigate: () => null,
    refute: () => null,
  })
  assert(
    'worktreePath is derived from the required worktrees array',
    out.deleteCandidates[0].worktreePath === '/wt/auth',
    JSON.stringify(out.deleteCandidates[0]),
  )
}

// ---- case 15: context is capped and untrusted spans are fenced
{
  const siblings = Array.from({ length: 40 }, (_, i) => b(`feature/api-old${i}`, { tracking: '', unpushedCommits: -1 }))
  const { prompts } = await run({
    survey: {
      ...survey,
      worktrees: [],
      branches: [
        b('main'),
        ...siblings.map((s) => ({ ...s, merged: true })),
        b('feature/api-x', { remoteGone: true, tracking: 'origin/feature/api-x', unpushedCommits: 0 }),
      ],
    },
    investigate: () => ({ verdicts: [] }),
    refute: () => ({ refutations: [] }),
  })
  const contextLines = (prompts[0].match(/^ {2}- feature\/api-old/gm) || []).length
  assert('context list is capped', contextLines <= 8, String(contextLines))
  assert(
    'untrusted repo text is fenced as data',
    prompts[0].includes('<repo-data>') && prompts[0].includes('DATA BOUNDARY'),
  )
}

// A checker that checks nothing must fail, not pass — and a run with failures must never
// sign off with a line that reads like a pass, since the summary is the last thing visible
// in a collapsed CI group.
if (ran !== EXPECTED_ASSERTIONS) {
  console.log(`\nFAIL  ran ${ran} assertions, expected ${EXPECTED_ASSERTIONS}`)
  process.exitCode = 1
} else if (failures > 0) {
  console.log(`\nFAIL  ${failures} of ${ran} assertions failed`)
  process.exitCode = 1
} else {
  // The js-tests runner greps for this line: a suite that exits 0 having run nothing
  // would otherwise be indistinguishable from a pass.
  console.log(`\n${ran} assertions passed`)
}
