// Ships as /code-improver:improve. Plugin workflows are namespaced by the plugin's
// `name` field; meta.name supplies the rest, not the filename.
export const meta = {
  name: 'improve',
  description:
    'Review→fix loop over a code target (skill, plugin, PR branch) with a pluggable reviewer: cross-round findings ledger, oscillation escalation, mechanical scope guard, guaranteed final clean review, checked finalize pass',
  whenToUse:
    'Invoked by the code-improver entry skills to run the improvement loop. Pass args as a JSON OBJECT, not prose: {"target": "/abs/path/to/target-dir", "reviewer": {"kind": "agent"|"skill", "name": "<plugin>:<agent-or-skill>", "notes": "..."}, "out": "...", "scope": ["repo/relative/glob/**"], "maxRounds": 5, "pluginRoot": "/abs/path/to/code-improver-plugin", "finalize": {"version_bump": true, "narration_strip": true, "docs_pass": true}, "decision": "..."}. target and reviewer are required; the reviewer must be an installed agent or skill — there is no bundled fallback, and an unavailable reviewer halts the run loudly. out, scope, finalize, and pluginRoot are resolved by the baseline phase when omitted. decision carries the user\'s answer to a prior escalation; a continued run reloads the on-disk ledger, so findings and verdicts survive across runs even though rounds restart.',
  phases: [
    { title: 'Baseline', detail: 'Resolve paths, snapshot git state, probe the reviewer, load any prior ledger' },
    { title: 'Review', detail: 'The configured reviewer reports everything with severity; the ledger verdict filters, once' },
    { title: 'Fix', detail: 'Fixer addresses blocking findings, one verdict per finding, then a scope check' },
    { title: 'Final review', detail: 'Completion requires the last action to be a review with zero blocking findings' },
    { title: 'Finalize', detail: 'Strip loop narration, exactly one version bump, then scope- and regression-check the pass itself, metrics' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
// args = {
//   target:     string  (required) absolute path to the directory under improvement
//               (a skill, a plugin, a repo checkout — the reviewer decides what it means)
//   reviewer:   object  (required) { kind: 'agent'|'skill', name: '<namespaced-name>', notes?: string }
//               The installed agent or skill that performs every review. No default and
//               no bundled fallback: an unavailable reviewer halts the run.
//   out:        string  (optional) artifact directory; defaults to <cwd>/.code-improver/<target-name>
//   scope:      string[] (optional) repo-relative globs the loop may touch; defaults to the
//               target's plugin directory (or the target directory when there is no plugin)
//   maxRounds:  number  (optional, default 5) fix-round cap; one review-only round follows it
//   pluginRoot: string  (optional) this plugin's own install directory, for scripts/collect_metrics.py
//   finalize:   object  (optional) { version_bump?, narration_strip?, docs_pass? } — version_bump
//               defaults to true iff the target sits inside a plugin; the other two to true
//   decision:   string  (optional) the user's answer to a prior escalation
// }
const parseArgs = (raw) => {
  if (!raw) return {}
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string') return {}
  const text = raw.trim()
  if (text.startsWith('{')) {
    try {
      return JSON.parse(text)
    } catch {
      // Fall through to key: value parsing rather than dying on a malformed brace.
    }
  }
  const KEYS = ['target', 'skill', 'out', 'scope', 'maxrounds', 'pluginroot', 'decision']
  const CANON = { maxrounds: 'maxRounds', pluginroot: 'pluginRoot', skill: 'target' }
  const out = {}
  let key = null
  for (const part of text.split(/;\s*|\n/)) {
    const m = part.match(/^\s*(\w+)\s*:\s*([\s\S]*)$/)
    if (m && KEYS.includes(m[1].toLowerCase())) {
      key = CANON[m[1].toLowerCase()] || m[1].toLowerCase()
      out[key] = m[2].trim()
    } else if (key && part.trim()) {
      out[key] = `${out[key]} ${part.trim()}`.trim()
    }
  }
  // A bare string with no recognizable key is the target path.
  if (!Object.keys(out).length) out.target = text
  if (typeof out.scope === 'string') out.scope = out.scope.split(/[,\s]+/).filter(Boolean)
  return out
}

const A = parseArgs(args)
if (A.skill && !A.target) A.target = A.skill
if (!A.target) {
  throw new Error(
    'args.target is required: the absolute path to the directory under improvement. ' +
      'Pass args as a JSON object, e.g. {"target": "/path/to/plugins/x/skills/y", "reviewer": {...}}.',
  )
}
const TARGET = String(A.target)
const REVIEWER = A.reviewer
if (
  !REVIEWER ||
  typeof REVIEWER !== 'object' ||
  !['agent', 'skill'].includes(REVIEWER.kind) ||
  typeof REVIEWER.name !== 'string' ||
  !REVIEWER.name.trim()
) {
  throw new Error(
    'args.reviewer is required: {"kind": "agent"|"skill", "name": "<namespaced-name>", "notes": "..."} — ' +
      'the installed agent or skill that performs the reviews. This loop ships no reviewer of its own.',
  )
}
const REVIEWER_NAME = REVIEWER.name.trim()
const REVIEWER_NOTES = REVIEWER.notes ? String(REVIEWER.notes) : ''
const MAX_FIX_ROUNDS = A.maxRounds === undefined || A.maxRounds === '' ? 5 : parseInt(A.maxRounds, 10)
if (!Number.isInteger(MAX_FIX_ROUNDS) || MAX_FIX_ROUNDS < 1 || MAX_FIX_ROUNDS > 20) {
  throw new Error('maxRounds must be an integer between 1 and 20')
}
const DECISION = A.decision ? String(A.decision) : ''

const SEVERITIES = ['critical', 'major', 'minor', 'info']
const BLOCKING = new Set(['critical', 'major'])

// ---------------------------------------------------------------------------
// Ledger — the cross-round memory. Finding ids are `<file>:<line>:<class>`; the
// coarse key drops the line so a finding re-reported at a shifted line still
// matches its ledger entry instead of spawning a duplicate.
// ---------------------------------------------------------------------------
const normFile = (f) => String(f || '').replace(/^\.\//, '').trim()
const normClass = (c) =>
  String(c || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
const findingId = (f) => `${normFile(f.file)}:${f.line | 0}:${normClass(f.class)}`
const coarseKey = (f) => `${normFile(f.file)}::${normClass(f.class)}`
const clip = (s, n) => (String(s || '').length > n ? `${String(s).slice(0, n)}…` : String(s || ''))

const hasThreeConsecutive = (rounds) => {
  const u = [...new Set(rounds)].sort((a, b) => a - b)
  for (let i = 0; i + 2 < u.length; i++) if (u[i + 1] === u[i] + 1 && u[i + 2] === u[i] + 2) return true
  return false
}

// `**` crosses directories, `*` does not, everything else is literal.
const globToRegex = (glob) => {
  const esc = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0001')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0001/g, '.*')
  return new RegExp(`^${esc}$`)
}
const inScope = (path, regexes) => regexes.some((r) => r.test(path))

const ledger = {
  version: 1,
  target: TARGET,
  reviewer: { kind: REVIEWER.kind, name: REVIEWER_NAME },
  scope: [],
  decisions: DECISION ? [DECISION] : [],
  prior_rounds: [],
  rounds: [],
  findings: {},
  result: null,
}

// A continued run keeps findings and verdicts but restarts round numbering, so
// per-round bookkeeping (rounds_seen, fixed_rounds) is archived rather than kept:
// stale round numbers would trip the oscillation checks on round one.
const loadPriorLedger = (rawJson, notes) => {
  if (!rawJson) return
  let prior
  try {
    prior = JSON.parse(rawJson)
  } catch (e) {
    notes.push(`PRIOR LEDGER UNREADABLE (${e.message}): starting a fresh ledger. Prior verdicts are lost; the file on disk will be overwritten.`)
    return
  }
  ledger.prior_rounds = [...(prior.prior_rounds || []), ...(prior.rounds || [])]
  ledger.decisions = [...(prior.decisions || []), ...ledger.decisions]
  for (const [id, f] of Object.entries(prior.findings || {})) {
    ledger.findings[id] = {
      ...f,
      rounds_seen: [],
      seen_prior: [...(f.seen_prior || []), ...(f.rounds_seen || [])],
      fixed_rounds: [],
      fixed_prior: (f.fixed_prior || 0) + (f.fixed_rounds || []).length,
    }
  }
  notes.push(`Loaded prior ledger: ${Object.keys(ledger.findings).length} findings carried over.`)
}

// The reviewer is told to re-report a known finding under its exact ledger id, so that id
// is the first thing consulted: recomputing `file:line:class` misses every finding whose
// line shifted, and the loop then re-dispatches findings it already ruled on. The coarse
// key is the rescue for a reviewer that recomputed the id anyway — but only an entry this
// review has not already claimed can be the match, because two findings of one class in
// one file are two findings, not one that moved.
const findExisting = (raw, round) => {
  const given = String(raw.id || '').trim()
  if (given && ledger.findings[given]) return ledger.findings[given]
  const id = findingId(raw)
  if (ledger.findings[id]) return ledger.findings[id]
  const ck = coarseKey(raw)
  const matches = Object.values(ledger.findings).filter(
    (x) => x.coarse === ck && !(x.rounds_seen || []).includes(round),
  )
  return matches.length === 1 ? matches[0] : null
}

const openBySeverity = () => {
  const counts = { critical: 0, major: 0, minor: 0, info: 0 }
  for (const f of Object.values(ledger.findings)) if (f.status === 'open') counts[f.severity]++
  return counts
}
const openBlocking = () =>
  Object.values(ledger.findings).filter((f) => f.status === 'open' && BLOCKING.has(f.severity))

const mergeReview = (round, review) => {
  let fresh = 0
  let reopened = 0
  let refiledRejected = 0
  for (const rawId of review.verified_fixed || []) {
    const f = ledger.findings[String(rawId).trim()]
    if (f && f.status === 'fixed') f.verified = true
  }
  for (const raw of review.findings || []) {
    const ex = findExisting(raw, round)
    if (!ex) {
      const id = findingId(raw)
      ledger.findings[id] = {
        id,
        coarse: coarseKey(raw),
        file: normFile(raw.file),
        line: raw.line | 0,
        class: normClass(raw.class),
        severity: raw.severity,
        title: clip(raw.title, 200),
        evidence: clip(raw.evidence, 400),
        status: 'open',
        verdict_reason: '',
        verified: false,
        first_round: round,
        last_round: round,
        rounds_seen: [round],
        fixed_rounds: [],
        refiled_after_verdict: 0,
        notes: [],
      }
      fresh++
      continue
    }
    if (ex.status === 'rejected' && !raw.new_evidence) {
      // Re-filed without new evidence: the verdict stands. Counted, not re-litigated.
      ex.refiled_after_verdict++
      refiledRejected++
      continue
    }
    if (ex.status === 'deferred') {
      // Parked findings do not churn — unless the reviewer now rates them blocking.
      if (!BLOCKING.has(raw.severity)) continue
      ex.notes.push(`round ${round}: severity raised to ${raw.severity}, reopened`)
    }
    if (ex.status === 'rejected') ex.notes.push(`round ${round}: reopened with new evidence`)
    if (ex.status === 'fixed') {
      ex.notes.push(`round ${round}: fix did not hold, reopened`)
      reopened++
    }
    ex.status = 'open'
    ex.verified = false
    ex.line = raw.line | 0
    ex.severity = raw.severity
    ex.evidence = clip(raw.evidence, 400)
    ex.rounds_seen.push(round)
    ex.last_round = round
  }
  ledger.rounds.push({
    round,
    type: 'review',
    open: openBySeverity(),
    new: fresh,
    reopened,
    refiled_rejected: refiledRejected,
  })
}

const mergeVerdicts = (round, fixed, dispatchedIds) => {
  const tally = { fixed: 0, rejected: 0, deferred: 0 }
  const seen = new Set()
  const structural = []
  for (const v of fixed.verdicts || []) {
    const f = ledger.findings[String(v.id).trim()]
    if (!f) continue
    seen.add(f.id)
    if (v.verdict === 'fixed') {
      f.status = 'fixed'
      f.verified = false
      f.fixed_rounds.push(round)
      f.pin = clip(v.pin, 300)
      tally.fixed++
    } else if (v.verdict === 'rejected') {
      f.status = 'rejected'
      f.verdict_reason = clip(v.reason, 400)
      if (v.structural && BLOCKING.has(f.severity)) {
        f.structural = true
        structural.push(f.id)
      }
      tally.rejected++
    } else if (v.verdict === 'deferred') {
      if (BLOCKING.has(f.severity)) {
        // A deferred blocker is an unfixed blocker; it stays open and keeps blocking.
        f.notes.push(`round ${round}: fixer deferred a ${f.severity} finding — kept open`)
      } else {
        f.status = 'deferred'
        f.verdict_reason = clip(v.reason, 400)
      }
      tally.deferred++
    }
  }
  const unaddressed = dispatchedIds.filter((id) => !seen.has(id))
  ledger.rounds.push({
    round,
    type: 'fix',
    verdicts: tally,
    unaddressed,
    failed: false,
    diff_file: fixed.diff_file || '',
  })
  return { unaddressed, structural }
}

// ---------------------------------------------------------------------------
// Oscillation detectors (fix C). All three mean the same thing: iteration is not
// converging and a design decision is needed, so stop instead of burning rounds.
// ---------------------------------------------------------------------------
const countsHistory = []
const nonDecreasingOver3 = (h) =>
  h.length >= 3 && h[h.length - 3] > 0 && h[h.length - 2] >= h[h.length - 3] && h[h.length - 1] >= h[h.length - 2]
const recurringBlocking = () =>
  openBlocking().filter((f) => hasThreeConsecutive(f.rounds_seen))
const refixed = () => Object.values(ledger.findings).filter((f) => f.fixed_rounds.length >= 2)

const buildEscalation = (type, message, ids, round) => {
  let named = ids
  if (!named.length) {
    // Nothing literally recurring (e.g. every round surfaces NEW blockers): name what is open now.
    named = openBlocking().map((f) => f.id)
  }
  return {
    type,
    round,
    finding_ids: named,
    message:
      `${message} This is structural — it needs a design decision, not another fix round. ` +
      `Do not weaken documented guarantees to make it converge. To continue after deciding, ` +
      `re-run the workflow with args.decision set; the on-disk ledger carries all findings and verdicts forward.`,
  }
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const BASELINE_SCHEMA = {
  type: 'object',
  required: ['ok', 'error', 'target_dir', 'plugin_dir', 'plugin_version', 'marketplace_file', 'git_root', 'git_initialized', 'head_sha', 'untracked', 'untracked_digests', 'out_dir', 'out_rel', 'prior_ledger_json', 'metrics_script', 'default_scope', 'reviewer_available', 'reviewer_probe'],
  properties: {
    ok: { type: 'boolean' },
    error: { type: 'string', description: 'Why the baseline could not be established; empty when ok.' },
    target_dir: { type: 'string', description: 'Absolute path to the verified target directory.' },
    plugin_dir: { type: 'string', description: 'Absolute path to the enclosing plugin (has .claude-plugin/plugin.json), or empty.' },
    plugin_version: { type: 'string', description: 'The version field of the enclosing plugin.json, or empty.' },
    marketplace_file: { type: 'string', description: 'Repo-relative path of the marketplace manifest that carries this plugin\'s version, or empty.' },
    git_root: { type: 'string', description: 'Absolute path of the repository root covering the target.' },
    git_initialized: { type: 'boolean', description: 'True if this run created the repository.' },
    head_sha: { type: 'string' },
    untracked: { type: 'array', items: { type: 'string' }, description: 'git ls-files --others --exclude-standard, repo-relative.' },
    untracked_digests: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'sha'],
        properties: {
          path: { type: 'string', description: 'One of the untracked paths, verbatim.' },
          sha: { type: 'string', description: 'What `git hash-object` printed for it.' },
        },
      },
      description: 'One entry per path in untracked: the content hash the loop guards it against.',
    },
    out_dir: { type: 'string', description: 'Absolute path of the created artifact directory.' },
    out_rel: { type: 'string', description: 'out_dir relative to git_root, or empty if outside the repo.' },
    prior_ledger_json: { type: 'string', description: 'Raw contents of <out_dir>/ledger.json if it exists, else empty.' },
    metrics_script: { type: 'string', description: 'Absolute path to collect_metrics.py, or empty if not found.' },
    default_scope: { type: 'array', items: { type: 'string' }, description: 'Repo-relative glob(s) covering the plugin (or target) directory.' },
    reviewer_available: { type: 'boolean', description: 'Whether the named reviewer is available in this session. Always true when the probe was not requested.' },
    reviewer_probe: { type: 'string', description: 'What the reviewer-availability check observed, verbatim.' },
  },
}

const REVIEW_SCHEMA = {
  type: 'object',
  required: ['findings', 'verified_fixed', 'summary'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'file', 'line', 'class', 'severity', 'title', 'evidence'],
        properties: {
          id: { type: 'string', description: 'file:line:class. Reuse the exact ledger id when re-reporting a known finding, even at a shifted line.' },
          file: { type: 'string', description: 'Repo-relative path.' },
          line: { type: 'integer' },
          class: { type: 'string', description: 'Short kebab-case defect class, e.g. dangling-reference, second-person-voice.' },
          severity: { type: 'string', enum: ['critical', 'major', 'minor', 'info'] },
          title: { type: 'string' },
          evidence: { type: 'string', description: 'What was observed, concretely. For a re-filed rejected finding, the NEW evidence.' },
          new_evidence: { type: 'boolean', description: 'Set true ONLY when re-filing a rejected finding with evidence its recorded rejection reason does not cover.' },
        },
      },
    },
    verified_fixed: {
      type: 'array',
      items: { type: 'string' },
      description: 'Ledger ids whose fix you verified by reading the current code. A fix that does not hold is re-filed under its id instead.',
    },
    summary: { type: 'string' },
  },
}

// Reviewer skills may orchestrate specialist agents. Workflow subagents cannot spawn
// subagents (the runtime strips the Agent tool at depth 1), so the wrapper returns the
// dispatches it would have made and the loop executes them — a trampoline.
const MAX_DISPATCH_WAVES = 3
const MAX_AGENTS_PER_WAVE = 8

const SKILL_REVIEW_SCHEMA = {
  type: 'object',
  required: ['mode', 'findings', 'verified_fixed', 'summary', 'agents'],
  properties: {
    mode: {
      type: 'string',
      enum: ['direct', 'dispatch'],
      description: '"direct": the review is finished and findings carry it. "dispatch": run the specialist agents listed in `agents` and continue this review with their reports.',
    },
    findings: REVIEW_SCHEMA.properties.findings,
    verified_fixed: REVIEW_SCHEMA.properties.verified_fixed,
    summary: { type: 'string' },
    agents: {
      type: 'array',
      items: {
        type: 'object',
        required: ['agentType', 'prompt', 'label'],
        properties: {
          agentType: { type: 'string', description: 'Namespaced subagent type exactly as the skill names it, e.g. pr-review-toolkit:code-reviewer.' },
          prompt: { type: 'string', description: 'The full, self-contained prompt the skill prescribes for this specialist: include the target path, the scope, and what to report.' },
          label: { type: 'string', description: 'Short kebab-case label for progress display.' },
        },
      },
      description: 'With mode "dispatch": one entry per specialist the skill prescribes. Empty with mode "direct".',
    },
  },
}

const FIX_SCHEMA = {
  type: 'object',
  required: ['verdicts', 'diff_file', 'notes'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'verdict', 'reason'],
        properties: {
          id: { type: 'string' },
          verdict: { type: 'string', enum: ['fixed', 'rejected', 'deferred'] },
          reason: { type: 'string', description: 'For rejected: why the finding is wrong or must not be fixed. For deferred: why it can wait.' },
          structural: {
            type: 'boolean',
            description: 'With verdict "rejected": true when the finding is REAL but a documented, immutable demand makes it unsatisfiable. The loop escalates these to the user instead of converging past a broken promise.',
          },
          pin: { type: 'string', description: 'The test or assertion that fails against the pre-fix code, or "none: prose-only change".' },
        },
      },
    },
    diff_file: { type: 'string', description: 'The fixes-round-N.diff file written to the artifact directory.' },
    notes: { type: 'string' },
  },
}

const SCOPE_SCHEMA = {
  type: 'object',
  required: ['changed', 'untracked'],
  properties: {
    changed: { type: 'array', items: { type: 'string' }, description: 'git diff --name-only <baseline>, repo-relative, verbatim.' },
    untracked: { type: 'array', items: { type: 'string' }, description: 'git ls-files --others --exclude-standard, repo-relative, verbatim.' },
    untracked_digests: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'sha'],
        properties: {
          path: { type: 'string', description: 'The guarded path, exactly as the prompt listed it.' },
          sha: { type: 'string', description: 'What `git hash-object` printed, or exactly "MISSING" when the file is gone.' },
        },
      },
      description: 'One entry per guarded path the prompt lists — every one, even when unchanged. Omitting a path reads as an unverified file, not as a clean one.',
    },
  },
}

const FINALIZE_SCHEMA = {
  type: 'object',
  required: ['narration_sites_removed', 'version', 'notes'],
  properties: {
    narration_sites_removed: { type: 'integer' },
    version: { type: 'string', description: 'The plugin version after finalize, or empty when the target is not a plugin.' },
    notes: { type: 'string' },
  },
}

// Finalize edits the tree after the last review and the last scope check, so its own
// output is checked here — mechanically for scope, by reading for regressions — before
// the run is allowed to report convergence.
const FINALIZE_CHECK_SCHEMA = {
  type: 'object',
  required: ['changed', 'untracked', 'regressions', 'metrics_ok'],
  properties: {
    changed: SCOPE_SCHEMA.properties.changed,
    untracked: SCOPE_SCHEMA.properties.untracked,
    untracked_digests: SCOPE_SCHEMA.properties.untracked_digests,
    regressions: {
      type: 'array',
      items: {
        type: 'object',
        required: ['file', 'line', 'why'],
        properties: {
          file: { type: 'string', description: 'Repo-relative path of the finalize edit that must not stand.' },
          line: { type: 'integer' },
          why: { type: 'string', description: 'What the edit broke, concretely: the content it rewrote, the statement it made false, the version it got wrong.' },
        },
      },
      description: 'Empty only when every finalize edit was read and is sound.',
    },
    metrics_ok: { type: 'boolean' },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 — Baseline
// ---------------------------------------------------------------------------
phase('Baseline')

const RESOLVE_METRICS = A.pluginRoot
  ? `ls "${A.pluginRoot}/scripts/collect_metrics.py" 2>/dev/null`
  : `ls "$CLAUDE_PLUGIN_ROOT/scripts/collect_metrics.py" 2>/dev/null
  ls ~/.claude/plugins/cache/*/code-improver/*/scripts/collect_metrics.py 2>/dev/null | sort -V | tail -1
  find "$HOME/.claude" . -maxdepth 7 -type f -path '*code-improver/scripts/collect_metrics.py' 2>/dev/null | head -1`

const SKILL_PROBE_STEP =
  REVIEWER.kind === 'skill'
    ? `\n9. Reviewer availability: every review of this run is performed by the installed skill \`${REVIEWER_NAME}\`. Check the listing of available skills in your context (the "skills are available for use with the Skill tool" system-reminder). Report reviewer_available=true only if \`${REVIEWER_NAME}\` is listed, and quote the matching listing line (or say it is absent) as reviewer_probe. Do NOT invoke the skill.\n`
    : '\n9. Reviewer availability: not your concern on this run; report reviewer_available=true and reviewer_probe as an empty string.\n'

const baseline = await agent(
  `You are establishing the baseline for an automated improvement loop over the target at \`${TARGET}\`. Run these steps and report exactly what you find.

1. Verify the target: the directory \`${TARGET}\` must exist and be non-empty. If it does not, report ok=false with the error.

2. Find the enclosing plugin: walk up from the target directory looking for \`.claude-plugin/plugin.json\`. Report its directory and its "version" field, or empty strings if there is none. When there is a plugin, also find the manifest that repeats its version: look for \`.claude-plugin/marketplace.json\` at the root of the repository containing the target (step 3 resolves that root) and, if it exists and holds an entry whose "source" names this plugin's directory, report that file's path relative to the repository root as marketplace_file. Empty string if there is no such file or no entry for this plugin.

3. Establish the git baseline: run \`git -C ${TARGET} rev-parse --show-toplevel\`. If the target is NOT inside a git repository, initialize one — the loop's scope guard and fix verification depend on a diffable baseline:
   - Choose the root: the current working directory if the target path is under it, otherwise the plugin directory (or the target's parent).
   - Run \`git init\` there, then commit everything as the baseline snapshot with an explicit identity so no junk identity leaks from the machine:
     \`git -c user.name='code-improver-baseline' -c user.email='code-improver@trailofbits.com' commit\` (after \`git add -A\`).
   - Report git_initialized=true. This is loud on purpose: the caller must tell the user a repository was created.

4. Record the snapshot: HEAD sha (\`git rev-parse HEAD\`) and the untracked files (\`git ls-files --others --exclude-standard\`). Untracked files are in no commit and no index, so \`git diff\` can never show what happens to them — hash each one so the loop can tell:

  git -C "<git_root>" ls-files --others --exclude-standard | while IFS= read -r p; do printf '%s %s\\n' "$(git -C "<git_root>" hash-object -- "$p")" "$p"; done

  Report one untracked_digests entry per line: sha first, then the path.

5. Create the artifact directory: \`mkdir -p ${A.out ? `"${A.out}"` : '"$PWD/.code-improver/<target-directory-name>"'}\` and report its absolute path as out_dir, plus its path relative to git_root as out_rel (empty if outside the repo).

6. Prior ledger: if \`<out_dir>/ledger.json\` exists, return its raw contents verbatim as prior_ledger_json; otherwise an empty string. Do not summarize or reformat it.

7. Locate the metrics collector. Run these in order and stop at the first that prints a path:

  ${RESOLVE_METRICS}

  Report the absolute path as metrics_script, or an empty string — do not guess.

8. default_scope: the plugin directory (or the target directory if there is no plugin) relative to git_root, as a single glob: \`<relpath>/**\`.
${SKILL_PROBE_STEP}
Report facts only. Do not review, fix, or change anything beyond git init/commit in step 3 and mkdir in step 5.`,
  { schema: BASELINE_SCHEMA, label: 'baseline', effort: 'low' },
)

if (!baseline) throw new Error('the baseline phase returned nothing; the loop cannot run without a git snapshot')
if (!baseline.ok) throw new Error(`baseline failed: ${baseline.error || 'no reason reported'}`)
if (!baseline.git_root || !baseline.git_root.startsWith('/')) {
  throw new Error(`baseline reported a non-absolute git root (\`${baseline.git_root}\`); the scope guard cannot work without one`)
}
if (!baseline.head_sha) throw new Error('baseline reported no HEAD sha; there is nothing to diff fixes against')
if (!baseline.out_dir || !baseline.out_dir.startsWith('/')) {
  throw new Error(`baseline reported a non-absolute artifact directory (\`${baseline.out_dir}\`)`)
}

const OUT = baseline.out_dir
const OUT_REL = baseline.out_rel || ''
const GIT_ROOT = baseline.git_root
const BASE_SHA = baseline.head_sha
const LEDGER_PATH = `${OUT}/ledger.json`
const notes = []

if (baseline.git_initialized) {
  notes.push(`A git repository was INITIALIZED at ${GIT_ROOT} to give the loop a baseline. Tell the user; remove with \`rm -rf ${GIT_ROOT}/.git\` if unwanted.`)
  log(notes[notes.length - 1])
}
if (!baseline.metrics_script) {
  notes.push('collect_metrics.py was not found; the run produces no metrics.json. Pass args.pluginRoot to fix.')
  log(notes[notes.length - 1])
}

const SCOPE = Array.isArray(A.scope) && A.scope.length ? A.scope.map(String) : [...(baseline.default_scope || [])]
if (!SCOPE.length) throw new Error('no scope: pass args.scope or let the baseline derive one from the plugin directory')

// Finalize is data-driven: "exactly one version bump" only means something when the
// target sits inside a plugin, and callers (e.g. PR mode) may opt out of any part.
const FIN_ARGS = A.finalize && typeof A.finalize === 'object' ? A.finalize : {}
const FINALIZE = {
  version_bump: FIN_ARGS.version_bump === undefined ? !!baseline.plugin_version : !!FIN_ARGS.version_bump,
  narration_strip: FIN_ARGS.narration_strip === undefined ? true : !!FIN_ARGS.narration_strip,
  docs_pass: FIN_ARGS.docs_pass === undefined ? true : !!FIN_ARGS.docs_pass,
}
// A plugin's version lives in two files: plugin.json and the marketplace entry that
// repeats it. The manifest sits at the repository root, outside the target's plugin
// directory, so a bump the scope cannot reach leaves the two disagreeing — which the
// repository's own metadata validator rejects. Widen the scope instead of shipping that.
const MARKETPLACE_FILE = baseline.marketplace_file ? String(baseline.marketplace_file) : ''
if (FINALIZE.version_bump && MARKETPLACE_FILE && !inScope(MARKETPLACE_FILE, SCOPE.map(globToRegex))) {
  SCOPE.push(MARKETPLACE_FILE)
  notes.push(`Scope extended with ${MARKETPLACE_FILE}: it repeats the plugin version, so the one bump must land there too or plugin.json and the marketplace entry disagree.`)
  log(notes[notes.length - 1])
}

const SCOPE_REGEXES = SCOPE.map(globToRegex)
ledger.scope = SCOPE
ledger.baseline = { sha: BASE_SHA, git_root: GIT_ROOT }
loadPriorLedger(baseline.prior_ledger_json, notes)
const baselineUntracked = new Set(baseline.untracked || [])

// The run's own artifact directory is not a violation, and neither is a file that was
// already untracked when the run started.
const isArtifact = (p) => OUT_REL && (p === OUT_REL || p.startsWith(`${OUT_REL}/`))
const outOfScopePaths = (rep) => [
  ...((rep && rep.changed) || []).filter((p) => !inScope(p, SCOPE_REGEXES) && !isArtifact(p)),
  ...((rep && rep.untracked) || []).filter(
    (p) => !inScope(p, SCOPE_REGEXES) && !isArtifact(p) && !baselineUntracked.has(p),
  ),
]
const newUntrackedInScope = (rep) =>
  ((rep && rep.untracked) || []).filter(
    (p) => inScope(p, SCOPE_REGEXES) && !isArtifact(p) && !baselineUntracked.has(p),
  )

// A file that was untracked at the baseline is in no commit and no index, so `git diff`
// shows nothing when it is rewritten and nothing when it is deleted: the change surface
// alone cannot guard it. Out-of-scope ones are guarded by content instead — the baseline
// hash against the hash the check reports.
const MAX_GUARDED_UNTRACKED = 50
const baselineDigest = new Map(
  (baseline.untracked_digests || []).map((d) => [normFile(d && d.path), String((d && d.sha) || '').trim()]),
)
const guardable = [...baselineUntracked].filter((p) => !inScope(p, SCOPE_REGEXES) && !isArtifact(p)).sort()
const GUARDED_UNTRACKED = guardable.filter((p) => baselineDigest.has(p)).slice(0, MAX_GUARDED_UNTRACKED)
const unguarded = guardable.filter((p) => !GUARDED_UNTRACKED.includes(p))
if (unguarded.length) {
  notes.push(
    `${unguarded.length} out-of-scope untracked file(s) cannot be guarded by content ` +
      `(${unguarded.slice(0, 5).join(', ')}${unguarded.length > 5 ? ', …' : ''}): the baseline reported no hash for them, or there are more than ${MAX_GUARDED_UNTRACKED}. ` +
      `A fixer that rewrites one of those leaves no trace in \`git diff\`; check them by hand if they matter.`,
  )
  log(notes[notes.length - 1])
}

// Listed in every surface report so the check has the same view the guard does.
const guardedCommands = GUARDED_UNTRACKED.length
  ? `\n${GUARDED_UNTRACKED.map((p) => `  git -C "${GIT_ROOT}" hash-object -- "${p}" || echo MISSING`).join('\n')}\n\nReport the hash commands as untracked_digests — one entry per path above, every one of them, with sha set to what the command printed ("MISSING" when the file is gone). These files are outside scope and must not have changed.`
  : ''

const tamperedUntracked = (rep) => {
  const reported = new Map(
    ((rep && rep.untracked_digests) || []).map((d) => [normFile(d && d.path), String((d && d.sha) || '').trim()]),
  )
  const bad = []
  for (const p of GUARDED_UNTRACKED) {
    const now = reported.get(p)
    if (now === undefined) bad.push(`${p} (unverified: the check reported no hash for it)`)
    else if (now !== baselineDigest.get(p)) bad.push(`${p} (${/^MISSING$/i.test(now) ? 'deleted' : 'modified'})`)
  }
  return bad
}

log(`Scope: ${SCOPE.join(', ')} | baseline ${BASE_SHA.slice(0, 12)} | artifacts: ${OUT}`)

// ---------------------------------------------------------------------------
// Prompt fragments
// ---------------------------------------------------------------------------
// The ledger is persisted by a dedicated agent before every review dispatch —
// the pluggable reviewer may lack the Write tool — and as step 0 of every fixer
// prompt, so an interrupt at any point leaves at most one round un-persisted on
// disk (the journal still has it). Exits with no next agent persist explicitly.
const persistBlock = () =>
  `STEP 0 — before anything else, persist the ledger for interrupt safety: use the Write tool to write the following JSON verbatim (no edits, no reformatting) to \`${LEDGER_PATH}\`:

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\``

const ledgerBlock = () =>
  `The ledger below is already persisted to \`${LEDGER_PATH}\`; it is read-only context — do not write it:

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\``

const persistLedger = async (label) => {
  await agent(
    `Persist the ledger of an improvement loop for interrupt safety: use the Write tool to write the following JSON verbatim (no edits, no reformatting) to \`${LEDGER_PATH}\`. Write that one file and nothing else.

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\``,
    { label, effort: 'low' },
  )
}

const decisionBlock = () =>
  ledger.decisions.length
    ? `\nThe user has ruled on prior escalations, most recent last: ${JSON.stringify(ledger.decisions)}. These rulings are binding; judge related findings under them.\n`
    : ''

// `uv run --no-project`, never `python3 <script>`: the modern-python shims refuse a
// script path outright, so that form silently produces no metrics.json for anyone who
// has that plugin installed. The collector is pure stdlib, so no project is needed.
const metricsCommand = () =>
  baseline.metrics_script
    ? `uv run --no-project "${baseline.metrics_script}" --ledger "${LEDGER_PATH}" --repo "${GIT_ROOT}" --baseline-sha ${BASE_SHA} --diff-dir "${OUT}" --out "${OUT}/metrics.json" --tokens ${budget.spent()} ${SCOPE.map((g) => `--scope '${g}'`).join(' ')}`
    : ''

const persistExit = async (label) => {
  ledger.result = RESULT
  await agent(
    `Persist the final state of an improvement loop.

1. Use the Write tool to write the following JSON verbatim (no edits, no reformatting) to \`${LEDGER_PATH}\`:

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\`

2. Write a short human-readable \`${OUT}/status.md\`: the outcome (${label}), open blocking findings with ids and titles, any escalation message, and how to continue (re-run the improvement loop; it reloads this ledger).
${baseline.metrics_script ? `\n3. Run the metrics collector and report whether it succeeded:\n\n  ${metricsCommand()}\n` : ''}`,
    { label: 'persist', effort: 'low' },
  )
}

// ---------------------------------------------------------------------------
// Phases 2+3 — Review and fix rounds. MAX_FIX_ROUNDS fix rounds at most; review
// round MAX_FIX_ROUNDS+1 is review-only, so the loop can never end on an
// unreviewed fix.
// ---------------------------------------------------------------------------
const RESULT = {
  converged: false,
  capped: false,
  halted: '',
  escalation: null,
  violations: [],
  finalize_regressions: [],
  rounds_run: 0,
  fix_rounds: 0,
  fixer_failed_rounds: [],
  open_blocking: [],
  open_minor_count: 0,
  new_untracked_files: [],
  ledger_path: LEDGER_PATH,
  out_dir: OUT,
  metrics: baseline.metrics_script ? `${OUT}/metrics.json` : '',
  notes,
}

const finishResult = () => {
  RESULT.open_blocking = openBlocking().map((f) => ({ id: f.id, severity: f.severity, title: f.title }))
  RESULT.open_minor_count = Object.values(ledger.findings).filter(
    (f) => f.status === 'open' && !BLOCKING.has(f.severity),
  ).length
  return RESULT
}

// The wrapper's no-improvisation sentinel. Every reviewer return passes through this —
// the first one and every trampoline continuation — because a continuation that lost its
// skill returns an empty review that would otherwise read as a clean bill of health.
const unavailableSentinel = (r) => /^REVIEWER-UNAVAILABLE:/.test((r && r.summary) || '')

const reviewerUnavailable = async (evidence) => {
  RESULT.halted = 'reviewer-unavailable'
  notes.push(
    `REVIEWER UNAVAILABLE: the ${REVIEWER.kind} \`${REVIEWER_NAME}\` is not installed in this session (${evidence}). ` +
      `Install the plugin that provides it${REVIEWER_NOTES ? ` (${REVIEWER_NOTES})` : ''} and re-run. ` +
      `Nothing was reviewed or edited: the loop never substitutes an inline review — an unguarded imitation has none of the ledger, scope, or escalation guarantees.`,
  )
  log(notes[notes.length - 1])
  finishResult()
  await persistExit('halted: reviewer unavailable')
}

let done = false
if (REVIEWER.kind === 'skill' && !baseline.reviewer_available) {
  await reviewerUnavailable(baseline.reviewer_probe || 'not in the session skill listing')
  done = true
}

for (let round = 1; round <= MAX_FIX_ROUNDS + 1 && !done; round++) {
  const finalRound = round === MAX_FIX_ROUNDS + 1
  phase(finalRound ? 'Final review' : 'Review')

  const reviewerLeadIn =
    REVIEWER.kind === 'skill'
      ? `You perform the review by invoking the Skill tool with skill="${REVIEWER_NAME}" FIRST and applying the review that skill prescribes to the target. If the Skill invocation fails or the skill is unavailable, do NOT review anything yourself: return zero findings, an empty verified_fixed, and a summary that begins exactly with "REVIEWER-UNAVAILABLE:" followed by the error you saw.
If the skill prescribes launching specialist review agents (Task dispatches), you cannot spawn them yourself — the loop runs them for you: return mode "dispatch" with one entry per specialist (agentType = the namespaced subagent type the skill names; prompt = the full, self-contained prompt you would give it, including the target path, the scope, and what to report; label = a short kebab-case tag). Their reports come back to you in a continuation. With mode "dispatch", leave findings empty and make summary a one-line status — the reporting contract below applies to the final "direct" return. If the skill needs no specialists, perform the review yourself and return mode "direct".`
      : `You are dispatched as the \`${REVIEWER_NAME}\` agent: apply your own review standards to the target.`

  await persistLedger(`persist:${round}`)

  let review
  try {
    review = await agent(
      `Review round ${round}${finalRound ? ' — FINAL. This is a review-only round: no fix will follow, so report the true state.' : ''} of an automated improvement loop over the target at \`${TARGET}\`. ${reviewerLeadIn}
${REVIEWER_NOTES ? `\nReviewer configuration notes from the caller: ${REVIEWER_NOTES}\n` : ''}
${ledgerBlock()}

Scope (repo-relative globs; the loop only changes files inside them): ${SCOPE.join(', ')}
${decisionBlock()}
The ledger above is the authoritative cross-round memory. Apply it:
- Findings with status "fixed" and verified=false: verify each fix by reading the current code. Return the ids that genuinely hold in verified_fixed. A fix that does not hold is re-filed under its exact ledger id.
- Findings with status "rejected": do NOT re-file them unless you have genuinely NEW evidence that the recorded verdict_reason does not cover. If you do, re-file under the same id with new_evidence=true and the new evidence in \`evidence\`.
- Findings with status "deferred" are parked; do not re-file them at the same severity.
- Reuse the exact ledger id when re-reporting any known finding, even when its line has shifted.

Now review the target and report EVERY defect the review surfaces, each with a severity attached — including minor and informational ones. Map the reviewer's native severity scale onto critical|major|minor|info. Do not withhold or pre-filter low-severity findings; filtering happens at the ledger verdict, once, not in your report. Do not edit or fix anything — you perform no writes at all.`,
      { schema: REVIEWER.kind === 'skill' ? SKILL_REVIEW_SCHEMA : REVIEW_SCHEMA, label: finalRound ? 'final-review' : `review:${round}`, phase: finalRound ? 'Final review' : 'Review', ...(REVIEWER.kind === 'agent' ? { agentType: REVIEWER_NAME } : {}) },
    )
  } catch (e) {
    // An unresolvable agentType throws at dispatch, before any tokens are spent.
    if (/agent type .* not found/i.test(e.message || '')) {
      await reviewerUnavailable(e.message)
      break
    }
    throw e
  }

  if (unavailableSentinel(review)) {
    await reviewerUnavailable(clip(review.summary, 300))
    break
  }

  // Trampoline: the wrapper cannot spawn agents, so it hands the loop the dispatches
  // the reviewer skill prescribes; the loop runs each wave and continues the review
  // with the reports until the wrapper finishes with mode "direct".
  let trampolineHalted = false
  if (REVIEWER.kind === 'skill') {
    let wave = 0
    while (review && review.mode === 'dispatch' && !trampolineHalted) {
      wave++
      if (wave > MAX_DISPATCH_WAVES) {
        RESULT.halted = 'reviewer-failed'
        notes.push(`The round-${round} reviewer requested a specialist wave beyond the ${MAX_DISPATCH_WAVES}-wave cap without finishing its review. The round is incomplete; re-run to continue from the persisted ledger.`)
        log(notes[notes.length - 1])
        finishResult()
        await persistExit('halted: reviewer exceeded the specialist wave cap')
        trampolineHalted = true
        break
      }
      const requested = Array.isArray(review.agents) ? review.agents : []
      if (!requested.length) {
        RESULT.halted = 'reviewer-failed'
        notes.push(`The round-${round} reviewer returned mode "dispatch" with an empty agent list — an unfinishable review. Re-run to continue from the persisted ledger.`)
        log(notes[notes.length - 1])
        finishResult()
        await persistExit('halted: empty specialist dispatch')
        trampolineHalted = true
        break
      }
      const plan = requested.slice(0, MAX_AGENTS_PER_WAVE)
      if (requested.length > plan.length) {
        log(`Round ${round} wave ${wave}: ${requested.length - plan.length} specialist request(s) dropped over the ${MAX_AGENTS_PER_WAVE}-agent cap`)
      }
      log(`Round ${round} wave ${wave}: dispatching ${plan.length} specialist(s): ${plan.map((s) => s.agentType).join(', ')}`)
      const reports = await parallel(
        plan.map((s, i) => () =>
          agent(String(s.prompt || ''), {
            label: `specialist:${round}.${wave}.${normClass(s.label || s.agentType || String(i))}`,
            phase: finalRound ? 'Final review' : 'Review',
            agentType: String(s.agentType || ''),
          })
            .then((r) => ({ ok: r !== null && r !== undefined, report: r, error: '' }))
            .catch((e) => ({ ok: false, report: null, error: String((e && e.message) || e) })),
        ),
      )
      const unresolvable = reports.find((r) => r && /agent type .* not found/i.test(r.error))
      if (unresolvable) {
        const which = plan[reports.indexOf(unresolvable)]
        await reviewerUnavailable(`its planned specialist \`${which.agentType}\` did not resolve: ${clip(unresolvable.error, 200)}`)
        trampolineHalted = true
        break
      }
      const reportBlock = plan
        .map((s, i) => {
          const r = reports[i]
          const body = r && r.ok ? clip(r.report, 20000) : `SPECIALIST FAILED: ${(r && r.error) || 'returned nothing'}`
          return `### ${s.label || s.agentType} (${s.agentType})\n${body}`
        })
        .join('\n\n')
      review = await agent(
        `Review round ${round}, continuation after specialist wave ${wave}, of an automated improvement loop over the target at \`${TARGET}\`. A previous stage invoked the installed skill \`${REVIEWER_NAME}\` and requested the specialist dispatches below; the loop ran them. Invoke the Skill tool with skill="${REVIEWER_NAME}" first if you need the review methodology it prescribes. If that Skill invocation fails or the skill is unavailable, do NOT review anything yourself and do NOT consolidate the reports without it: return mode "direct", zero findings, an empty verified_fixed, and a summary that begins exactly with "REVIEWER-UNAVAILABLE:" followed by the error you saw. The loop halts on that sentinel; an empty review without it reads as a clean bill of health.
${REVIEWER_NOTES ? `\nReviewer configuration notes from the caller: ${REVIEWER_NOTES}\n` : ''}
${ledgerBlock()}

Scope (repo-relative globs; the loop only changes files inside them): ${SCOPE.join(', ')}
${decisionBlock()}
Specialist reports:

${reportBlock}

Either request another specialist wave (mode "dispatch"; ${MAX_DISPATCH_WAVES - wave} wave(s) remain — a report marked SPECIALIST FAILED may be re-requested) or finish the round with mode "direct": consolidate the specialist reports and your own verification into findings, applying the ledger discipline:
- Findings with status "fixed" and verified=false: verify each fix by reading the current code. Return the ids that genuinely hold in verified_fixed. A fix that does not hold is re-filed under its exact ledger id.
- Findings with status "rejected": do NOT re-file them unless you have genuinely NEW evidence that the recorded verdict_reason does not cover. If you do, re-file under the same id with new_evidence=true and the new evidence in \`evidence\`.
- Findings with status "deferred" are parked; do not re-file them at the same severity.
- Reuse the exact ledger id when re-reporting any known finding, even when its line has shifted.

Report EVERY defect the review surfaced, each with a severity mapped onto critical|major|minor|info. Do not withhold or pre-filter low-severity findings; filtering happens at the ledger verdict, once, not in your report. Do not edit or fix anything — you perform no writes at all.`,
        { schema: SKILL_REVIEW_SCHEMA, label: `review:${round}.${wave + 1}`, phase: finalRound ? 'Final review' : 'Review' },
      )
      if (unavailableSentinel(review)) {
        await reviewerUnavailable(clip(review.summary, 300))
        trampolineHalted = true
        break
      }
    }
  }
  if (trampolineHalted) break

  if (!review) {
    RESULT.halted = 'reviewer-failed'
    notes.push(`The round-${round} reviewer returned nothing; the loop cannot certify the tree. Re-run to continue from the persisted ledger.`)
    finishResult()
    await persistExit('halted: reviewer failed')
    break
  }

  RESULT.rounds_run = round
  mergeReview(round, review)
  const blocking = openBlocking()
  countsHistory.push(blocking.length)
  log(`Round ${round} review: ${blocking.length} blocking open (${JSON.stringify(openBySeverity())})`)

  if (blocking.length === 0) {
    RESULT.converged = true
    done = true
    break
  }

  if (nonDecreasingOver3(countsHistory)) {
    RESULT.escalation = buildEscalation(
      'counts-non-decreasing',
      `The open critical/major count has not decreased for 3 review rounds (${countsHistory.slice(-3).join(' → ')}): fixes are producing as many blockers as they resolve.`,
      recurringBlocking().map((f) => f.id),
      round,
    )
  } else if (recurringBlocking().length) {
    RESULT.escalation = buildEscalation(
      'recurrence',
      `Finding(s) ${recurringBlocking().map((f) => f.id).join(', ')} have stayed open for 3 consecutive review rounds despite fix attempts.`,
      recurringBlocking().map((f) => f.id),
      round,
    )
  }
  if (RESULT.escalation) {
    log(`ESCALATION (${RESULT.escalation.type}): ${RESULT.escalation.message}`)
    finishResult()
    await persistExit(`escalation: ${RESULT.escalation.type}`)
    break
  }

  if (finalRound) {
    // The cap. The fix budget is spent and this review was not clean: exit loudly.
    RESULT.capped = true
    notes.push(`CAPPED, NOT CONVERGED: ${MAX_FIX_ROUNDS} fix rounds were spent and the final review still reports blocking findings. The tree holds uncommitted changes; the open-findings list is in the result and the ledger.`)
    log(notes[notes.length - 1])
    finishResult()
    await persistExit('capped, NOT converged')
    break
  }

  phase('Fix')
  const dispatched = blocking.map((f) => ({
    id: f.id,
    file: f.file,
    line: f.line,
    class: f.class,
    severity: f.severity,
    title: f.title,
    evidence: f.evidence,
  }))
  const fixed = await agent(
    `Fix round ${round} of an automated improvement loop over the target at \`${TARGET}\`.

${persistBlock()}

Address ONLY these blocking findings (the ledger above is context — honor recorded rejections and deferrals):

\`\`\`json
${JSON.stringify(dispatched, null, 2)}
\`\`\`
${decisionBlock()}
Non-negotiable rules:
- Stay inside scope: ${SCOPE.join(', ')} (repo-relative, repo root \`${GIT_ROOT}\`). If a fix requires touching anything outside scope, do NOT make it — return verdict "rejected" with reason "requires out-of-scope change: <path>". Files git does not track are in scope or out of it like any other: the guard holds a content hash of the out-of-scope ones, so deleting or rewriting one is a violation, not an invisible edit.
- NEVER run \`git checkout --\`, \`git stash\`, \`git reset\`, \`git clean\`, or \`git commit\`. The tree holds uncommitted work that is not yours.
- Return a verdict for EVERY finding listed: "fixed", "rejected" (with the reason the finding is wrong or must not be fixed), or "deferred" (minor/info only — a deferred blocker stays open). When a rejection's reason is that the finding is REAL but a documented immutable demand makes it unsatisfiable, also set structural=true — the loop escalates those to the user instead of converging past a broken promise.
- A fix that changes executable behavior (scripts, hooks, commands) needs a pin: a test or assertion that fails against the pre-fix code. String or severity heuristics need table pins covering the cases, not one example. Name the pin in the verdict. Prose and frontmatter fixes need no pin; the next review verifies them.
- If you create a new file, register it with \`git add -N <file>\` so the scope guard and the diff can see it.
- No narration: never write comments, docs, or commit-message-style text referencing this loop, rounds, iterations, or previous fixes.
- Never weaken a documented guarantee, threat model, or stated behavior to make a finding go away. When project docs mark a guarantee as contractual or immutable, rewording, narrowing, or deleting its text counts as weakening. If a documented demand is structurally unsatisfiable, reject the finding and say why.
- LAST STEP, after all edits: write the cumulative diff for verification:

  git -C "${GIT_ROOT}" diff ${BASE_SHA} > "${OUT}/fixes-round-${round}.diff"

  and return "fixes-round-${round}.diff" as diff_file.`,
    { schema: FIX_SCHEMA, label: `fix:${round}`, phase: 'Fix', agentType: 'code-improver:fixer' },
  )

  if (!fixed) {
    // A dead fixer may have left partial edits. Record the failure; the next
    // review round is the verifier, so the loop proceeds to review, never to
    // another blind fix.
    ledger.rounds.push({ round, type: 'fix', verdicts: { fixed: 0, rejected: 0, deferred: 0 }, unaddressed: dispatched.map((d) => d.id), failed: true, diff_file: '' })
    RESULT.fixer_failed_rounds.push(round)
    RESULT.fix_rounds = round
    notes.push(`The round-${round} fixer died; the tree may hold partial edits. The next review verifies it.`)
    log(notes[notes.length - 1])
  } else {
    RESULT.fix_rounds = round
    const { unaddressed, structural } = mergeVerdicts(round, fixed, dispatched.map((d) => d.id))
    if (unaddressed.length) log(`Round ${round} fix left ${unaddressed.length} finding(s) without a verdict: ${unaddressed.join(', ')}`)

    if (structural.length) {
      // A blocking finding rejected because the docs demand the impossible is not a
      // clean bill: converging past it ships the broken promise. The user rules.
      RESULT.escalation = buildEscalation(
        'structural-rejection',
        `Finding(s) ${structural.join(', ')} are real but were rejected as structurally unsatisfiable: the documentation demands something the implementation cannot deliver, and the demand is marked immutable.`,
        structural,
        round,
      )
      log(`ESCALATION (structural-rejection): ${RESULT.escalation.message}`)
      finishResult()
      await persistExit('escalation: structural-rejection')
      break
    }

    if (refixed().length) {
      RESULT.escalation = buildEscalation(
        'relocation',
        `Finding(s) ${refixed().map((f) => f.id).join(', ')} have now been "fixed" in more than one round — the fix is relocating the problem, not resolving it. The tree holds the latest attempt UNREVIEWED.`,
        refixed().map((f) => f.id),
        round,
      )
      log(`ESCALATION (relocation): ${RESULT.escalation.message}`)
      finishResult()
      await persistExit('escalation: relocation')
      break
    }
  }

  // Mechanical scope guard (fix E) — runs even when the fixer died, since partial
  // edits are exactly the ones nobody vouches for.
  const scopeRep = await agent(
    `Report the current change surface of the git repository at \`${GIT_ROOT}\`. Run exactly these commands and return their output verbatim as lists of repo-relative paths — do not filter, fix, or interpret anything:

  git -C "${GIT_ROOT}" diff --name-only ${BASE_SHA}
  git -C "${GIT_ROOT}" ls-files --others --exclude-standard${guardedCommands}`,
    { schema: SCOPE_SCHEMA, label: `scope:${round}`, phase: 'Fix', effort: 'low' },
  )
  if (!scopeRep) {
    RESULT.halted = 'scope-check-failed'
    notes.push(`The round-${round} scope check returned nothing. The loop halts rather than continuing unguarded.`)
    finishResult()
    await persistExit('halted: scope check failed')
    break
  }
  const violations = [...outOfScopePaths(scopeRep), ...tamperedUntracked(scopeRep)]
  if (violations.length) {
    RESULT.halted = 'scope-violation'
    RESULT.violations = violations
    notes.push(`SCOPE VIOLATION after fix round ${round}: ${violations.join(', ')} — outside ${SCOPE.join(', ')}. The loop halts here; nothing was reverted. Inspect and revert or widen args.scope, then re-run.`)
    log(notes[notes.length - 1])
    finishResult()
    await persistExit('halted: scope violation')
    break
  }
}

// ---------------------------------------------------------------------------
// Phase 5 — Finalize (convergence path only)
// ---------------------------------------------------------------------------
if (RESULT.converged) {
  // Completion requires no unregistered new files in scope: an untracked file that
  // tests silently depend on is work one `git clean` away from destruction.
  const finalScope = await agent(
    `Report the current change surface of the git repository at \`${GIT_ROOT}\`, then snapshot it. Run exactly these three commands; return the first two commands' output verbatim as lists of repo-relative paths — do not filter, fix, or interpret anything:

  git -C "${GIT_ROOT}" diff --name-only ${BASE_SHA}
  git -C "${GIT_ROOT}" ls-files --others --exclude-standard
  git -C "${GIT_ROOT}" diff ${BASE_SHA} > "${OUT}/pre-finalize.diff"

The third command writes the snapshot the finalize check diffs against; run it last and report nothing about it.`,
    { schema: SCOPE_SCHEMA, label: 'final-scope', phase: 'Finalize', effort: 'low' },
  )
  const newUntracked = newUntrackedInScope(finalScope)
  if (!finalScope) {
    RESULT.converged = false
    RESULT.halted = 'scope-check-failed'
    notes.push('The final scope check returned nothing; completion cannot be certified.')
    finishResult()
    await persistExit('halted: final scope check failed')
  } else if (newUntracked.length) {
    RESULT.converged = false
    RESULT.halted = 'untracked-files-in-scope'
    RESULT.new_untracked_files = newUntracked
    notes.push(`NOT COMPLETE: new untracked file(s) in scope: ${newUntracked.join(', ')}. Register them (git add -N) or remove them, then re-run.`)
    log(notes[notes.length - 1])
    finishResult()
    await persistExit('halted: untracked files in scope')
  } else {
    phase('Finalize')
    finishResult()
    ledger.result = RESULT
    const steps = []
    if (FINALIZE.narration_strip) {
      steps.push(`Strip session narration from every file in scope. Grep ONLY inside the scope directories under \`${GIT_ROOT}\` — never the wider filesystem or this plugin's own install directory — for these patterns (case-insensitive) and remove or rewrite each hit so the text describes the code as it is, with no history:
   - \\b(round|iteration|pass) [0-9]\\b
   - previous(ly)? (fix|attempt|version|round)
   - (was|were) (added|moved|changed|renamed|removed) (here|to|from)
   - per (the )?(review|reviewer|finding)
   Count the sites you changed as narration_sites_removed. If a hit is legitimate content (e.g. "round-trip", a changelog entry that predates this loop), leave it and do not count it.`)
    } else {
      steps.push('Narration stripping is disabled for this run; return narration_sites_removed as 0.')
    }
    if (FINALIZE.version_bump) {
      steps.push(`Exactly one version bump. The baseline plugin version was \`${baseline.plugin_version || '(not recorded)'}\`. The plugin.json inside scope must now read exactly one increment above the baseline — one bump for the whole loop, whatever the rounds did. Collapse multiple bumps; add the single bump if none happened. Return the resulting version.${MARKETPLACE_FILE ? ` \`${MARKETPLACE_FILE}\` repeats this plugin's version and is in scope: set its entry for this plugin to the identical new version. A plugin.json and a marketplace entry that disagree fail the repository's metadata validator, so half a bump is worse than none.` : ''}`)
    } else {
      steps.push('Version handling is disabled for this run (the target is not a plugin or the caller opted out). Return version as an empty string and do not touch any version field.')
    }
    if (FINALIZE.docs_pass) {
      steps.push('Docs-match-code pass: read the documentation files in scope (README, SKILL.md, and the like) and fix any statement the loop\'s changes made false. Change nothing else.')
    }
    steps.push(`LAST STEP, after all edits: snapshot what you changed so the check can read it:

  git -C "${GIT_ROOT}" diff ${BASE_SHA} > "${OUT}/post-finalize.diff"`)
    const finalize = await agent(
      `Finalize a converged improvement loop over the target at \`${TARGET}\`. The last review was clean; your job is to remove loop residue, not to improve anything further. Stay inside scope: ${SCOPE.join(', ')}. Your edits are the only ones in this run no reviewer has seen, so a scope check and a regression check run over them after you finish: rewriting content that only looked like loop residue fails the run. When a hit is arguable, leave it.

The run's ledger, for context only — the check that follows you writes it to \`${LEDGER_PATH}\`, so do not write it yourself:

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\`

${steps.map((s, i) => `${i + 1}. ${s}`).join('\n\n')}`,
      { schema: FINALIZE_SCHEMA, label: 'finalize', phase: 'Finalize' },
    )
    if (!finalize) {
      notes.push('The finalize agent died; the tree may hold partial finalize edits. The check below runs over them anyway — nobody vouches for a dead agent\'s work.')
      log(notes[notes.length - 1])
    } else {
      ledger.finalize = {
        narration_sites_removed: finalize.narration_sites_removed,
        version: finalize.version,
        notes: clip(finalize.notes, 500),
      }
    }

    // Finalize is the last agent to touch the tree, so its edits are the only ones no
    // reviewer and no scope guard has seen. Check them before the run reports success,
    // and write the run's final artifacts from here — after finalize's own outcome is
    // known, so the ledger on disk records it.
    const versionRule = FINALIZE.version_bump
      ? `\n   - a version that is not exactly one increment above the baseline \`${baseline.plugin_version || '(not recorded)'}\`${MARKETPLACE_FILE ? `, or a \`${MARKETPLACE_FILE}\` entry for this plugin that does not match plugin.json exactly` : ''}`
      : '\n   - any change to a version field: version handling was disabled for this run'
    const check = await agent(
      `The finalize pass of an automated improvement loop has just edited the repository at \`${GIT_ROOT}\` (target \`${TARGET}\`, scope ${SCOPE.join(', ')}). Verify those edits and write the run's final artifacts. You fix nothing and improve nothing: you report.

1. Change surface — run exactly these commands and return their output verbatim as lists of repo-relative paths:

  git -C "${GIT_ROOT}" diff --name-only ${BASE_SHA}
  git -C "${GIT_ROOT}" ls-files --others --exclude-standard${guardedCommands}

2. Read what finalize changed:

  diff -u "${OUT}/pre-finalize.diff" "${OUT}/post-finalize.diff"

  Both files are cumulative diffs against the baseline commit, taken before and after the pass, so their difference is exactly the finalize edits. \`diff\` exits 1 when the files differ, which is the expected case here — not an error. If \`${OUT}/post-finalize.diff\` is missing, the pass died before snapshotting: diff \`${OUT}/pre-finalize.diff\` against \`git -C "${GIT_ROOT}" diff ${BASE_SHA}\` instead. Then read the current content around every site it touched — the diff says what changed, the file says whether the result is right.

3. Report as \`regressions\` every finalize edit that must not stand, one entry per site with its file, line, and why:
   - legitimate content rewritten or deleted as loop narration: "round 2 of the tournament", "pass 1 of the parser", "iteration 3" in a documented algorithm, a changelog entry that predates this run
   - a documentation statement the pass made false, or a claim it added that the code does not support${versionRule}
   - anything outside the finalize mandate (narration strip, the version bump, docs-match-code): finalize may not refactor, re-fix, or otherwise improve the target
   An empty list means you read the finalize edits and they are all sound. This is the only check these edits get, and the run reports success on your word.

4. Write the ledger: write the following JSON verbatim (no edits, no reformatting) to \`${LEDGER_PATH}\`, and render a short human-readable \`${OUT}/ledger.md\` from it (findings table: id, severity, status, verdict reason; one row per finding; rounds summary underneath):

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\`

5. ${baseline.metrics_script ? `Run the metrics collector and report metrics_ok:\n\n  ${metricsCommand()}` : 'No metrics collector was found; return metrics_ok=false.'}`,
      { schema: FINALIZE_CHECK_SCHEMA, label: 'finalize-check', phase: 'Finalize' },
    )

    const checkViolations = [...outOfScopePaths(check), ...(check ? tamperedUntracked(check) : [])]
    const checkUntracked = newUntrackedInScope(check)
    const checkRegressions = ((check && check.regressions) || []).map((r) => ({
      file: normFile(r.file),
      line: r.line | 0,
      why: clip(r.why, 300),
    }))
    if (!check) {
      RESULT.converged = false
      RESULT.halted = 'finalize-check-failed'
      notes.push('The finalize check returned nothing. The finalize pass edited the tree and no scope check or review has seen those edits, so completion cannot be certified. Inspect the diff against the baseline and re-run.')
      log(notes[notes.length - 1])
      finishResult()
      await persistExit('halted: finalize check failed')
    } else if (checkViolations.length || checkUntracked.length) {
      RESULT.converged = false
      RESULT.halted = checkViolations.length ? 'scope-violation' : 'untracked-files-in-scope'
      RESULT.violations = checkViolations
      RESULT.new_untracked_files = checkUntracked
      notes.push(`NOT COMPLETE: the finalize pass left ${[checkViolations.length ? `out-of-scope change(s) ${checkViolations.join(', ')}` : '', checkUntracked.length ? `unregistered new file(s) in scope ${checkUntracked.join(', ')}` : ''].filter(Boolean).join(' and ')}. Nothing was reverted; inspect, revert or widen args.scope, then re-run.`)
      log(notes[notes.length - 1])
      finishResult()
      await persistExit('halted: finalize left the tree outside scope')
    } else if (checkRegressions.length) {
      RESULT.converged = false
      RESULT.halted = 'finalize-regression'
      RESULT.finalize_regressions = checkRegressions
      notes.push(`NOT COMPLETE: the finalize pass introduced ${checkRegressions.length} regression(s) the loop will not certify: ${checkRegressions.map((r) => `${r.file}:${r.line} — ${r.why}`).join('; ')}. The edits stand in the tree; revert the named sites (or re-run with narration_strip/docs_pass disabled) and re-run.`)
      log(notes[notes.length - 1])
      finishResult()
      await persistExit('halted: finalize regression')
    } else if (baseline.metrics_script && !check.metrics_ok) {
      notes.push('collect_metrics.py FAILED — metrics.json is missing or stale. The run artifacts are incomplete; the ledger is still on disk.')
      log(notes[notes.length - 1])
    }
  }
}

log(
  RESULT.converged
    ? `Converged in ${RESULT.rounds_run} review round(s), ${RESULT.fix_rounds} fix round(s). Last action: clean review.`
    : RESULT.escalation
      ? `Escalated (${RESULT.escalation.type}) at round ${RESULT.rounds_run}.`
      : RESULT.capped
        ? `CAPPED at ${MAX_FIX_ROUNDS} fix rounds, NOT converged: ${RESULT.open_blocking.length} blocking finding(s) open.`
        : `Halted: ${RESULT.halted}.`,
)

return finishResult()
