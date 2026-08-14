// Ships as /skill-improver:improve. Plugin workflows are namespaced by the plugin's
// `name` field; meta.name supplies the rest, not the filename.
export const meta = {
  name: 'improve',
  description:
    'Review→fix loop over a Claude Code skill: cross-round findings ledger, oscillation escalation, mechanical scope guard, guaranteed final clean review, finalize pass',
  whenToUse:
    'Invoked by the skill-improver skill to run the improvement loop. Pass args as a JSON OBJECT, not prose: {"skill": "/abs/path/to/skill-dir", "out": "...", "scope": ["repo/relative/glob/**"], "maxRounds": 5, "pluginRoot": "/abs/path/to/skill-improver-plugin", "decision": "..."}. skill is required. out, scope, and pluginRoot are resolved by the baseline phase when omitted. decision carries the user\'s answer to a prior escalation; a continued run reloads the on-disk ledger, so findings and verdicts survive across runs even though rounds restart.',
  phases: [
    { title: 'Baseline', detail: 'Resolve paths, snapshot git state, load any prior ledger' },
    { title: 'Review', detail: 'Reviewer reports everything with severity; the ledger verdict filters, once' },
    { title: 'Fix', detail: 'Fixer addresses blocking findings, one verdict per finding, then a scope check' },
    { title: 'Final review', detail: 'Completion requires the last action to be a review with zero blocking findings' },
    { title: 'Finalize', detail: 'Strip loop narration, exactly one version bump, metrics' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
// args = {
//   skill:      string  (required) absolute path to the skill directory (contains SKILL.md)
//   out:        string  (optional) artifact directory; defaults to <cwd>/.skill-improver/<skill-name>
//   scope:      string[] (optional) repo-relative globs the loop may touch; defaults to the
//               skill's plugin directory (or the skill directory when there is no plugin)
//   maxRounds:  number  (optional, default 5) fix-round cap; one review-only round follows it
//   pluginRoot: string  (optional) this plugin's own install directory, for scripts/collect_metrics.py
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
  const KEYS = ['skill', 'out', 'scope', 'maxrounds', 'pluginroot', 'decision']
  const CANON = { maxrounds: 'maxRounds', pluginroot: 'pluginRoot' }
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
  // A bare string with no recognizable key is the skill path.
  if (!Object.keys(out).length) out.skill = text
  if (typeof out.scope === 'string') out.scope = out.scope.split(/[,\s]+/).filter(Boolean)
  return out
}

const A = parseArgs(args)
if (!A.skill) {
  throw new Error(
    'args.skill is required: the absolute path to the skill directory (the one containing SKILL.md). ' +
      'Pass args as a JSON object, e.g. {"skill": "/path/to/plugins/x/skills/y"}.',
  )
}
const SKILL = String(A.skill)
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
  skill: SKILL,
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

const findExisting = (raw) => {
  const id = findingId(raw)
  if (ledger.findings[id]) return ledger.findings[id]
  const ck = coarseKey(raw)
  const matches = Object.values(ledger.findings).filter((x) => x.coarse === ck)
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
    const ex = findExisting(raw)
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
  return unaddressed
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
  required: ['ok', 'error', 'skill_dir', 'plugin_dir', 'plugin_version', 'git_root', 'git_initialized', 'head_sha', 'untracked', 'out_dir', 'out_rel', 'prior_ledger_json', 'metrics_script', 'default_scope'],
  properties: {
    ok: { type: 'boolean' },
    error: { type: 'string', description: 'Why the baseline could not be established; empty when ok.' },
    skill_dir: { type: 'string', description: 'Absolute path to the verified skill directory.' },
    plugin_dir: { type: 'string', description: 'Absolute path to the enclosing plugin (has .claude-plugin/plugin.json), or empty.' },
    plugin_version: { type: 'string', description: 'The version field of the enclosing plugin.json, or empty.' },
    git_root: { type: 'string', description: 'Absolute path of the repository root covering the skill.' },
    git_initialized: { type: 'boolean', description: 'True if this run created the repository.' },
    head_sha: { type: 'string' },
    untracked: { type: 'array', items: { type: 'string' }, description: 'git ls-files --others --exclude-standard, repo-relative.' },
    out_dir: { type: 'string', description: 'Absolute path of the created artifact directory.' },
    out_rel: { type: 'string', description: 'out_dir relative to git_root, or empty if outside the repo.' },
    prior_ledger_json: { type: 'string', description: 'Raw contents of <out_dir>/ledger.json if it exists, else empty.' },
    metrics_script: { type: 'string', description: 'Absolute path to collect_metrics.py, or empty if not found.' },
    default_scope: { type: 'array', items: { type: 'string' }, description: 'Repo-relative glob(s) covering the plugin (or skill) directory.' },
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
  },
}

const FINALIZE_SCHEMA = {
  type: 'object',
  required: ['narration_sites_removed', 'version', 'metrics_ok', 'notes'],
  properties: {
    narration_sites_removed: { type: 'integer' },
    version: { type: 'string', description: 'The plugin version after finalize, or empty when the target is not a plugin.' },
    metrics_ok: { type: 'boolean' },
    notes: { type: 'string' },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 — Baseline
// ---------------------------------------------------------------------------
phase('Baseline')

const RESOLVE_METRICS = A.pluginRoot
  ? `ls "${A.pluginRoot}/scripts/collect_metrics.py" 2>/dev/null`
  : `ls "$CLAUDE_PLUGIN_ROOT/scripts/collect_metrics.py" 2>/dev/null
  ls ~/.claude/plugins/cache/*/skill-improver/*/scripts/collect_metrics.py 2>/dev/null | sort -V | tail -1
  find "$HOME/.claude" . -maxdepth 7 -type f -path '*skill-improver/scripts/collect_metrics.py' 2>/dev/null | head -1`

const baseline = await agent(
  `You are establishing the baseline for an automated improvement loop over the Claude Code skill at \`${SKILL}\`. Run these steps and report exactly what you find.

1. Verify the target: \`${SKILL}/SKILL.md\` must exist. If it does not, report ok=false with the error.

2. Find the enclosing plugin: walk up from the skill directory looking for \`.claude-plugin/plugin.json\`. Report its directory and its "version" field, or empty strings if there is none.

3. Establish the git baseline: run \`git -C ${SKILL} rev-parse --show-toplevel\`. If the skill is NOT inside a git repository, initialize one — the loop's scope guard and fix verification depend on a diffable baseline:
   - Choose the root: the current working directory if the skill path is under it, otherwise the plugin directory (or the skill's parent).
   - Run \`git init\` there, then commit everything as the baseline snapshot with an explicit identity so no junk identity leaks from the machine:
     \`git -c user.name='skill-improver-baseline' -c user.email='skill-improver@trailofbits.com' commit\` (after \`git add -A\`).
   - Report git_initialized=true. This is loud on purpose: the caller must tell the user a repository was created.

4. Record the snapshot: HEAD sha (\`git rev-parse HEAD\`) and the untracked files (\`git ls-files --others --exclude-standard\`).

5. Create the artifact directory: \`mkdir -p ${A.out ? `"${A.out}"` : '"$PWD/.skill-improver/<skill-directory-name>"'}\` and report its absolute path as out_dir, plus its path relative to git_root as out_rel (empty if outside the repo).

6. Prior ledger: if \`<out_dir>/ledger.json\` exists, return its raw contents verbatim as prior_ledger_json; otherwise an empty string. Do not summarize or reformat it.

7. Locate the metrics collector. Run these in order and stop at the first that prints a path:

  ${RESOLVE_METRICS}

  Report the absolute path as metrics_script, or an empty string — do not guess.

8. default_scope: the plugin directory (or the skill directory if there is no plugin) relative to git_root, as a single glob: \`<relpath>/**\`.

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

const SCOPE = Array.isArray(A.scope) && A.scope.length ? A.scope.map(String) : baseline.default_scope || []
if (!SCOPE.length) throw new Error('no scope: pass args.scope or let the baseline derive one from the plugin directory')
const SCOPE_REGEXES = SCOPE.map(globToRegex)
ledger.scope = SCOPE
ledger.baseline = { sha: BASE_SHA, git_root: GIT_ROOT }
loadPriorLedger(baseline.prior_ledger_json, notes)
const baselineUntracked = new Set(baseline.untracked || [])

log(`Scope: ${SCOPE.join(', ')} | baseline ${BASE_SHA.slice(0, 12)} | artifacts: ${OUT}`)

// ---------------------------------------------------------------------------
// Prompt fragments
// ---------------------------------------------------------------------------
// The ledger is persisted as step 0 of every reviewer/fixer prompt, so an
// interrupt at any point leaves at most one round un-persisted on disk (the
// journal still has it). Exits with no next agent persist explicitly.
const persistBlock = () =>
  `STEP 0 — before anything else, persist the ledger for interrupt safety: use the Write tool to write the following JSON verbatim (no edits, no reformatting) to \`${LEDGER_PATH}\`:

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\``

const decisionBlock = () =>
  ledger.decisions.length
    ? `\nThe user has ruled on prior escalations, most recent last: ${JSON.stringify(ledger.decisions)}. These rulings are binding; judge related findings under them.\n`
    : ''

const metricsCommand = () =>
  baseline.metrics_script
    ? `python3 "${baseline.metrics_script}" --ledger "${LEDGER_PATH}" --repo "${GIT_ROOT}" --baseline-sha ${BASE_SHA} --diff-dir "${OUT}" --out "${OUT}/metrics.json" --tokens ${budget.spent()} ${SCOPE.map((g) => `--scope '${g}'`).join(' ')}`
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

let done = false
for (let round = 1; round <= MAX_FIX_ROUNDS + 1 && !done; round++) {
  const finalRound = round === MAX_FIX_ROUNDS + 1
  phase(finalRound ? 'Final review' : 'Review')

  const review = await agent(
    `Review round ${round}${finalRound ? ' — FINAL. This is a review-only round: no fix will follow, so report the true state.' : ''} of an automated improvement loop over the Claude Code skill at \`${SKILL}\`.

${persistBlock()}

Scope (repo-relative globs; the loop only changes files inside them): ${SCOPE.join(', ')}
${decisionBlock()}
The ledger above is the authoritative cross-round memory. Apply it:
- Findings with status "fixed" and verified=false: verify each fix by reading the current code. Return the ids that genuinely hold in verified_fixed. A fix that does not hold is re-filed under its exact ledger id.
- Findings with status "rejected": do NOT re-file them unless you have genuinely NEW evidence that the recorded verdict_reason does not cover. If you do, re-file under the same id with new_evidence=true and the new evidence in \`evidence\`.
- Findings with status "deferred" are parked; do not re-file them at the same severity.
- Reuse the exact ledger id when re-reporting any known finding, even when its line has shifted.

Now review the skill and report EVERY defect you find, each with a severity attached — including minor and informational ones. Do not withhold or pre-filter low-severity findings; filtering happens at the ledger verdict, once, not in your report.`,
    { schema: REVIEW_SCHEMA, label: finalRound ? 'final-review' : `review:${round}`, phase: finalRound ? 'Final review' : 'Review', agentType: 'skill-improver:reviewer' },
  )

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
    `Fix round ${round} of an automated improvement loop over the Claude Code skill at \`${SKILL}\`.

${persistBlock()}

Address ONLY these blocking findings (the ledger above is context — honor recorded rejections and deferrals):

\`\`\`json
${JSON.stringify(dispatched, null, 2)}
\`\`\`
${decisionBlock()}
Non-negotiable rules:
- Stay inside scope: ${SCOPE.join(', ')} (repo-relative, repo root \`${GIT_ROOT}\`). If a fix requires touching anything outside scope, do NOT make it — return verdict "rejected" with reason "requires out-of-scope change: <path>".
- NEVER run \`git checkout --\`, \`git stash\`, \`git reset\`, \`git clean\`, or \`git commit\`. The tree holds uncommitted work that is not yours.
- Return a verdict for EVERY finding listed: "fixed", "rejected" (with the reason the finding is wrong or must not be fixed), or "deferred" (minor/info only — a deferred blocker stays open).
- A fix that changes executable behavior (scripts, hooks, commands) needs a pin: a test or assertion that fails against the pre-fix code. String or severity heuristics need table pins covering the cases, not one example. Name the pin in the verdict. Prose and frontmatter fixes need no pin; the next review verifies them.
- If you create a new file, register it with \`git add -N <file>\` so the scope guard and the diff can see it.
- No narration: never write comments, docs, or commit-message-style text referencing this loop, rounds, iterations, or previous fixes.
- Never weaken a documented guarantee, threat model, or stated behavior to make a finding go away. When project docs mark a guarantee as contractual or immutable, rewording, narrowing, or deleting its text counts as weakening. If a documented demand is structurally unsatisfiable, reject the finding and say why.
- LAST STEP, after all edits: write the cumulative diff for verification:

  git -C "${GIT_ROOT}" diff ${BASE_SHA} > "${OUT}/fixes-round-${round}.diff"

  and return "fixes-round-${round}.diff" as diff_file.`,
    { schema: FIX_SCHEMA, label: `fix:${round}`, phase: 'Fix', agentType: 'skill-improver:fixer' },
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
    const unaddressed = mergeVerdicts(round, fixed, dispatched.map((d) => d.id))
    if (unaddressed.length) log(`Round ${round} fix left ${unaddressed.length} finding(s) without a verdict: ${unaddressed.join(', ')}`)

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
    `Report the current change surface of the git repository at \`${GIT_ROOT}\`. Run exactly these two commands and return their output verbatim as lists of repo-relative paths — do not filter, fix, or interpret anything:

  git -C "${GIT_ROOT}" diff --name-only ${BASE_SHA}
  git -C "${GIT_ROOT}" ls-files --others --exclude-standard`,
    { schema: SCOPE_SCHEMA, label: `scope:${round}`, phase: 'Fix', effort: 'low' },
  )
  if (!scopeRep) {
    RESULT.halted = 'scope-check-failed'
    notes.push(`The round-${round} scope check returned nothing. The loop halts rather than continuing unguarded.`)
    finishResult()
    await persistExit('halted: scope check failed')
    break
  }
  const isArtifact = (p) => OUT_REL && (p === OUT_REL || p.startsWith(`${OUT_REL}/`))
  const violations = [
    ...(scopeRep.changed || []).filter((p) => !inScope(p, SCOPE_REGEXES) && !isArtifact(p)),
    ...(scopeRep.untracked || []).filter((p) => !inScope(p, SCOPE_REGEXES) && !isArtifact(p) && !baselineUntracked.has(p)),
  ]
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
    `Report the current change surface of the git repository at \`${GIT_ROOT}\`. Run exactly these two commands and return their output verbatim as lists of repo-relative paths — do not filter, fix, or interpret anything:

  git -C "${GIT_ROOT}" diff --name-only ${BASE_SHA}
  git -C "${GIT_ROOT}" ls-files --others --exclude-standard`,
    { schema: SCOPE_SCHEMA, label: 'final-scope', phase: 'Finalize', effort: 'low' },
  )
  const isArtifact = (p) => OUT_REL && (p === OUT_REL || p.startsWith(`${OUT_REL}/`))
  const newUntracked = ((finalScope && finalScope.untracked) || []).filter(
    (p) => inScope(p, SCOPE_REGEXES) && !isArtifact(p) && !baselineUntracked.has(p),
  )
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
    const finalize = await agent(
      `Finalize a converged improvement loop over the Claude Code skill at \`${SKILL}\`. The last review was clean; your job is to remove loop residue, not to improve anything further. Stay inside scope: ${SCOPE.join(', ')}.

1. Strip session narration from every file in scope. Grep for these patterns (case-insensitive) and remove or rewrite each hit so the text describes the code as it is, with no history:
   - \\b(round|iteration|pass) [0-9]\\b
   - previous(ly)? (fix|attempt|version|round)
   - (was|were) (added|moved|changed|renamed|removed) (here|to|from)
   - per (the )?(review|reviewer|finding)
   Count the sites you changed as narration_sites_removed. If a hit is legitimate content (e.g. "round-trip", a changelog entry that predates this loop), leave it and do not count it.

2. Exactly one version bump. The baseline plugin version was \`${baseline.plugin_version || '(not a plugin)'}\`. If the target is a plugin, its plugin.json (and any marketplace entry inside scope) must now read exactly one increment above the baseline — one bump for the whole loop, whatever the rounds did. Collapse multiple bumps; add the single bump if none happened. If the target is not a plugin, skip this and return version as an empty string.

3. Docs-match-code pass: read the README and SKILL.md in scope and fix any statement the loop's changes made false. Change nothing else.

4. Write the ledger: write the following JSON verbatim to \`${LEDGER_PATH}\`, and render a short human-readable \`${OUT}/ledger.md\` from it (findings table: id, severity, status, verdict reason; one row per finding; rounds summary underneath):

\`\`\`json
${JSON.stringify(ledger, null, 2)}
\`\`\`
${baseline.metrics_script ? `\n5. Run the metrics collector and report metrics_ok:\n\n  ${metricsCommand()}\n` : '\n5. No metrics collector was found; return metrics_ok=false.\n'}`,
      { schema: FINALIZE_SCHEMA, label: 'finalize', phase: 'Finalize' },
    )
    if (!finalize) {
      notes.push('The finalize agent died. The tree is converged and reviewed, but loop residue (narration, version bumps) may remain and no metrics were collected.')
      log(notes[notes.length - 1])
    } else {
      ledger.finalize = {
        narration_sites_removed: finalize.narration_sites_removed,
        version: finalize.version,
        metrics_ok: finalize.metrics_ok,
        notes: clip(finalize.notes, 500),
      }
      if (baseline.metrics_script && !finalize.metrics_ok) {
        notes.push('collect_metrics.py FAILED — metrics.json is missing or stale. The run artifacts are incomplete; see finalize notes in the ledger.')
        log(notes[notes.length - 1])
      }
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
