export const meta = {
  name: 'triage-batch',
  description:
    'Stage 0: derive the shared context once over the whole finding set, dispatch Stage 1 per finding with it, account for every one of them by id, then check the pairs that are only exploitable together',
  whenToUse:
    'When more than one finding arrives at once — a scanner report, a bug bounty submission, an agentic discovery run. It is the only entry point that sees a second finding, so it is the only one that can find an exploit chain.',
  phases: [{ title: 'Context' }, { title: 'Triage' }, { title: 'Chains' }],
}

// args: { baseDir, scope, project, findings: [ { id, finding, entryPoint, layers,
//         layersSearched, route, crossComponent, ambiguous } ] }
//
// Two capabilities live here and nowhere else, and both are false-NEGATIVE
// guards — which is what makes this script different in kind from the other
// three. Everything in Stage 1 pushes toward dismissing a finding; the ledger
// and the chain check push back.
//
//   - THE LEDGER. The batch used to be the orchestrator's loop, so "rapid
//     analysis of the remaining bugs" was prose arguing with prose. Here a
//     finding whose sub-workflow returned nothing is REPORTED as unverified,
//     matched by id, and it cannot be silently absent from the result.
//   - THE CHAIN CHECK. Findings that individually failed a gate may combine into
//     a viable attack. Two NOT_EXPLOITABLE results whose blocking layers DIFFER
//     is the shape; the comparison needs a second finding, so no other workflow
//     in this plugin can make it.

const { baseDir, scope, project } = args || {}
// `|| []`, not a destructure default, for the reason triage-static records at
// the same line: the default only fires on `undefined`, and a null would reach
// `.slice` below and kill the run with a TypeError before `missingArgs` could
// report the one thing it exists to report.
const findings = (args && args.findings) || []

// Deliberately low. Stage 1 is ~9 agents, so five findings is ~45 agents before a
// single chain check — roughly a full sweep's spend on one dispatch. Raise it on
// evidence, not on ambition.
const MAX_FINDINGS = 5
const MAX_CHAINS = 3

const CONTEXT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['entryPoints', 'trustBoundaries', 'framework', 'recoveryDefaults', 'declaredScope', 'evidence'],
  properties: {
    entryPoints: {
      type: 'string',
      description: 'how attacker data enters this codebase: the router or dispatch table, and the handlers it reaches',
    },
    trustBoundaries: {
      type: 'string',
      description: 'where input stops being attacker-controlled: the shared middleware, authn/authz layers and validators every request passes',
    },
    framework: { type: 'string', description: 'the framework and version, and the runtime' },
    recoveryDefaults: {
      type: 'string',
      description: 'what that framework does with a panic or an uncaught exception in a handler, per its own source or docs',
    },
    declaredScope: {
      type: 'string',
      description: "the project's own statement of what it defends against, quoted, or an explicit statement that it publishes none",
    },
    evidence: { type: 'string', description: 'the files read, with paths' },
  },
}

const CHAIN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['chains', 'firstContribution', 'secondContribution', 'supplies', 'evidence'],
  properties: {
    chains: { type: 'boolean', description: 'true only when one finding supplies what the other lacks' },
    firstContribution: { type: 'string', description: 'what the FIRST finding contributes to the combined attack' },
    secondContribution: { type: 'string', description: 'what the SECOND finding contributes to the combined attack' },
    supplies: {
      type: 'string',
      description: 'the mechanism: which finding supplies which missing precondition of the other, and how',
    },
    impact: { type: 'string', description: 'what the combined attack achieves that neither achieves alone' },
    evidence: { type: 'string', description: 'the code behind the claim, quoted with file:line' },
  },
}

// Pure. A declaration that the path has no validation on it must NAME A FILE THAT
// WAS READ. Non-blankness was the whole test, so `n/a` cleared checkpoint 2.2's
// "or confirmed none exist", `decideGate`'s zero-layer guard passed on it, and
// Stage 1 reached TRUE_POSITIVE at High having dispatched zero layer agents —
// with the affirmative counter-check on the layer fan-out vacuous at zero
// against zero, so no code path in the stage established reachability at all. The
// same value then reached the impact and gate prompts as "What was read, and what
// was not found: n/a", which reads as a completed audit.
//
// This is not a new demand: SKILL.md, references/checkpoints.md and
// references/evidence-templates.md all already say "naming the files and
// functions you read". Only the validator disagreed with them. It is also the
// falsifiable half of the claim — a reviewer can open `billing/charge.py` and see
// whether it validates the rate, and cannot open `n/a`.
//
// A DENYLIST of stand-ins was refused for the reason `citedReference` refuses one
// for advisory IDs: it only knows the placeholders someone thought of, and `x`,
// `-`, `unknown` and `see above` are each one keystroke away. A length or
// word-count floor was refused because it admits "I looked everywhere and did not
// find anything" while rejecting a terse true declaration.
//
// `typeof !== 'string'` rather than `String(value || '')`: an ARRAY of filenames
// coerces to `charge.py` and would clear a rule about naming files, and
// args.test.mjs pins `['charge.py']` as a non-declaration. `{2,}` before the dot
// so `e.g.` and `i.e.` in prose are not read as filenames. Matched ANYWHERE in
// the string, exactly as `citedReference` matches: a declaration is free text,
// and anchoring would reject every real sentence.
function auditedSearch(value) {
  if (typeof value !== 'string') return null
  const named = new RegExp('(^|[^0-9a-z._-])[0-9a-z_-]{2,}[.][0-9a-z]{1,8}([^0-9a-z]|$)', 'i')
  const text = value.trim()
  return named.test(text) ? text : null
}

// Pure. The arg gate, and the first place the empty-batch vacuous pass is
// stopped: an empty `findings` array makes every loop below match nothing and
// the script would return a clean ledger having triaged nothing at all. This
// codebase has rediscovered that failure in `layers`, in `sources` and in the
// citation gate; it is the same one three times.
function missingArgs(a, maxFindings = 5) {
  // The per-entry field contract, as data rather than as nine `need` calls, so
  // tests/test_workflow_contract.py can compare it against triage-static's own
  // list. Duplicating a validator is what this repo calls drift; the pin is what
  // makes the duplication safe, and the duplication is what makes the batch fail
  // BEFORE the shared-context agent is paid for rather than after.
  //
  // Inline rather than hoisted to a module const, for the reason `selectRoute`
  // gives about its keyword list: the tests extract this function and evaluate it
  // alone, where a free variable is a ReferenceError.
  const ENTRY_FIELDS = [
    ['finding', 'summary'],
    ['finding', 'sink'],
    ['finding', 'component'],
    ['finding', 'claimedImpact'],
    ['finding', 'bugClass'],
    ['finding', 'threatModel'],
    ['entryPoint', 'description'],
    ['entryPoint', 'location'],
    ['entryPoint', 'payload'],
  ]
  const missing = []
  // Whitespace is missing. `finding.summary = '   '` satisfies a `!== ''` check
  // and then reaches every prompt as blank space, which is the `undefined`
  // failure this validator exists to stop wearing a different hat.
  //
  // The TYPE is checked for the same reason the blank is. Presence alone let
  // `finding.bugClass = {cwe: 89}` and `layers[i].name = {fn: 'validate'}` clear
  // this validator and reach six prompts as the literal text `[object Object]` —
  // the agent LABEL became `layer:[object Object]` — and the run still returned
  // TRUE_POSITIVE, from a layer agent told to inspect "[object Object] at
  // [object Object]". `baseDir` was worse: `[]`, `[null]` and `['']` are none of
  // undefined, null or a blank string, so they cleared here AND stringified to ''
  // in the shape guard below, which skips on a falsy `base` — zero problems
  // reported, every `${baseDir}/references/` read resolving under a bare
  // `/references/`, and five agents answering from memory behind a verdict that
  // looks complete.
  //
  // `kind` exists for one call site: an integer whose range is graded elsewhere.
  // Demanding a string there would reject every well-formed envelope.
  const need = (path, value, kind = 'string') => {
    const blank = typeof value === 'string' && value.trim() === ''
    if (value === undefined || value === null || blank) {
      missing.push(path)
      return
    }
    if (kind === 'string' && typeof value !== 'string') {
      missing.push(`${path} (must be a string; a value of type ${typeof value} interpolates as '${String(value)}')`)
    }
  }

  need('baseDir', a && a.baseDir)
  // The same shape check triage-static and triage-online make, for the same
  // reason: the plausible wrong value is the TARGET repo's root, every
  // `${baseDir}/references/` read then misses, and the agents answer from memory
  // with nothing in the result to show for it. Written without a regex literal
  // on purpose — the Python contract suite refuses to lex one rather than risk
  // mis-lexing it, and one here turns that suite red on unmutated code.
  //
  // Separators are normalised and a drive letter counts as absolute for the
  // reason triage-static records: the leading-slash test rejected the only value
  // that works on native Windows, so the guard sent the orchestrator back to
  // reconstruct a POSIX-shaped path that does not exist.
  const base = String((a && a.baseDir) ?? '').trim()
  const slashed = base.split('\\').join('/')
  const withoutSlash = slashed.endsWith('/') ? slashed.slice(0, -1) : slashed
  const absolute = withoutSlash.startsWith('/') || new RegExp('^[A-Za-z]:/').test(withoutSlash)
  if (base && !(absolute && withoutSlash.endsWith('/skills/fp-check'))) {
    missing.push(
      `baseDir (must be the skill directory's ABSOLUTE path, ending in skills/fp-check; got '${base}')`,
    )
  }

  need('scope', a && a.scope)
  // The bespoke string-type guard that used to sit here is gone: `need` makes the
  // same decision one line above, for every field rather than for this one.
  // Keeping it meant reporting one field twice, and — worse — a reader seeing a
  // type guard on `scope` alone could reasonably infer the other nine were
  // covered by something. They were not.

  const entries = a && a.findings
  if (!Array.isArray(entries)) {
    missing.push('findings (must be an array of at least one finding)')
    return missing
  }
  if (entries.length === 0) {
    missing.push('findings (empty; a batch of nothing returns a clean ledger having triaged nothing)')
    return missing
  }
  if (entries.length > maxFindings) {
    missing.push(
      `findings (${entries.length} supplied, at most ${maxFindings} are dispatched; split the batch rather than paying for a run that cannot cover it)`,
    )
  }

  const seen = []
  for (const [i, entry] of entries.entries()) {
    if (!entry || typeof entry !== 'object') {
      missing.push(`findings[${i}] (must be an object)`)
      continue
    }
    need(`findings[${i}].id`, entry.id)
    // The ledger is matched BY ID and the chain report names findings by id, so
    // two entries sharing one make both ambiguous — the unverified report would
    // name an id that identifies two findings, which is the same as naming
    // neither.
    const id = String(entry.id ?? '').trim()
    if (id !== '' && seen.includes(id)) missing.push(`findings[${i}].id (duplicate of an earlier id '${id}')`)
    if (id !== '') seen.push(id)

    for (const [obj, field] of ENTRY_FIELDS) {
      need(`findings[${i}].${obj}.${field}`, ((entry[obj] || {}))[field])
    }

    // The layers rule, verbatim from triage-static, because the whole point of
    // checking it here is to reject before the shared-context agent is paid for.
    // An empty list alone is the vacuous pass: a forgotten field and a deliberate
    // "nothing guards this path" are the same value, and `layersSearched` is what
    // tells them apart.
    const layers = entry.layers
    const searched = entry.layersSearched
    const declaredNone = auditedSearch(searched) !== null
    if (layers !== undefined && layers !== null && !Array.isArray(layers)) {
      missing.push(`findings[${i}].layers (must be an array)`)
    } else if (layers === undefined || layers === null || layers.length === 0) {
      if (!declaredNone) {
        missing.push(
          `findings[${i}].layers (at least one layer to inspect; if NOTHING on the path validates the payload, send layers: [] with layersSearched NAMING THE FILES you read and what you did not find)`,
        )
      }
    } else {
      for (const [j, layer] of layers.entries()) {
        // Through `need`, for the reason triage-static gives at the same loop:
        // bare truthiness admits a non-string, which reaches the child dispatch
        // and then a prompt as `[object Object]`.
        need(`findings[${i}].layers[${j}].name`, layer && layer.name)
        need(`findings[${i}].layers[${j}].location`, layer && layer.location)
      }
    }
  }
  return missing
}

const argProblems = missingArgs(args, MAX_FINDINGS)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-batch received an unusable arg shape: ${argProblems.join(', ')}. See the Batch Triage section of SKILL.md for the required fields.`,
  }
}

const roster = findings
  .map(({ id, finding, entryPoint }) =>
    `${id}: ${finding.summary}\n    component ${finding.component}, sink ${finding.sink}, entry point ${entryPoint.location}`,
  )
  .join('\n  ')

// ------------------------------------------------------------- Shared context

phase('Context')

// ONE agent, once, over the whole set. This is the phase that makes a batch
// cheaper than a loop, and the quality argument is the larger one: without it
// five findings get five independent and possibly inconsistent readings of the
// same router, the same middleware and the same framework recovery default.
//
// It is not a gate. A dead context agent degrades the children to what they do
// today — deriving it themselves — so it is logged and carried on from, never
// fatal. Failing the batch on it would trade a saving for the whole capability.
const context = await agent(
  `Establish the facts EVERY finding in this batch would otherwise re-derive. You are
not judging any of them; you are reading the codebase once so that the per-finding
analyses do not each read it again.

Project: ${project || 'not stated — describe what the code is from the code itself'}
Declared scope for this batch: ${scope}

The findings, for orientation only — do NOT assess them:
  ${roster}

Read the code and establish:
  - the entry points and the routing or dispatch table that reaches the handlers
  - the trust boundaries: the shared middleware, authentication, authorisation and
    validation every request passes before it reaches a handler
  - the framework, its version and the runtime
  - what that framework does with a panic or uncaught exception in a handler.
    ${baseDir}/references/recovery-mechanisms.md has the summary table; confirm it
    against the version actually in use here
  - what the project itself declares it defends against, quoted from SECURITY.md,
    the README or the docs. If it publishes nothing, say so — do not infer a
    security model from the code and present it as declared

State facts with file paths. Where you could not establish something, say that
rather than filling it in; an invented routing table is worse than an absent one,
because every finding in the batch then inherits it.`,
  { label: 'context', phase: 'Context', schema: CONTEXT_SCHEMA, effort: 'medium' },
)

// Pure. Flattens the context agent's return into the block forwarded to every
// child, dropping the fields it could not establish rather than passing
// `undefined` down as text. A blank field that reaches a prompt as the literal
// string 'undefined' reads to the child as an established fact.
function contextBlock(ctx) {
  if (!ctx) return ''
  const lines = [
    ['Entry points and routing', ctx.entryPoints],
    ['Trust boundaries', ctx.trustBoundaries],
    ['Framework and runtime', ctx.framework],
    ['Framework recovery default', ctx.recoveryDefaults],
    ['Declared scope and security model', ctx.declaredScope],
  ]
    .map(([label, value]) => [label, String(value ?? '').trim()])
    .filter(([, value]) => value !== '')
    .map(([label, value]) => `${label}: ${value}`)
  return lines.join('\n')
}

const shared = contextBlock(context)
if (shared === '') {
  log('shared context could not be established; each finding derives its own, as a single dispatch does')
}

// ------------------------------------------------------------------- Triage

phase('Triage')

// `pipeline`, not `parallel`. There is no cross-finding decision until the chain
// phase, so finding B's triage should start as soon as A's does rather than wait
// at a barrier for it. The barrier belongs where a decision genuinely needs every
// result — `Chains` below — and nowhere earlier.
//
// Nesting is one level: `workflow()` inside a child throws, so triage-static
// cannot call anything, and Stages 2 and 3 stay the orchestrator's decision per
// finding exactly as they are for a single dispatch.
const settled = await pipeline(findings.slice(0, MAX_FINDINGS), (entry) =>
  workflow('fp-check:triage-static', {
    baseDir,
    scope,
    context: shared,
    finding: entry.finding,
    entryPoint: entry.entryPoint,
    layers: entry.layers,
    layersSearched: entry.layersSearched,
    route: entry.route,
    crossComponent: entry.crossComponent,
    ambiguous: entry.ambiguous,
  }),
)
const live = settled.filter(Boolean)

// Pure, and the reason this workflow exists in code rather than in prose. The
// result count is checked against the DISPATCH count, matched by position — which
// is what `pipeline` preserves — and a finding whose sub-workflow returned
// nothing is reported as unverified rather than dropped.
//
// Tallying the RETURNED array instead would let a dead sub-workflow shrink the
// denominator: four of four verified, one finding gone, and nothing in the output
// showing which. That is the same fail-open triage-static records for its layer
// tally, one level up.
//
// A verdict is a NAMED status, not a non-blank one. Non-blankness counted BLOCKED
// as a verdict, and BLOCKED is this codebase's word for an analysis that did not
// RUN — triage-static returns it for a dead layer agent, a dead recovery agent, a
// dead history agent, a mis-attributed verdict list. So a batch whose every child
// refused came back BATCH_TRIAGED, "3 of 3 finding(s) verified; 0 unverified",
// with the zero-verdict guard below unable to fire because the ledger was full,
// and the one channel designed to say so empty.
function accountFindings(entries, results) {
  // An ALLOWLIST rather than a `status !== 'BLOCKED'` exclusion, for the reason
  // triage-static gives at the layer level: grading by exclusion makes a pass the
  // fall-through for any verdict this script does not recognise — a renamed
  // status, the PROCEED sentinel escaping decideGate, a Stage 2 payload
  // dispatched here by mistake. Inline rather than a module const because the
  // tests extract this function and evaluate it alone, where a free variable is a
  // ReferenceError; the same reason `ENTRY_FIELDS` and `isChainable`'s list are.
  // test_the_batch_verdict_allowlist_matches_what_stage_1_returns pins it to what
  // triage-static.js actually returns, in both directions.
  const VERDICT_STATUSES = [
    'TRUE_POSITIVE',
    'FALSE_POSITIVE',
    'NOT_EXPLOITABLE',
    'NOT_VULNERABLE',
    'NEEDS_MORE_INFO',
    'ALREADY_FIXED',
    'OUT_OF_SCOPE',
  ]
  const verified = []
  const unverified = []
  // More results than dispatches means the two lists cannot be zipped by
  // position, so no row read out of either can be trusted — including a verdict
  // that would dismiss a live finding under another finding's id.
  if (results.length > entries.length) {
    return {
      verified,
      unverified,
      problem: `${results.length - entries.length} more sub-workflow result(s) than findings dispatched; results were mis-attributed and the batch ledger cannot be trusted`,
    }
  }
  for (const [i, entry] of entries.entries()) {
    const id = String((entry && entry.id) ?? `findings[${i}]`)
    const result = results[i]
    if (!result) {
      unverified.push({ id, why: 'the sub-workflow returned nothing; this finding was never triaged' })
      continue
    }
    const status = String(result.status ?? '').trim()
    // Hoisted above the branch so the child's own sentence — "2 layer agent(s)
    // returned nothing; Stage 1c is unverified" — survives into `why`. An
    // unverified row is the orchestrator's NEEDS MORE INFO and the missing fact
    // is the deliverable; a row naming only an id is unactionable.
    const reason = String(result.reason ?? '').trim()
    if (status === '') {
      unverified.push({ id, why: 'the sub-workflow returned a payload with no status; no verdict was reached' })
      continue
    }
    if (!VERDICT_STATUSES.includes(status)) {
      unverified.push({
        id,
        why: `the sub-workflow returned ${status}, which is not a verdict: ${reason || 'no reason given'}`,
      })
      continue
    }
    // The dispatched entry rides along with the verdict because this is the ONLY
    // place the two are joined, and the chain phase downstream reads these rows
    // and nothing else. Without the join it had a status and one sentence —
    // `blocked at <layer>` on the canonical pair — with which to ask an agent
    // which precondition one finding supplies the other, while being told to
    // answer chains:false whenever it could not name the mechanism.
    //
    // `(entry || {})` rather than `entry.`: this loop is entered for the
    // `!result` and blank-status rows too, and `entry` may be a non-object in a
    // hostile arg shape. `missingArgs` rejects that already; the pattern matches
    // the defensive read the entry validator uses on the same values.
    verified.push({
      id,
      status,
      reason,
      severity: result.severity,
      finding: (entry || {}).finding,
      entryPoint: (entry || {}).entryPoint,
      result,
    })
  }
  return { verified, unverified, problem: '' }
}

const ledger = accountFindings(findings.slice(0, MAX_FINDINGS), settled)
if (ledger.problem) {
  log(`BLOCKED: ${ledger.problem}`)
  return { status: 'BLOCKED', reason: ledger.problem, unverified: ledger.unverified }
}
for (const row of ledger.unverified) {
  log(`UNVERIFIED ${row.id}: ${row.why}`)
}
// Zero verified findings is the vacuous pass in its last hiding place: a ledger
// of five unverified rows would otherwise return BATCH_TRIAGED, and a status
// with "TRIAGED" in it reads as work done.
if (ledger.verified.length === 0) {
  const why = `no finding reached a verdict: ${ledger.unverified.map((r) => `${r.id} — ${r.why}`).join('; ')}`
  log(`BLOCKED: ${why}`)
  return { status: 'BLOCKED', reason: why, findings: [], unverified: ledger.unverified }
}
log(`${ledger.verified.length} of ${findings.length} finding(s) reached a verdict.`)

// -------------------------------------------------------------------- Chains

phase('Chains')

// Pure. Only these three statuses can contribute to a chain, and the exclusions
// are the interesting half:
//   - ALREADY_FIXED pairs with nothing. It is dead, and pairing it invites the
//     chain agent to argue it back to life.
//   - NOT_VULNERABLE is intended behaviour and OUT_OF_SCOPE is a policy answer
//     that never established whether the bug is real; neither is a primitive.
//   - BLOCKED means the analysis did not run. There is nothing to compose.
//   - FALSE_POSITIVE failed one of the four gates that grade the bug, which are
//     four different reasons.
//     Reading them back out of a sentence is the string heuristic this plugin
//     has regressed on five times, so it is excluded and NAMED rather than
//     guessed at.
//
// The list is inline rather than a module const because the tests extract this
// function and evaluate it alone, where a free variable is a ReferenceError.
function isChainable(status) {
  return ['NOT_EXPLOITABLE', 'TRUE_POSITIVE', 'NEEDS_MORE_INFO'].includes(status)
}

// Pure. The blocking layers a Stage 1 return names, read out of the STRUCTURED
// layer verdicts rather than out of the `reason` sentence they were formatted
// into. Sorted so two findings stopped by the same set compare equal whatever
// order their layer agents returned in.
function blockingLayers(result) {
  return ((result && result.layers) || [])
    .filter((l) => l && l.verdict === 'PAYLOAD_STOPPED_HERE')
    .map((l) => `${l.layer} (${l.location})`)
    .sort()
}

// Pure, and the gate that keeps this phase from being O(n^2) agents. Two findings
// are paired only when one's blocking reason could plausibly supply what the
// other lacks — the selection is testable without a model, which is the whole
// point of making it a function.
function pairReason(a, b) {
  const pair = [a.status, b.status].sort().join(' + ')
  if (pair === 'NOT_EXPLOITABLE + NOT_EXPLOITABLE') {
    const first = blockingLayers(a.result)
    const second = blockingLayers(b.result)
    // Neither one names a wall, so there is nothing to compare. Paired anyway and
    // said out loud: a false positive here costs one agent, a false negative
    // loses the only false-negative guard in the plugin.
    if (first.length === 0 || second.length === 0) {
      return 'both unexploitable, and at least one names no blocking layer to compare'
    }
    // The same wall stops both, so composing them changes nothing. Different
    // walls may compose — that is the shape this whole check is for.
    if (first.join(' | ') === second.join(' | ')) return ''
    return `both unexploitable, blocked at different layers: ${first.join(', ')} versus ${second.join(', ')}`
  }
  if (pair === 'NOT_EXPLOITABLE + TRUE_POSITIVE') {
    return 'one is unexploitable for want of a reachable path, the other is confirmed and may supply one'
  }
  if (pair === 'NEEDS_MORE_INFO + TRUE_POSITIVE') {
    return 'one is missing a fact, the other has an established impact that may be that fact'
  }
  // TRUE_POSITIVE + TRUE_POSITIVE is deliberately absent: both are already
  // reportable on their own, so a chain between them recovers nothing that was
  // lost. This phase exists to catch findings that were DISMISSED and should not
  // have been.
  //
  // NEEDS_MORE_INFO + NEEDS_MORE_INFO and NEEDS_MORE_INFO + NOT_EXPLOITABLE are
  // absent for a different reason, and it is not that they could never chain. A
  // NEEDS_MORE_INFO names its missing fact only in `reason` prose: there is no
  // structured field to select on the way NOT_EXPLOITABLE gives `blockingLayers`
  // and TRUE_POSITIVE gives an established impact. Either pair could therefore
  // only be chosen on the status alone, which is the string heuristic this plugin
  // has regressed on five times. NEEDS_MORE_INFO + TRUE_POSITIVE survives because
  // it is selected on the TRUE_POSITIVE's established impact, not on the gap.
  //
  // The prescribed answer to a NEEDS_MORE_INFO is to close it and re-run Stage 1,
  // after which it becomes one of the two statuses this function CAN select on —
  // whereas a TRUE_POSITIVE will not be re-run. And both pairs spend against
  // MAX_CHAINS, which is sliced in candidate order rather than by value, so
  // admitting them displaces the two-different-walls pair the phase was built for.
  return ''
}

// Pure. Every ordered-once pair worth an agent, uncapped: the cap is applied at
// the dispatch below so that what it drops can be reported rather than silently
// vanishing, which is the mistake `beyondCap` exists for in triage-online.
function chainCandidates(verified) {
  const eligible = verified.filter((row) => isChainable(row.status))
  const pairs = []
  for (let i = 0; i < eligible.length; i++) {
    for (let j = i + 1; j < eligible.length; j++) {
      const why = pairReason(eligible[i], eligible[j])
      if (why !== '') pairs.push({ first: eligible[i], second: eligible[j], why })
    }
  }
  return pairs
}

const excluded = ledger.verified.filter((row) => !isChainable(row.status)).map((r) => `${r.id} (${r.status})`)
if (excluded.length > 0) {
  log(`not eligible to chain: ${excluded.join(', ')}`)
}

const candidates = chainCandidates(ledger.verified)
// Carried, not merely logged, for the reason triage-online records on `beyondCap`:
// a log is not something any consumer reads, and a silent cap reads as "every pair
// was checked".
const chainsBeyondCap = candidates
  .slice(MAX_CHAINS)
  .map((p) => `${p.first.id} + ${p.second.id}`)
if (chainsBeyondCap.length > 0) {
  log(`${chainsBeyondCap.length} candidate pair(s) beyond the cap of ${MAX_CHAINS} were NOT checked: ${chainsBeyondCap.join(', ')}`)
}

// Pure. What the chain agent is shown of each finding. It used to be the id, the
// status and the Stage 1 `reason` — and on the canonical pair that reason is
// `blocked at <layer> (file:line)` and nothing more, so the phase that exists to
// recover a WRONGLY DISMISSED finding was asked to compose two bugs it had never
// been shown the sink, class, entry point, payload or claimed impact of, under an
// instruction to answer chains:false whenever it could not name the supplying
// mechanism. It was the shape this phase exists for that it was least equipped to
// see.
//
// Blank fields are dropped rather than rendered, for the reason `contextBlock`
// drops them: a literal 'undefined' in a prompt reads to the agent as an
// established fact. The claimed impact is labelled UNVERIFIED because it is the
// submitter's claim, and this phase never established it.
function describe(row) {
  const finding = (row && row.finding) || {}
  const entryPoint = (row && row.entryPoint) || {}
  const facts = [
    ['bug', finding.summary],
    ['bug class', finding.bugClass],
    ['sink', finding.sink],
    ['component', finding.component],
    ['entry point', entryPoint.description],
    ['entry point location', entryPoint.location],
    ['example payload', entryPoint.payload],
    ['threat model as reported', finding.threatModel],
    ['claimed impact, UNVERIFIED', finding.claimedImpact],
  ]
    .map(([label, value]) => [label, String(value ?? '').trim()])
    .filter(([, value]) => value !== '')
    .map(([label, value]) => `\n      ${label}: ${value}`)
    .join('')
  return `${row.id} — ${row.status}: ${row.reason || 'no reason given'}${facts}`
}

const chainVerdicts = await parallel(
  candidates.slice(0, MAX_CHAINS).map((pair) => () =>
    agent(
      `Two findings were each analysed alone. Decide whether they COMBINE into an attack
that neither is on its own.

First finding
  ${describe(pair.first)}
Second finding
  ${describe(pair.second)}

Why this pair was selected: ${pair.why}

${shared || 'No shared context was established for this batch; read the code yourself.'}

A chain exists only when one finding supplies a precondition the other lacks. Name
what each contributes and the mechanism connecting them, with the code behind it.

These are NOT chains, and each is the usual way a wrong one gets reported:
  - the two findings are in the same component, or are the same bug class
  - both are serious, so together they are more serious
  - a chain that needs a third capability nobody has established
  - one finding was dismissed and the chain argument is really a rebuttal of that
    dismissal. If the dismissal was wrong, that is a re-run of Stage 1 on that
    finding with the new fact, not a chain

If either finding was dismissed, the chain must explain why the layer that stopped
it does not stop the combined attack. Quote that layer.

Answer chains: false whenever you cannot name the supplying mechanism. A pair with
no chain is the expected outcome and is not a failure of this analysis.`,
      { label: `chain:${pair.first.id}+${pair.second.id}`, phase: 'Chains', schema: CHAIN_SCHEMA, effort: 'high' },
    ).then((v) => (v ? { pair, verdict: v } : null)),
  ),
)
const chainResults = chainVerdicts.filter(Boolean)

// Pure. A chain is reported only when the agent names BOTH contributions and the
// mechanism by which one supplies what the other lacks. Without this, "these two
// are both auth bugs" comes back with chains: true and is reported as a chain —
// the `required` keyword validates PRESENCE, not content, and '' satisfies it.
//
// The two contributions must also differ. An agent that pastes one sentence into
// both fields has named one contribution, not two, and that is a structural fact
// rather than a judgement about the text.
function chainProblem(v) {
  if (!v) return 'the chain agent returned nothing'
  if (v.chains !== true) return ''
  const first = String(v.firstContribution ?? '').trim()
  const second = String(v.secondContribution ?? '').trim()
  const supplies = String(v.supplies ?? '').trim()
  const blank = []
  if (first === '') blank.push('firstContribution')
  if (second === '') blank.push('secondContribution')
  if (supplies === '') blank.push('supplies')
  if (blank.length > 0) return `a chain was claimed with ${blank.join(' and ')} empty`
  if (first.toLowerCase() === second.toLowerCase()) {
    return 'a chain was claimed with the same contribution given for both findings, so only one was named'
  }
  return ''
}

const chains = []
for (const { pair, verdict } of chainResults) {
  const problem = chainProblem(verdict)
  if (problem !== '') {
    log(`chain ${pair.first.id} + ${pair.second.id} rejected: ${problem}`)
    continue
  }
  if (verdict.chains !== true) continue
  // A status of its own, because without one the single return told the
  // orchestrator both that these two findings were false positives — SKILL.md's
  // Verdicts table maps their NOT_EXPLOITABLE straight to FALSE POSITIVE — and
  // that they compose into an attack, and the reader resolved the contradiction
  // in favour of the half that had a table row. The chain then vanished, which is
  // the exact outcome this phase exists to prevent.
  //
  // NEEDS_MORE_INFO and not TRUE_POSITIVE: the composed attack has been through
  // one agent, not Stage 1 — no impact phase, no severity arithmetic, no six
  // gates — and this phase's own prompt already says that correcting a dismissal
  // is a Stage 1 re-run rather than a chain. No severity is invented for the same
  // reason: severity here is `capSeverity` arithmetic over an impact phase that
  // never ran for the composed finding.
  chains.push({
    findings: [pair.first.id, pair.second.id],
    status: 'NEEDS_MORE_INFO',
    reason: `${pair.first.id} + ${pair.second.id} compose into an attack neither is alone: ${verdict.supplies}. Re-run Stage 1 on the composed finding with that mechanism as a given; until then neither finding may be reported on its own verdict.`,
    supplies: verdict.supplies,
    contributions: [verdict.firstContribution, verdict.secondContribution],
    impact: verdict.impact,
    evidence: verdict.evidence,
  })
  log(`CHAIN ${pair.first.id} + ${pair.second.id}: ${verdict.supplies}`)
}

// A pair whose agent died was not checked, and "not checked" must never be
// summarised as "no chain there". Matched by POSITION rather than by id, the way
// triage-online matches its dead sources: `parallel` preserves position and
// substitutes null in place.
const chainsUnchecked = candidates
  .slice(0, MAX_CHAINS)
  .filter((p, i) => !chainVerdicts[i])
  .map((p) => `${p.first.id} + ${p.second.id}`)
if (chainsUnchecked.length > 0) {
  log(`${chainsUnchecked.length} candidate pair(s) returned nothing at all: ${chainsUnchecked.join(', ')}`)
}

// Pure. Which confirmed chains name this row, labelled the way the chain rows
// label themselves so the two can be matched by eye in a report.
function chainedInto(row, confirmed) {
  return (confirmed || [])
    .filter((c) => c && (c.findings || []).includes(row.id))
    .map((c) => c.findings.join(' + '))
}

// The row's own status is left exactly as Stage 1 wrote it: rewriting a
// sub-workflow's verdict in the parent is the "argue the dismissal back to life"
// this phase's own prompt forbids, and those findings ARE unexploitable alone.
// The supersession rides BESIDE the verdict instead. The key is absent when no
// chain names the row, so its presence means something and a reader cannot take
// an empty array for a mark.
const reported = ledger.verified.map((row) => {
  const into = chainedInto(row, chains)
  return into.length > 0 ? { ...row, chainedInto: into } : row
})

const tally = `${ledger.verified.length} of ${findings.length} finding(s) verified; ${ledger.unverified.length} unverified; ${candidates.length} candidate pair(s), ${chains.length} chain(s) confirmed`
log(`Batch triage complete. ${tally}`)
return {
  status: 'BATCH_TRIAGED',
  reason: tally,
  context,
  findings: reported,
  unverified: ledger.unverified,
  chains,
  chainCandidates: candidates.map((p) => `${p.first.id} + ${p.second.id}`),
  chainsUnchecked,
  chainsBeyondCap,
  notChainable: excluded,
}
