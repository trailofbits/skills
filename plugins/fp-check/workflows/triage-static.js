export const meta = {
  name: 'triage-static',
  description:
    'Stage 1: per-layer reachability, recovery, already-fixed history, impact and severity, then the six gates as code',
  whenToUse:
    'Always, and first. Runs offline against the code in front of you and reaches a TRUE POSITIVE / FALSE POSITIVE / NEEDS MORE INFO verdict on its own. Stages 2 and 3 only narrow or correct what this returns.',
  phases: [
    { title: 'Layers' },
    { title: 'Impact' },
    { title: 'Verdict' },
  ],
}

// args: { baseDir, finding, entryPoint, layers[], scope, route }
//
// Every defensive habit below guards one specific fail-open. The comments
// recording which one are the only reason the next reader does not simplify
// them away.

// `args || {}`, not `args`. A dispatch with no args at all — a mistyped `arg:`,
// or an omitted block — makes this destructure throw before `missingArgs` can
// report anything, so the run dies with a TypeError instead of returning
// BLOCKED.
const { baseDir, finding, entryPoint, scope, layersSearched, context } = args || {}
// `|| []`, not a destructure default: the default only fires on `undefined`, and
// `missingArgs` reads a null `layers` as "none supplied" and passes it whenever
// `layersSearched` declares the absence. A null would then reach `layers.map`
// below and throw a TypeError, killing the run with no status at all — the one
// outcome this script's whole arg gate exists to prevent.
const layers = (args && args.layers) || []

// Optional, and supplied only by triage-batch: the routing table, trust
// boundaries, framework and recovery defaults, derived ONCE for a whole batch
// instead of independently by every finding's layer and recovery agents. Absent
// on a single dispatch, where those agents derive it themselves as they always
// have.
//
// Built into a labelled block here rather than interpolated raw, because a
// `context` that arrives undefined would otherwise reach the prompt as the
// literal text 'undefined' under a heading announcing it as established fact.
// Trimmed, not merely presence-checked: '   ' is a string, and a heading with
// whitespace under it says the same wrong thing.
const contextBlock =
  typeof context === 'string' && context.trim() !== ''
    ? `Shared context, already established across this batch — treat it as given and do
not re-derive it, but say so if what you read contradicts it:
${context.trim()}

`
    : ''

const MAX_LAYERS = 4

// `additionalProperties: false` on every schema. It is the only thing stopping
// an agent returning a shape this script never contracted for, and a volunteered
// key is a signal the prompt and the schema have drifted.
// test_every_schema_forbids_extra_keys pins it across all three workflows.

const LAYER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'evidence'],
  properties: {
    verdict: {
      enum: ['PAYLOAD_REACHES_SINK', 'PAYLOAD_STOPPED_HERE', 'UNCERTAIN'],
      description:
        'PAYLOAD_REACHES_SINK: the payload survives this layer and carries on. PAYLOAD_STOPPED_HERE: this layer stops it, so the finding is not exploitable',
    },
    location: { type: 'string', description: 'file:line of the check itself' },
    evidence: { type: 'string', description: 'the code, and why the payload survives or does not' },
    reason: { type: 'string' },
  },
}

// The deep-route proofs. A layer's verdict and a proof's are DIFFERENT questions
// and do not share an enum: a layer is asked what happens to the payload, a
// proof is asked whether its own argument leaves the finding alive. One enum
// across both inverts the polarity — "the payload passes" and "the bounds proof
// passes" are opposite directions of the same word.
//
// `applies` is the other field that tells them apart.
//
// A layer is ON the attack path and is always applicable — it either stops the
// payload or it does not. A proof is an auxiliary argument, and two of the three
// are asked a question that frequently does not apply at all: there is no
// algebra in a logic bug and no threading model in a synchronous one. Telling
// the agent in the prompt to answer UNCERTAIN in that case is not an enforcement
// mechanism — an agent asked "is concurrent access actually possible?" about a
// finding with no concurrency in it answers the question it was asked,
// truthfully, with the refuting verdict, and the finding is then dismissed on a
// question it never raised. The label also contradicts the agent's own reasoning
// text, so the orchestrator's rational response is to discard the whole workflow
// and report its own uncapped severity — every gate below this one included.
//
// `applies` is required so the model is asked, and read as `applies === true` so
// an omitted or non-boolean answer cannot block — the same `!== true` idiom
// `upstreamFixStands` uses on `complete`, for the same reason. The direction is
// deliberate: a proof that cannot say it applies fails toward more analysis.
const PROOF_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['applies', 'verdict', 'evidence'],
  properties: {
    applies: {
      type: 'boolean',
      description: 'false when this question is not applicable to this finding at all; a proof that does not apply cannot answer it',
    },
    verdict: {
      enum: ['FINDING_SURVIVES', 'FINDING_REFUTED', 'UNCERTAIN'],
      description:
        'FINDING_SURVIVES: this proof does not dispose of the finding. FINDING_REFUTED: this proof shows the finding cannot happen',
    },
    location: { type: 'string' },
    evidence: { type: 'string' },
    reason: { type: 'string' },
  },
}

const RECOVERY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['recoveryExists', 'effectiveImpact', 'evidence'],
  properties: {
    recoveryExists: { type: 'boolean' },
    mechanism: { type: 'string', description: 'e.g. net/http per-connection recover in conn.serve' },
    effectiveImpact: { type: 'string', description: 'the impact that survives recovery' },
    evidence: { type: 'string' },
  },
}

const THREAT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['inScope', 'byDesign', 'byDesignIndicators', 'evidence'],
  properties: {
    inScope: { enum: ['YES', 'NO', 'UNCERTAIN'] },
    byDesign: { type: 'boolean' },
    byDesignIndicators: { type: 'integer', description: 'count of the three indicator classes that fired' },
    evidence: { type: 'string' },
  },
}

// Stage 3's challenge 4 asks the same question, but Stage 3 runs only when the
// user asked for a PoC. On the cheap path — which is the default — an
// already-fixed finding would pass unexamined, so the same search runs here.
const HISTORY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['fixed', 'complete', 'reference', 'searched', 'evidence'],
  properties: {
    fixed: { enum: ['YES', 'NO', 'UNCERTAIN'] },
    // Required, and empty when nothing was found. `upstreamFixStands` branches on
    // it, and `required` is the only thing the runtime validator enforces — so
    // leaving it optional means an omitted field reads as undefined, which is the
    // same as empty here but arrives without the model having been asked. A
    // `fixed: YES` carrying an empty reference is treated as unproven: a
    // retraction has to point at something.
    reference: { type: 'string', description: 'the commit, PR, issue or advisory that fixed it; empty if none' },
    // Required for the same reason `reference` is: the two fields make the same
    // claim about the same retraction. `upstreamFixStands` reads it, and an
    // omitted one is `undefined`, which is not `false`, which reads as a WHOLE
    // fix — so a partial fix nobody flagged retracts the finding entirely.
    // Required makes the model answer instead of the default guessing.
    complete: { type: 'boolean', description: 'false for a partial fix, which is still a finding' },
    searched: { type: 'string', description: 'what was actually searched, so a null result is auditable' },
    evidence: { type: 'string' },
  },
}

const IMPACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['result', 'impact', 'rootCause', 'classification', 'severity', 'severityRationale', 'evidence'],
  properties: {
    result: { enum: ['VERIFIED', 'NOT_VERIFIED', 'DISPROVEN'] },
    impact: { type: 'string' },
    rootCause: { enum: ['internal', 'integration', 'external'] },
    externalPrecondition: { type: 'string' },
    classification: { enum: ['vulnerability', 'hardening_gap'] },
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
    severityRationale: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// The six gates from references/gate-reviews.md, flattened. Nested per-gate
// objects would put the fields `decideVerdict` branches on out of reach of
// `required`, which is the only thing the runtime validator enforces.
const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'gateProcess',
    'gateReachability',
    'gateRealImpact',
    'gatePocValidation',
    'gateMathBounds',
    'gateEnvironment',
    'unresolvedUncertainty',
    'verdictReason',
    'evidence',
  ],
  properties: {
    gateProcess: { enum: ['PASS', 'FAIL'] },
    gateReachability: { enum: ['PASS', 'FAIL'] },
    gateRealImpact: { enum: ['PASS', 'FAIL'] },
    gatePocValidation: { enum: ['PASS', 'FAIL'] },
    // The only gate with an N/A: most bugs are not bounds bugs, and forcing a
    // PASS/FAIL there would make the answer meaningless rather than absent.
    gateMathBounds: { enum: ['PASS', 'FAIL', 'N/A'] },
    gateEnvironment: { enum: ['PASS', 'FAIL'] },
    // fp-check's standard route escalates to deep "if any question produces
    // genuine uncertainty you cannot resolve". This is that signal, and
    // decideVerdict turns it into NEEDS_MORE_INFO rather than a coin-flip
    // verdict.
    unresolvedUncertainty: { type: 'string', description: 'empty when nothing is unresolved' },
    verdictReason: { type: 'string' },
    evidence: { type: 'string' },
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

// Pure. Reject an arg shape this script does not understand BEFORE spending
// agents on it. Every field named here is interpolated into a prompt below, so a
// missing one reaches an agent as the literal text 'undefined' and it spends a
// full turn reasoning about nothing — an unvalidated dispatch degrades the
// threat-model prompt to "Finding: undefined, Component: undefined, Declared
// scope: [object Object]" and the agent answers it anyway.
//
// maxLayers is a defaulted parameter rather than a reference to MAX_LAYERS
// because the tests extract this function and evaluate it in isolation, where a
// free variable would throw ReferenceError.
// test_the_layer_cap_default_matches_max_layers pins the two together.
function missingArgs(a, maxLayers = 4) {
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
  const finding = (a && a.finding) || {}
  const entry = (a && a.entryPoint) || {}

  need('baseDir', a && a.baseDir)

  // PRESENCE is not enough without SHAPE, and the shape is the larger source of
  // variance: `baseDir` is interpolated into every reference path, and the
  // plausible wrong value is the TARGET REPO's root, because that is the working
  // directory. Every read under `${baseDir}/references/` then misses — the impact
  // agent cannot open dismissal-grounds.md, the gate agent cannot open
  // false-positive-patterns.md — while the layers and the impact verdict come
  // back correct, so the degradation is invisible from the result.
  //
  // A workflow has no filesystem access, so existence cannot be checked here. The
  // SHAPE can be, and it is exactly what a wrong dispatch gets wrong: an absolute
  // path ending in the skill directory. Reported rather than silently tolerated,
  // because the failure is otherwise invisible — an agent that cannot read its
  // reference file carries on and answers from memory.
  //
  // Written without a regex literal on purpose: the Python contract suite lexes
  // these scripts to strip strings and comments, and it REJECTS a regex literal
  // rather than risk mis-lexing one (test_a_regex_literal_is_rejected_rather_than_mis_lexed).
  // One here turns that suite red on unmutated code, and its mutation gate proves
  // nothing from a baseline that is already red.
  // Still `String(... ?? '')` and not a `typeof` test, but no longer for the
  // reason it used to give: `need` now rejects a non-string baseDir one line
  // above. It is load-bearing for an ABSENT one — `undefined.trim()` would throw
  // out of the validator and kill the run with no BLOCKED result at all, which is
  // the worst shape this plugin can fail in.
  //
  // Separators are normalised and a drive letter counts as absolute because the
  // leading-slash test rejected the only value that WORKS on native Windows.
  // `C:\\Users\\...\\skills\\fp-check` failed both halves, the stage returned
  // BLOCKED, and the only path that then satisfied this guard was a POSIX-shaped
  // path that does not exist — so the guard manufactured the very failure it was
  // written to prevent, one case further down. A UNC path normalises to
  // `//server/share/...` and passes on the leading slash; `skills\\fp-check`
  // normalises to a relative path and is still refused.
  const base = String((a && a.baseDir) ?? '').trim()
  const slashed = base.split('\\').join('/')
  const withoutSlash = slashed.endsWith('/') ? slashed.slice(0, -1) : slashed
  const absolute = withoutSlash.startsWith('/') || new RegExp('^[A-Za-z]:/').test(withoutSlash)
  const shaped = absolute && withoutSlash.endsWith('/skills/fp-check')
  if (base && !shaped) {
    missing.push(
      `baseDir (must be the skill directory's ABSOLUTE path, ending in skills/fp-check; got '${base}'. Copy it from an expanded reference link rather than reconstructing it — the working directory is the TARGET repo and has no references/ in it)`,
    )
  }
  need('finding.summary', finding.summary)
  need('finding.sink', finding.sink)
  need('finding.component', finding.component)
  need('finding.claimedImpact', finding.claimedImpact)
  need('finding.bugClass', finding.bugClass)
  // The one dismissal ground that survives as a HARD requirement, and it survives
  // because it is about the dispatch rather than about the finding: a report that
  // cannot say who the attacker is, what they hold, how they trigger it and what
  // breaks is unanalysable, and every downstream stage would be guessing at the
  // threat model it is supposed to align to. Refusing an unusable arg shape is not
  // the same as dismissing a finding, which is why this is here and the other
  // grounds are guidance in references/dismissal-grounds.md.
  need('finding.threatModel', finding.threatModel)
  need('entryPoint.description', entry.description)
  need('entryPoint.location', entry.location)
  need('entryPoint.payload', entry.payload)
  // `scope` is the input the threat-model checkpoint is entirely about. Absent,
  // the best the prompt can say is "Declared scope: none declared — report
  // UNCERTAIN rather than assuming", and the workflow returns a verdict whenever
  // the agent answers YES anyway. That instruction is a prompt, and a prompt is
  // not an enforcement mechanism.
  need('scope', a && a.scope)
  // The bespoke string-type guard that used to sit here is gone: `need` makes the
  // same decision one line above, for every field rather than for this one.
  // Keeping it meant reporting one field twice, and — worse — a reader seeing a
  // type guard on `scope` alone could reasonably infer the other nine were
  // covered by something. They were not.
  // `.entries()` on a non-array throws out of the validator, so a wrong shape
  // would kill the run instead of being reported.
  const layers = a && a.layers
  // Checkpoint 2.2 passes on "identified at least 1 layer (OR CONFIRMED NONE
  // EXIST)", and an empty list on its own confirms nothing — `layers` defaults to
  // [] in the destructure, so a forgotten field and a deliberate "nothing
  // validates this path" are the same value, zero agents run, and a verdict comes
  // back having inspected nothing.
  //
  // Demanding the absence be passed AS a layer is the worse fix, not the safer
  // one. A caller told to do that sends `{name: 'rate-value validation between
  // fetch_rate and ledger.debit', description: 'No validation layer exists
  // between...'}`, and an agent asked "does this layer stop the payload?" about a
  // layer that is the absence of a layer cannot answer coherently: what comes
  // back is the stopping verdict carrying a reason that says the opposite. The
  // finding then dies at `decideGate` before the impact agent ever runs. **A
  // contract that asks for a fabrication gets one, and is then broken by it.**
  //
  // So the second half of the checkpoint gets its own input. `layersSearched` is
  // an affirmative, auditable statement of what was read and what was not found —
  // the same shape as `sourcesRead`, `searched` and `coverage` elsewhere in this
  // plugin, where a null result is acceptable precisely because it says where it
  // looked. A blank string does not satisfy it, neither does its absence, and
  // neither does `n/a` — `auditedSearch` demands it name a file that was read.
  const searched = a && a.layersSearched
  const declaredNone = auditedSearch(searched) !== null
  if (layers === undefined || layers === null || (Array.isArray(layers) && layers.length === 0)) {
    if (!declaredNone) {
      missing.push(
        'layers (Stage 1c needs at least one layer to inspect; if NOTHING on the path validates the payload, send layers: [] together with layersSearched naming the files and functions you read and what you did not find. Do not pass the absence of a check as a layer — an agent asked whether a layer that does not exist stops the payload cannot answer coherently)',
      )
    }
  } else if (searched !== undefined && searched !== null && !declaredNone) {
    // Present but not a declaration, alongside real layers. Reported rather than
    // ignored: a field that is silently dropped reads downstream as a field that
    // was answered, so the fallback it should have triggered never fires. The
    // message no longer says "empty", because this branch now fires on `n/a` too
    // and calling that empty is the same class of lie.
    missing.push('layersSearched (present but names nothing that was read; omit it, or name the files you read)')
  }
  // Reject an over-long list HERE rather than after dispatching. Failing closed
  // is only worth anything if it happens before the spend.
  if (Array.isArray(layers) && layers.length > maxLayers) {
    missing.push(
      `layers (${layers.length} supplied, at most ${maxLayers} are dispatched; narrow the attack path or split the finding rather than paying for agents that cannot cover it)`,
    )
  }
  if (layers !== undefined && layers !== null && !Array.isArray(layers)) {
    missing.push('layers (must be an array)')
  } else {
    for (const [i, layer] of (Array.isArray(layers) ? layers : []).entries()) {
      // Through `need`, so a layer whose name is an object is refused rather
      // than dispatched: bare truthiness let one through as the agent LABEL
      // `layer:[object Object]`. `layer && layer.name` keeps a null item pushing
      // the bare path, which is what the message reads best as.
      need(`layers[${i}].name`, layer && layer.name)
      need(`layers[${i}].location`, layer && layer.location)
    }
  }
  const route = a && a.route
  if (route !== undefined && route !== null && route !== 'standard' && route !== 'deep') {
    missing.push(`route (must be 'standard' or 'deep' when supplied; got '${route}')`)
  }
  return missing
}

// Pure. The standard/deep routing, decided from the dispatch rather than from
// the orchestrator's mood.
//
// This is the reason Stage 1 is not an unconditional fan-out. On a finding whose
// bug class needs none of the three extra proofs, the cheap path reaches the same
// verdict for a fraction of the spend, so "always run everything" buys nothing
// and costs several times as much. What deep adds is those three proofs, listed
// at the dispatch site — not a second opinion on the questions the standard route
// already asks.
//
// An explicit `route` wins: the user asking for full verification is one of
// fp-check's own escalation criteria.
// Built with `new RegExp` from a string rather than a regex literal: the contract
// scanner refuses to lex a literal in code position, deliberately, because
// reading one wrong blanks the rest of the file and every check below it goes
// green. A keyword list is still easier to extend than an alternation.
//
// The list is inline rather than hoisted: the tests extract this function and
// evaluate it alone, where a free variable is a ReferenceError.
function selectRoute(a) {
  if (a && a.route) return a.route
  const finding = (a && a.finding) || {}
  const layers = (a && Array.isArray(a.layers) && a.layers) || []
  // 3+ trust boundaries in the path. fp-check's first escalation checkpoint.
  if (layers.length >= 3) return 'deep'
  const bugClass = String(finding.bugClass || '').toLowerCase()
  // Keyed on the CLASS NAMES in references/bug-class-verification.md first, then
  // on the ways the same bug gets written by hand. Both halves are needed:
  // SKILL.md sends the orchestrator to that reference for the bug class, so with
  // only the hand-written spellings "Memory Corruption" — the heading it reads
  // there — takes the cheap route with no algebraic bounds proof while "buffer
  // overflow" takes the deep one. Same finding, opposite route, decided by which
  // words got typed.
  //
  // test_every_bug_class_has_a_routing_decision pins this against the reference's
  // headings, so a class added there has to be routed rather than silently
  // defaulting to standard.
  const escalates = [
    // Memory corruption: the archetypal case for the algebraic bounds proof, and
    // the allocator/API-contract question disposes of whole reports on its own.
    'memory corruption',
    'buffer overflow',
    'heap overflow',
    'stack overflow',
    'out-of-bounds',
    'out of bounds',
    'oob',
    'use-after-free',
    'use after free',
    'double-free',
    'double free',
    'type confusion',
    // Integer arithmetic. Gate 5 wants algebra, which is a separate agent's job
    // rather than a clause in the impact prompt.
    'integer',
    'overflow',
    'underflow',
    'off-by-one',
    'truncation',
    'signedness',
    'bounds',
    // Concurrency in the trigger. A race that cannot be shown to BE a race is
    // the most common false positive in the class, and it needs its own proof.
    'race',
    'racing',
    'toctou',
    'concurren',
    'deadlock',
    'atomic',
    // Denial of service: the amplification ratio and the worst-case input are
    // arithmetic, and "it is O(n^2)" asserted without them is the usual shape of
    // a wrong DoS report.
    'denial of service',
    'dos',
    // Spelled out because the word-start anchor below will not find 'dos' inside
    // 'DDoS' or 'ReDoS', which is how most of each arrive written. Both are the
    // standard spelling of their class and neither appears anywhere in the
    // references, so no pin would have caught the drop to the standard route —
    // where a ReDoS finding, which IS an algorithmic-complexity DoS, never
    // reaches the math-bounds agent the Route table escalates it for.
    'ddos',
    'redos',
    'algorithmic complexity',
    'resource exhaustion',
  ]
  // Anchored to a WORD START, in a copy of both sides where every run of
  // non-alphanumerics is one space. As raw substrings these keywords escalated on
  // letters sitting inside another word: 'race' fired on 'stack trace',
  // 'traceback' and 'grace period', so an information-disclosure finding —
  // standard in the Route table of references/bug-class-verification.md — bought
  // the deep route, where any one of the three proof agents returning nothing is
  // BLOCKED and a race-feasibility proof answers a question the finding never
  // asked.
  //
  // Only the START is anchored. 'data races', 'deadlocks' and 'atomicity' are the
  // same bug as the spelling in the list, 'concurren' is in it as a deliberate
  // prefix, and anchoring the end drops all of them. Normalising the keyword
  // through the same split is what keeps the hyphenated entries matching
  // 'out of bounds' and 'use_after_free' too.
  const words = (s) => s.split(new RegExp('[^a-z0-9]+')).filter(Boolean).join(' ')
  const spaced = ` ${words(bugClass)} `
  if (escalates.some((k) => spaced.includes(` ${words(k)}`))) return 'deep'
  if (a && a.crossComponent === true) return 'deep'
  if (a && a.ambiguous === true) return 'deep'
  return 'standard'
}

const argProblems = missingArgs(args, MAX_LAYERS)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-static received an unusable arg shape: ${argProblems.join(', ')}. See the Dispatch section of SKILL.md for the required fields.`,
  }
}

const route = selectRoute(args)

// ------------------------------------------------------- Stages 1c and 1d

phase('Layers')

// One agent per layer. Checkpoint 2.2's pass criteria are "identified every
// layer, determined pass/block/uncertain for each WITH EVIDENCE, ZERO uncertain
// layers" — a fan-out over an enumerated list, which one agent reading in a
// single pass cannot honestly satisfy.
//
// The case this shape is for is a sink that is genuinely injectable with no
// attacker-reachable path to it. A single reader names the blocking check
// reliably and still calls the finding real: naming it is not the hard part,
// being made to record a per-layer verdict against it is, because that verdict
// then decides the gate in code instead of being weighed in prose. Do not
// collapse this into one agent to save money.
const checks = [
  ...layers.map((layer, i) => () =>
    agent(
      `You are verifying ONE validation layer, independently. Do not reason about the
others.

Finding: ${finding.summary}
Entry point: ${entryPoint.description} (${entryPoint.location})
Attacker payload: ${entryPoint.payload}

${contextBlock}Layer under test: ${layer.name} at ${layer.location}
What it checks: ${layer.checks || 'determine this from the code'}

Read the actual code. Decide whether the payload above survives this layer and
reaches the next hop toward ${finding.sink}. Quote the code in your evidence.
Class-specific requirements for a ${finding.bugClass} finding are in
${baseDir}/references/bug-class-verification.md.

The verdict is about the PAYLOAD, not about the finding:
  - PAYLOAD_REACHES_SINK — it survives this layer and carries on. The finding is
    still alive as far as this layer is concerned
  - PAYLOAD_STOPPED_HERE — this layer stops it. The finding is not exploitable
  - UNCERTAIN — you cannot establish it from the code

UNCERTAIN is a legitimate answer and is preferable to a guess; it halts the
pipeline for a manual trace, which is the intended behaviour.

If the check named above turns out not to exist in the code, that is
PAYLOAD_REACHES_SINK with the absence quoted as the evidence — a layer that is
not there stops nothing.`,
      { label: `layer:${layer.name || i + 1}`, phase: 'Layers', schema: LAYER_SCHEMA, effort: 'low' },
      // This guard is the only thing standing between a dead layer agent and a
      // fail-open, and it is load-bearing rather than defensive: `{...null}` is
      // `{}`, so an unguarded spread yields `{layer, location}` with no
      // `verdict`. That object is truthy, so it survives the `.filter(Boolean)`
      // below, the missing-agent count computes to 0, and the gate reaches a
      // verdict having inspected nothing. Do not simplify it away.
    ).then((v) => (v ? { layer: layer.name || `layer-${i + 1}`, location: layer.location, ...v } : null)),
  ),
]

// Positions are recorded as the list is built rather than computed as
// `layers.length + 1`, `+ 2` and so on. The arithmetic form is what makes the
// deep-route extras dangerous to add: one off-by-one and a recovery verdict is
// read as a threat-model verdict. `additionalProperties: false` on the schemas
// catches some of those mix-ups, but only by accident of the two shapes
// differing, so the positions are recorded rather than derived.
const at = {}
const add = (key, thunk) => {
  at[key] = checks.length
  checks.push(thunk)
}

add('recovery', () =>
  agent(
    `Stage 1d, recovery mechanism check.

Read ${baseDir}/references/recovery-mechanisms.md, in particular the summary
table and the checklist before claiming a process crash.

Finding: ${finding.summary}
Claimed impact: ${finding.claimedImpact}
Vulnerable code: ${finding.sink}

${contextBlock}Determine whether a panic/exception at that location is caught by any recovery
in the call stack — language-level, framework middleware, or server built-in —
and state the impact that actually survives.

Do not assume recovery is absent because you did not find it. If the claimed
impact is a process crash, that claim requires positive evidence that nothing
recovers.`,
    { label: 'recovery', phase: 'Layers', schema: RECOVERY_SCHEMA, effort: 'medium' },
  ),
)

add('threat', () =>
  agent(
    `Threat model alignment: scope, security model, and design intent.

Read ${baseDir}/references/validation-dimensions.md.

Finding: ${finding.summary}
Component: ${finding.component}
Declared scope: ${scope}
Reported threat model: ${finding.threatModel}

Answer three things:
  Scope. Is this component explicitly in scope? Ambiguous means UNCERTAIN, not
    YES.
  Security model. Does this violate a security property the target claims, or is
    it within stated trust assumptions?
  Design intent. Check all three indicator classes: privilege identifiers,
    symmetric guarded/unguarded sibling paths, and documentation or tests
    covering it as normal operation. Report how many fired in
    byDesignIndicators. Set byDesign true only if two or more fired AND a search
    of usage and test coverage confirmed the intent — the gate reads the count,
    so byDesign: true below two does not dismiss anything. One class firing is a
    flag to check, not a verdict.

Centralized control is not by itself a vulnerability.`,
    { label: 'threat-model', phase: 'Layers', schema: THREAT_SCHEMA, effort: 'medium' },
  ),
)

add('history', () =>
  agent(
    `Has this already been fixed? Search, do not reason from the file alone.

Finding: ${finding.summary}
Vulnerable code: ${finding.sink}
Entry point: ${entryPoint.location}

Search the git log for the relevant paths (\`git log -p --\` on the sink's file
and its callers, and \`git log --grep\` for the symptom), the issue tracker,
release notes, CHANGELOG, and any published advisories. Report exactly what you
searched in \`searched\`, so a null result is auditable rather than assumed.

The fix is often NOT in the file the finding names. A caller one layer up that
now normalises, encodes or digests the value fixes the sink without touching it,
and nothing in the sink file says so. That is the shape that gets missed.

Report fixed: YES only with a concrete reference — a commit, PR, issue or
advisory ID. YES without one is downgraded to UNCERTAIN, because a retraction has
to point at something. Set complete: false for a partial fix; a partial fix is
still a finding.`,
    { label: 'history', phase: 'Layers', schema: HISTORY_SCHEMA, effort: 'low' },
  ),
)

if (route === 'deep') {
  add('api-contract', () =>
    agent(
      `Deep route only: API contracts and environmental protections.

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}

Two questions, both of which dispose of whole classes of report on their own:

  1. Do the APIs on this path carry built-in protection that prevents the alleged
     issue REGARDLESS of input? Many do — a bounded copy, a managed allocation, a
     validated return value. Read the API's contract, not its name.
  2. Do compiler, runtime, OS or framework protections prevent exploitation
     ENTIRELY, as distinct from raising the bar? Rust's safe type system prevents;
     ASLR and stack canaries raise the bar. Only the former makes this a false
     positive.

Also check whether this pattern exists elsewhere in the codebase and is handled
safely there, and whether tests cover this path. See
${baseDir}/references/false-positive-patterns.md for the API-contract and
context-blind red-flag lists.

Return FINDING_SURVIVES if no such protection exists, so the alleged issue is
still open after both questions. FINDING_REFUTED if a protection you have READ
prevents it entirely. UNCERTAIN if you cannot establish either from the code. Set
applies: false if neither question bears on this finding — no relevant API
contract and no relevant platform protection — and leave the verdict as
UNCERTAIN.`,
      { label: 'api-contract', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'medium' },
    ),
  )

  add('math-bounds', () =>
    agent(
      `Deep route only: the algebraic proof. This is fp-check's Gate 5 and nothing
else in this analysis does it.

Finding: ${finding.summary}
Sink: ${finding.sink}
Validation on the path: ${layers.length ? layers.map((l) => `${l.name} at ${l.location}`).join('; ') : `NONE. What was read, and what was not found: ${layersSearched}`}

Write the explicit algebra, using the template in
${baseDir}/references/evidence-templates.md. The form is:

    IF validation_check_passes THEN bounds_guarantee_holds

State each validated relation, then derive whether the vulnerable condition is
reachable. Concretely: if the code checks \`size >= MIN\` and \`MIN >= sizeof(hdr)\`,
then \`size - sizeof(hdr)\` cannot underflow, and the finding is mathematically
impossible rather than merely unlikely.

Return FINDING_SURVIVES if the vulnerable condition is algebraically reachable,
FINDING_REFUTED if the validation makes it impossible, UNCERTAIN if the relations
cannot be pinned down. If this is not a bounds or arithmetic finding, set
applies: false with verdict UNCERTAIN and say so in the evidence — do not invent
algebra for a logic bug. Only applies: true can end the analysis, so mis-setting
it is how a logic bug gets dismissed by an arithmetic argument that was never
made.`,
      { label: 'math-bounds', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'high' },
    ),
  )

  add('race-feasibility', () =>
    agent(
      `Deep route only: is concurrent access actually possible?

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}

A race requires proof that the value can change between check and use, by a
second actor that really exists. Establish the threading or task model first:
single-threaded initialisation and synchronised contexts cannot race, however
suggestive the code looks. For a TOCTOU claim specifically, show what modifies
the checked value between the check and the use — if it is read and used in the
same function with no external mutation possible, there is no TOCTOU.

Return FINDING_SURVIVES if the race is feasible, FINDING_REFUTED if the model
rules it out, UNCERTAIN if the threading model cannot be established. If
concurrency is not part of this finding's trigger, set applies: false with verdict
UNCERTAIN and say so. FINDING_REFUTED is reserved for a finding that DOES claim a
race and whose threading model rules it out; refuting a finding because there is
no concurrency in it at all dismisses it on a question it never asked.`,
      { label: 'race-feasibility', phase: 'Layers', schema: PROOF_SCHEMA, effort: 'medium' },
    ),
  )
}

// parallel() preserves position and substitutes null in place for a dead agent,
// so which thunk produced which result is known from the index. Slice
// positionally out of the UNFILTERED array, and only then drop the nulls.
//
// Disaggregating by shape instead — `.filter(Boolean)` then
// `results.find((r) => r.inScope)` — is a fail-open: the recovery thunk precedes
// the threat thunk, so a recovery agent that volunteers an `inScope: 'YES'` key
// wins the threat-model lookup, the real `inScope: 'NO'` verdict is discarded,
// and the workflow returns a verdict on an out-of-scope finding.
//
// The barrier is justified: the gate below is a decision over ALL layers, and a
// blocking layer skips the impact agent and both later stages entirely.
const raw = await parallel(checks)
const layerVerdicts = raw.slice(0, layers.length).filter(Boolean)

// What the fan-out established, rendered once for the three prompts that quote
// it. With `layers: []` there is no fan-out, and "All 0 validation layers were
// independently verified as passable" is worse than saying nothing: it reads to
// the impact and verdict agents as a completed check that found no obstacle,
// which is the vacuous pass arriving by the prompt instead of by the gate.
const layerSummary = layers.length
  ? `All ${layerVerdicts.length} validation layer(s) were independently verified as passable.`
  : `NO validation layer stands between the entry point and the sink — the caller declared this rather than any agent verifying it. What was read, and what was not found: ${layersSearched}`

const recovery = raw[at.recovery] || null
const threat = raw[at.threat] || null
// Downgraded here rather than at each reader, so no consumer sees the raw value.
// The history prompt promises "YES without a reference is downgraded to
// UNCERTAIN", and `upstreamFixStands` alone only refuses to ACT on such a
// retraction: the unreferenced `YES` is still interpolated verbatim into the gate
// prompt and carried in this payload to Stage 3's already-fixed challenge, so the
// retraction the code refused arrives as prose instead, in front of the two
// agents most able to act on it.
const history = downgradeUnreferencedFix(raw[at.history] || null)
const proofs = route === 'deep'
  ? [
      { key: 'api-contract', verdict: raw[at['api-contract']] || null },
      { key: 'math-bounds', verdict: raw[at['math-bounds']] || null },
      { key: 'race-feasibility', verdict: raw[at['race-feasibility']] || null },
    ]
  : []

// Pure. Checkpoint 5.1 challenge 4's rule — "a fix exists -> DO NOT SUBMIT, and
// this outcome overrides everything else" — applied at Stage 1c so it also holds
// on the cheap path. Stage 3 enforces the same rule over its challenge verdicts,
// as `alreadyFixedStands`.
//
// Pure. What counts as a citation, for both stages' already-fixed rule.
// Duplicated verbatim in triage-poc.js, where challenge 4's `reference` is held
// to the same test: these scripts have no module system, and the alternative to
// two copies is two rules that drift apart.
//
// A citation is a TOKEN of a recognisable shape — a sha, `#412`, `CVE-2024-1234`,
// `GHSA-jf85-cpcp-j695`, a release tag, a URL. Not "non-blank", which accepts
// `n/a`, `unknown commit`, `see evidence` and `TBD` — the stand-ins an agent
// reaches for when it has no citation — and not "contains a digit", which accepts
// `see evidence at auth.py:31` and `fixed sometime in the 2.x line` while
// REFUSING an all-hex-letter short sha like `deadbeef`. Wrong in either direction
// loses a finding: a stand-in retracts a live bug terminally, and a refused sha
// reports a dead one.
function citedReference(value) {
  // `new RegExp` from strings rather than regex literals: the contract suite
  // lexes these scripts and rejects a bare `/` in code position, because reading
  // a regex as a division silently blanks the rest of the file and turns every
  // check built on that text green.
  //
  // Matched ANYWHERE in the string, bounded by non-identifier characters, rather
  // than split on whitespace with each token anchored. Anchoring rejects every
  // ordinary wrapper a citation arrives in: `openssl/openssl#12345` — the
  // canonical cross-repo form, and the one a fix in an upstream dependency takes —
  // `torvalds/linux@a1b2c3d`, a backticked sha, `<https://...>`, a markdown link,
  // and `PR 4521`. A rejection here is not harmless in either direction: Stage 1
  // writes a note saying no reference was given and reports an already-fixed bug
  // as live, and Stage 3 turns a genuine retraction into NEEDS_MORE_INFO.
  //
  // A BARE number is deliberately not a citation. `4521` is indistinguishable
  // from a line number or a year, and admitting it makes "fixed in 2021" a
  // reference; the keyword form (`PR 4521`, `issue 1234`) carries the context
  // that tells them apart. For the same reason a dotted version needs either a
  // `v` or two dots, so that `v3` and `2.3.1` are citations and `2021.03` is not.
  const bound = '(^|[^0-9a-z])'
  const forms = new RegExp(
    [
      // a commit sha, alone or qualified by the repo it belongs to
      bound + '[0-9a-f]{7,40}([^0-9a-z]|$)',
      // #412, owner/repo#412, and GitLab's merge-request form !412 — the same
      // shorthand with the other sigil, and the only thing a fix that landed in a
      // GitLab MR has to cite. In the shared class rather than a branch of its
      // own so `group/project!412` is reached the way `openssl/openssl#12345`
      // already is.
      '[0-9a-z._-]*[#!][0-9]+',
      // Advisory IDs, recognised by REGISTRY NAME rather than by shape. Every
      // available shape rule mis-classifies in both directions: "one hyphen and
      // a digit" makes `internal-fix-2` and `fixed in a post-2020 refactor`
      // advisory IDs and retracts live findings; "the last segment ends in a
      // digit" throws out roughly one real GHSA ID in twenty; "every segment is
      // four or more characters" throws out `PYSEC-2021-19`, `OSV-2021-9`,
      // `DSA-4879-1` and `USN-5678-1` — writing "no reference given" over a
      // correct citation and reporting a fixed bug as live. A shape cannot tell
      // an ID from an English phrase because registries did not agree on one. An
      // allowlist is honest about what it knows: a name it has never heard of is
      // not silently promoted, and a name it has is matched against that
      // registry's actual ID grammar.
      //
      // GHSA is its own branch because its shape is documented and unlike the
      // rest: exactly three four-character segments over the alphabet
      // `23456789cfghjmpqrvwx`, in which a digit is common but not guaranteed —
      // `GHSA-vqqm-hhhc-jqhw` carries none at all.
      bound + 'ghsa(-[0-9a-z]{4}){3}',
      // CVE-2024-1234, RUSTSEC-2021-0093, PYSEC-2021-19, OSV-2021-9,
      // GO-2022-0603, DSA-4879-1, USN-5678-1, DLA-2571-1, ZDI-21-1234,
      // ALSA-2021:9106. Each of these numbers its first segment — a year or a
      // bulletin number — which is what separates the ID from the prose: `go` is
      // in the list, and `go-to-market-2` still fails because `to` is not a
      // number.
      //
      // The list is INCOMPLETE by construction, and every name missing from it is
      // the false REJECT this comment already names. It shipped carrying `alsa`
      // and `elsa` — the AlmaLinux and Oracle REBUILDS of a Red Hat erratum —
      // without `rhsa`, the original both rebuild, and refused `MFSA-2021-24` and
      // `SUSE-SU-2021:1234` outright, so bugs those advisories had already fixed
      // were reported as live. A name it still has not heard of is not silently
      // promoted; what makes that survivable is the note in
      // `downgradeUnreferencedFix`, which quotes the string it was handed instead
      // of claiming nothing was offered. SUSE numbers a two-letter advisory KIND
      // (`SU` security, `RU` recommended) before the year, so it needs `[a-z]{2}`
      // where the others need nothing, and `openSUSE` is a registry name rather
      // than a prefix on one — the `open` is inside the group because `bound`
      // refuses to reach `suse` through the `n`.
      //
      // One physical line, and that is load-bearing rather than a style choice:
      // mutation-gate.sh's "the registry allowlist reverts to a shape rule"
      // mutant matches `bound + '(cve|` and its whole alternation with a single
      // pattern, and a wrapped form makes that mutation a no-op the gate scores
      // as SURVIVED.
      bound + '(cve|rustsec|pysec|osv|go|dsa|usn|dla|zdi|mal|alsa|elsa|talos|rhsa|rhba|cesa|glsa|mfsa|mgasa|fedora|asa|ssa|vmsa|icsa|(open)?suse-[a-z]{2})[-:][0-9]+[-:][0-9a-z]+',
      // v3, v2.3.1, 2.3.1. The trailing lookahead refuses a version that some
      // other component hangs off: a FILENAME (`src/handlers/auth-v2.go:118`)
      // and equally a PATH SEGMENT (`api/v1/handlers.go:40`), both of which are
      // the bare file:line challenge 4's own prompt names as a NON-citation, and
      // without the lookahead the `v1` inside satisfies a consuming boundary
      // group. `[.][0-9a-z]`, not `[.][a-z]`, because the branch BACKTRACKS:
      // refusing `v1.2` in `api/v1.2/x.go` only makes the engine retry `v1`,
      // whose next character is a `.` followed by a DIGIT. A separator is
      // refused only AFTER the version, never before it — `refs/tags/v1.4.0` and
      // `release/v1.4.0` reach a real release tag through a `/`. FOUR
      // backslashes, not two: the string literal halves them, and with two the
      // `\]` escapes the closing bracket, the class runs on, and `api/v1/`,
      // `a/b/v10/c.ts:3` and the Windows path quietly come back — a slip the
      // NOT_CITATIONS table below is the fixture for.
      bound + '(v[0-9]+([.][0-9]+)*|[0-9]+([.][0-9]+){2,})(?![0-9a-z/\\\\]|[.][0-9a-z])',
      // PR 4521, issue #1234, release 3, gh-1234, bpo-40501 — the last a
      // two-token tracker ID that no other branch here could reach.
      bound + '(pr|pull|issues?|bug|bpo|ticket|gh|release)[ #-]+[0-9]+',
      // pull/882 and issues/1234, which is how GitHub shorthand is written. The
      // keyword may NOT be reached through a path separator, and that is the
      // whole difference between this branch and the one above it: with `/` in
      // the shared separator class, `src/bug/12.go` and `tests/issues/42/repro.py`
      // are both citations, contradicting this function's own rule that a bare
      // `file:line` is not one. Inside a full URL the `https?://` branch already
      // matches, so nothing is lost by refusing the path form here.
      //
      // Deliberately NOT the same keyword list as the branch above: `bpo` is
      // there and not here because `bpo/40501` is not a form anyone writes, and
      // two adjacent near-identical lists invite a future "sync" that would
      // admit it.
      '(^|[^0-9a-z/])(pr|pull|issues?|bug|ticket|gh|release)/[0-9]+',
      'https?://[^ ]',
    ].join('|'),
    'i',
  )
  const ref = String(value || '').trim()
  return forms.test(ref) ? ref : null
}

// Pure. `fixed` canonicalised, because case and whitespace are not meaning and
// `enum` is advisory to the runtime validator. A case-exact compare turned OFF
// the retraction and its compensating downgrade at once — one predicate gates
// both — so `fixed: 'Yes'` with a real commit sha shipped an already-fixed bug
// as TRUE_POSITIVE, and `reference` reaches no prompt on that path, so no agent
// downstream could catch it either.
//
// The fallback is UNCERTAIN rather than a looser match, and that is the whole
// point of the exactness: `YES` is the answer that RETRACTS a finding, so
// anything this cannot read falls to the side that keeps analysing.
// `YES, in the unstable branch only` is refused for that reason rather than
// matched on its first word.
//
// `typeof !== 'string'` rather than coercing, for the reason `auditedSearch`
// refuses to coerce one field up, and here the cost is higher: `String(...)` read
// `['YES']` and any object with a `toString` as the retraction, so a `fixed` that
// arrived as an ARRAY — which `type` being advisory makes reachable — took a live
// finding out terminally as ALREADY_FIXED. An off-TYPE answer is no more readable
// than an off-enum one and falls to the same side.
function fixedAnswer(historyVerdict) {
  const raw = historyVerdict && historyVerdict.fixed
  if (typeof raw !== 'string') return 'UNCERTAIN'
  const answer = raw.trim().toUpperCase()
  return answer === 'YES' || answer === 'NO' ? answer : 'UNCERTAIN'
}

// `fixed: YES` with no CITED reference is NOT a retraction. Schema `required`
// checks presence, not content, so `reference: ''` validates; and an
// unreferenced retraction is the one failure mode that silently discards a real
// finding rather than merely reporting a false one.
function upstreamFixStands(historyVerdict) {
  if (!historyVerdict || fixedAnswer(historyVerdict) !== 'YES') return null
  const ref = citedReference(historyVerdict.reference)
  if (!ref) return null
  // `!== true`, not `=== false`. Only an affirmative "this fix is complete"
  // retracts, because the caller treats a non-partial fix as terminal: with
  // `=== false`, an omitted flag is `undefined`, which is not `false`, so a
  // PARTIAL fix that nobody flagged retracts the whole finding — the same silent
  // discard the `reference` check above exists to stop, one field over.
  // A fix flagged partial is not lost: the impact prompt is told about it and the
  // analysis continues against what remains.
  const partial = historyVerdict.complete !== true
  return {
    reference: ref,
    partial,
    evidence: String(historyVerdict.evidence || '').trim() || `fixed by ${ref}`,
  }
}

// Pure. The downgrade the history prompt promises, performed, and the single
// place `fixed` is canonicalised. Applied once, at the assignment, so
// `history.fixed` is the same value everywhere it is read — the impact prompt's
// inconclusive branch, the gate prompt, and the payload Stage 3 forwards to its
// already-fixed challenge. The note rides on `searched` because that is the
// field printed beside `fixed` in both prompts.
//
// The canonical answer is returned on EVERY path, not only the downgraded one:
// returning the verdict untouched left `Yes` and `MAYBE` to reach both prompts
// as the agent typed them, where the impact prompt's `=== 'UNCERTAIN'` branch
// fires for neither and the reader is left to assume the search came back clean.
//
// Two ways to fail the citation test, two notes, because they need different
// work from the reader. `upstreamFixStands` returns null both when `reference`
// was blank and when it held something `citedReference` did not recognise, and
// one note over both asserted that no reference was given whenever one was —
// which is what it wrote for every registry the allowlist had not heard of.
// `reference` is interpolated into no prompt of its own, so that note is the
// only channel it has: the string it would take to check the claim by hand was
// exactly the string the note threw away, and the gate agent — the one party
// able to catch the mistake — was told there was nothing to check.
function downgradeUnreferencedFix(historyVerdict) {
  if (!historyVerdict) return historyVerdict
  const answer = fixedAnswer(historyVerdict)
  if (answer !== 'YES' || upstreamFixStands(historyVerdict)) return { ...historyVerdict, fixed: answer }
  const given = String(historyVerdict.reference || '').trim()
  const why = given
    ? `reported fixed: YES citing "${given}", which citedReference does not recognise as a commit, PR, issue or advisory — check it by hand rather than reading this as nothing having been offered`
    : 'reported fixed: YES with no commit, PR, issue or advisory reference'
  return {
    ...historyVerdict,
    fixed: 'UNCERTAIN',
    searched: `${String(historyVerdict.searched || '').trim() || 'nothing recorded'} (the agent ${why}, so it is UNCERTAIN: a retraction has to point at something)`,
  }
}

// Checkpoint 2.2's gate, as a pure function so it can be graded without a model.
//
// attemptedLayers is how many layer agents were dispatched. A verdict list
// shorter than that means agents died, and a gate that inspected nothing must
// not report a verdict.
function decideGate(verdicts, recoveryVerdict, threatVerdict, historyVerdict, attemptedLayers, layersSearched) {
  const where = (ls) => ls.map((l) => `${l.layer} (${l.location})`).join(', ')

  // Zero dispatched layers is the vacuous pass UNLESS the caller declared it: no
  // stopping verdict to find and no UNCERTAIN to find, so every filter below
  // matches nothing and the function falls through to PROCEED having inspected
  // nothing.
  //
  // The declaration is what tells the two apart, and it is read through the same
  // `auditedSearch` the arg validator reads it through — a statement naming a file
  // that was read. Anything else, including a forgotten `layers` field and a
  // placeholder such as `n/a`, is still the vacuous pass and still BLOCKED. This
  // is the checkpoint's own "or confirmed none exist", which is unreachable unless
  // there is a way to say it other than inventing a layer.
  const declaredNone = auditedSearch(layersSearched) !== null
  if (attemptedLayers === 0 && !declaredNone) {
    return {
      status: 'BLOCKED',
      reason: 'no validation layers were inspected; Stage 1c cannot pass on zero evidence',
    }
  }

  // Counted, not tested for zero yet: the two signs are two different failures
  // and they do not belong at the same precedence. `> 0` alone lets a negative
  // difference slip silently past a check meant to catch a missing verdict;
  // `!== 0` catches both by collapsing them to one rank, which is the opposite
  // error, for the reason the next two blocks give.
  const missing = attemptedLayers - verdicts.length

  // MORE verdicts than agents dispatched first, and above everything else: some
  // verdict in this list came from something that is not a layer, so no verdict
  // read out of it can be trusted — including a BLOCKS, which would dismiss a
  // live finding on evidence that was mis-attributed to it.
  if (missing < 0) {
    return {
      status: 'BLOCKED',
      reason: `${-missing} more layer verdict(s) than agents dispatched; results were mis-attributed and Stage 1c cannot be trusted`,
    }
  }

  // The layer verdicts are decided BEFORE every "did that agent run" check, and
  // the order is load-bearing. A blocking layer means the finding is unreachable
  // whatever recovery, the threat model or the git history say, so it outranks a
  // dead sibling agent: with the liveness checks first, a firm NOT_EXPLOITABLE
  // degrades to "could not determine" whenever the recovery agent happens to die,
  // throwing away the answer the fan-out has already found.
  //
  // The missing-LAYER-agent count is such a check, and it sits BELOW this filter
  // for the same reason: above it, the same discarding happens whenever a sibling
  // LAYER agent dies, which is the likeliest death of all — there are up to four
  // of them. The layers are conjunctive (a PROCEED needs the payload to survive
  // every one), so one that stops the payload settles reachability on its own and
  // the dead sibling cannot overturn it.
  const blocked = verdicts.filter((l) => l.verdict === 'PAYLOAD_STOPPED_HERE')

  // A referenced, complete upstream fix outranks the blocking layer. Both
  // outcomes retract the finding, so the order cannot make a false positive
  // easier to report — only the REASON the orchestrator relays changes, and one
  // of the two reasons is strictly better.
  //
  // The two coincide constantly, because the usual shape of an already-fixed
  // finding is a fix one layer up that a layer agent then correctly reports as
  // stopping the payload. `blocked at _digest (auth.py:31)` does not tell the
  // reader the bug is dead upstream, and it cites nothing they can go and read;
  // `already fixed by <commit>` does both. The blocking layer is named in the
  // reason too, so nothing is lost.
  const fix = upstreamFixStands(historyVerdict)
  if (fix && !fix.partial) {
    return {
      status: 'ALREADY_FIXED',
      reason:
        `already fixed by ${fix.reference} — ${fix.evidence}.` +
        `${blocked.length ? ` The path is also blocked at ${where(blocked)}.` : ''}` +
        ' Retract rather than report at a lowered severity.',
    }
  }

  if (blocked.length > 0) {
    return { status: 'NOT_EXPLOITABLE', reason: `blocked at ${where(blocked)}` }
  }

  // No layer decided the path, so a dead one is the answer: Stage 1c ran on
  // partial evidence and cannot pass.
  if (missing > 0) {
    return {
      status: 'BLOCKED',
      reason: `${missing} layer agent(s) returned nothing; Stage 1c is unverified`,
    }
  }

  // NEEDS_MORE_INFO rather than BLOCKED, and the distinction is the whole reason
  // the third verdict exists. BLOCKED means this analysis could not be RUN — a
  // contract violation, a dead agent. NEEDS_MORE_INFO means it ran and the
  // evidence does not decide. An UNCERTAIN layer is the second: the code is
  // there, it was read, and it could not be traced. Reporting that as a failure
  // of the harness sends the reader to the wrong place, and rounding it to
  // FALSE POSITIVE loses real findings.
  const uncertain = verdicts.filter((l) => l.verdict === 'UNCERTAIN')
  if (uncertain.length > 0) {
    return { status: 'NEEDS_MORE_INFO', reason: `unresolved layers: ${where(uncertain)}` }
  }

  // Read the affirmative value. Grading by exclusion — anything not stopped and
  // not UNCERTAIN — makes a pass the fall-through for any verdict this script
  // does not recognise, on the checkpoint that decides reachability.
  const passed = verdicts.filter((l) => l.verdict === 'PAYLOAD_REACHES_SINK')
  if (passed.length !== attemptedLayers) {
    return {
      status: 'BLOCKED',
      reason: `${attemptedLayers - passed.length} layer(s) returned no PAYLOAD_REACHES_SINK verdict; Stage 1c is unverified`,
    }
  }

  // Now the "did this agent run at all" checks. Stage 1d passes on "checked for
  // recovery (not assumed absent)", and a dead recovery agent means it was not
  // checked — the impact prompt would say "not established" and carry on,
  // assuming absence by another route.
  if (!recoveryVerdict) {
    return { status: 'BLOCKED', reason: 'recovery agent returned nothing; Stage 1d unverified' }
  }
  if (!threatVerdict) {
    return { status: 'BLOCKED', reason: 'threat-model agent returned nothing; scope and design intent unverified' }
  }
  // The already-fixed search is the cheap path's only guard against reporting a
  // bug that was fixed upstream, so a dead agent there is a blocker rather than a
  // shrug.
  if (!historyVerdict) {
    return { status: 'BLOCKED', reason: 'already-fixed history agent returned nothing; Stage 1c unverified' }
  }

  // The retraction itself is decided above, before the blocking-layer filter,
  // for the reason recorded there. It is gated on a reference existing, so it
  // cannot become a cheap escape hatch, and a `historyVerdict` of null reaches
  // the liveness blocker just above rather than falling through as "nothing was
  // fixed".

  // These reasons are taken straight from an agent, and JSON Schema `required`
  // checks presence, not content — `evidence: ''` validates. Without the
  // fallback the orchestrator relays "OUT_OF_SCOPE:" with nothing after it.
  const why = (fallback) => String(threatVerdict.evidence || '').trim() || fallback
  if (threatVerdict.inScope === 'NO') {
    return { status: 'OUT_OF_SCOPE', reason: why('threat-model agent reported out of scope but gave no evidence') }
  }
  // `!== 'YES'` rather than a list of the two values that block. The rule is
  // "ambiguous means UNCERTAIN, not YES", and grading by exclusion implemented
  // the opposite — anything that was not NO or UNCERTAIN became YES.
  if (threatVerdict.inScope !== 'YES') {
    return { status: 'NEEDS_MORE_INFO', reason: 'scope ambiguous; the declared scope does not settle whether this component is covered' }
  }
  // The COUNT gates this, not the boolean: returning NOT_VULNERABLE on the
  // boolean alone is the self-reported gate this plugin exists to replace.
  // validation-dimensions.md and checkpoint 3.3 both set the bar at "two or more,
  // plus a search", and the two fields routinely disagree — an agent will report
  // `byDesign: true, byDesignIndicators: 1` beside evidence reading "Count = 1/3.
  // Below the 'two or more' bar, so this is not a by-design dismissal on
  // indicators alone", the prose right and the boolean dismissing anyway. Below
  // the bar this is a flag to check, not a verdict, so the analysis continues
  // rather than halting.
  if (threatVerdict.byDesign && Number(threatVerdict.byDesignIndicators) >= 2) {
    return { status: 'NOT_VULNERABLE', reason: why('threat-model agent reported by-design but gave no evidence') }
  }

  return { status: 'PROCEED', reason: '' }
}

const gate = decideGate(layerVerdicts, recovery, threat, history, layers.length, layersSearched)

if (gate.status !== 'PROCEED') {
  log(`${gate.status}: ${gate.reason}`)
  return {
    status: gate.status,
    reason: gate.reason,
    route,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
  }
}

// Pure. Which deep-route proofs actually block the finding.
//
// Two rules:
//
// `applies === true`, not merely truthy and not defaulted. A proof that says the
// question does not bear on this finding has not answered it, and an omitted or
// non-boolean flag reads as "did not say", which cannot block. Same `!== true`
// idiom as `upstreamFixStands`' `complete`, in the same direction: unsure means
// keep analysing.
//
// The result is CARRIED rather than terminal. A layer is on the attack path and
// is conjunctive with its siblings — one that stops the payload settles it. A
// proof is an auxiliary argument by a single agent that saw one question, and
// making it terminal puts it above the impact stage, the severity cap and the six
// gates, none of which then run. `gateMathBounds` and `gateEnvironment` are those
// same two questions asked again with all the evidence in view, so routing a
// blocking proof to them produces a verdict that names the gate it failed
// instead of naming the agent that raised its hand first.
//
// This cannot make a false positive easier to report: a blocking proof still
// forbids TRUE_POSITIVE in code at the verdict, so the softest outcome available
// is NEEDS_MORE_INFO carrying the proof's own evidence.
function blockingProofs(proofs) {
  return (proofs || [])
    .filter((p) => p && p.verdict && p.verdict.applies === true && p.verdict.verdict === 'FINDING_REFUTED')
    .map((p) => ({
      key: p.key,
      title: p.key,
      what: String(p.verdict.evidence || '').trim() || 'proof reported BLOCKS with no evidence',
    }))
}

const blockingProof = blockingProofs(proofs)
if (blockingProof.length > 0) {
  log(
    `${blockingProof.length} deep-route proof(s) block and are carried to the verdict: ${blockingProof
      .map((p) => p.key)
      .join(', ')}`,
  )
}

// A dead proof agent is the deep route not having run, and it fails closed for
// the same reason decideGate blocks on a dead recovery, threat-model or history
// agent: these three ARE the escalation. Nothing else in this workflow writes the
// algebraic bounds proof or establishes the threading model, so a null read as
// "did not block" pays for the deep route and enforces none of it — the finding
// reaches the six gates with the extra evidence missing and only a line of prose
// telling the gate agent so, which is the self-report the deep route exists to
// replace.
//
// UNCERTAIN is not a death — two of the three are asked a question that often does
// not apply and set `applies: false` — so only a missing verdict blocks.
const deadProofs = proofs.filter((p) => !p.verdict).map((p) => p.key)
if (deadProofs.length > 0) {
  const why = `${deadProofs.join(', ')} returned nothing; the deep route was selected for those proofs and they are the only thing it adds`
  log(`BLOCKED: ${why}`)
  return {
    status: 'BLOCKED',
    reason: why,
    route,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
  }
}

// ------------------------------------------------------------- Stage 1e

phase('Impact')

const impact = await agent(
  `Impact verification, root cause attribution, exploitability classification, and
severity.

Finding: ${finding.summary}
Originally claimed impact: ${finding.claimedImpact}
Recovery finding: ${recovery.recoveryExists ? 'recovery EXISTS' : 'no recovery found'} — ${recovery.effectiveImpact}
${layerSummary}
${history.fixed === 'UNCERTAIN' ? `History search was inconclusive: ${history.searched}` : ''}
${upstreamFixStands(history) ? `A PARTIAL fix exists (${upstreamFixStands(history).reference}); report what remains, not the original claim.` : ''}
${blockingProof.length ? `Deep-route proof(s) reporting that the finding is impossible. They were carried\nrather than made terminal; weigh them against the traced path:\n  ${blockingProof.map((p) => `${p.key}: ${p.what}`).join('\n  ')}` : ''}

Verify the claimed impact against evidence. If recovery downgrades it, the
verified impact is the downgraded one, not the original claim.

  \`result\` grades whether ANY impact is established by evidence. It does NOT
  grade whether the reported claim survived intact:
    VERIFIED     an impact is established. Put the impact the evidence supports
                 in \`impact\` — it may be far smaller than what was claimed. A
                 real bug reported at inflated severity is VERIFIED with the
                 corrected impact. Downgrading is what this asks you to do, not
                 a reason to fail it.
    NOT_VERIFIED no impact could be established either way on the evidence
                 available.
    DISPROVEN    the evidence positively shows there is no impact.
  Only VERIFIED continues, so grading a real-but-smaller impact as NOT_VERIFIED
  discards a genuine finding.

Attribute the root cause: internal, integration, or external. If it is not
internal, state the external precondition the attack requires.

Classify: does the code DO something it should not (vulnerability), or LACK
something it should have (hardening gap)?

Then set a severity and justify it on impact and exploitability both. An
integration or external root cause caps severity at Medium, and a hardening gap
is not written up as an exploited vulnerability — those caps are applied in code
after you answer, so a rating above them is corrected rather than accepted.

Before you settle on \`vulnerability\`, read
${baseDir}/references/dismissal-grounds.md. It is the list of recurring reasons a
reported finding turns out not to be one — the attacker already holds what the
exploit grants, the behaviour is specified, the project documents and warns about
it, the cure is worse than the disease. **Those are grounds for judgement, not
tests that end anything**, and you are the first agent with the traced path in hand,
so you are the first who can apply them honestly. Note especially that "the trigger
comes from outside this repository" is an external precondition to state and a
severity to cap — not a reason the bug is imaginary.

See ${baseDir}/references/checkpoints.md for the pass criteria of each, and
${baseDir}/references/bug-class-verification.md for what a ${finding.bugClass}
finding specifically has to establish.`,
  { label: 'impact', phase: 'Impact', schema: IMPACT_SCHEMA, effort: 'high' },
)

// The cap is applied HERE, before any early exit, and the position is
// load-bearing. The impact guard and `missingPrecondition` below both return the
// `impact` object verbatim, so a cap applied after them hands the orchestrator
// the agent's own uncapped `severity` on every finding that exits at either one,
// with no correction and no note. The second of those exits fires PRECISELY when
// the root cause is anything but internal with the precondition unstated, which
// is the most likely non-passing outcome for exactly the findings the cap exists
// to bound.
//
// `impact` may be null if the agent died; `capSeverity` is total over that.
const capped = impact
  ? capSeverity(impact.severity, impact.rootCause, impact.classification)
  : { severity: undefined, note: '', ambiguous: '' }
if (capped.note) log(capped.note)

// Every return below carries the corrected severity, not `impact.severity`. A
// consumer reading `impact.severity` directly is reading the pre-cap number, so
// the corrected one is surfaced under the same keys the passing path uses.
const severityFields = { severity: capped.severity, severityCorrection: capped.note || capped.ambiguous }

// Only VERIFIED is a pass: NOT_VERIFIED means NO impact could be established,
// which is not a licence to spend the rest of the pipeline on it.
//
// "No impact established" is not the same as "the reported severity was too
// high", and the two are easy to conflate: an agent that performs exactly the
// downgrade it was asked for — "NOT VERIFIED as stated and is downgraded to
// LOW" — and then reports NOT_VERIFIED is describing a real, demonstrable bug.
// NOT_VERIFIED therefore returns NEEDS_MORE_INFO rather than a false-positive
// verdict, because "could not establish" is not "does not exist".
if (!impact || impact.result !== 'VERIFIED') {
  const stated = impact ? impact.result : 'missing'
  // Read the affirmative value, as every sibling gate in this file does. Only
  // DISPROVEN is positive evidence that no impact exists, so only DISPROVEN may
  // reach a terminal dismissal. Grading by exclusion made NOT_EXPLOITABLE the
  // fall-through for every grade this script does not recognise, and `enum` is
  // advisory to the validator: an impact agent that answered `Verified` in the
  // wrong case, or invented a fourth grade, was reported to the user as "FALSE
  // POSITIVE — no attacker-reachable path" over its own evidence FOR the impact,
  // with no later stage left that would reopen it.
  const status = impact && impact.result === 'DISPROVEN' ? 'NOT_EXPLOITABLE' : 'NEEDS_MORE_INFO'
  // An unrecognised grade establishes nothing, so its `evidence` is not the
  // reason: that text argues the impact, and relaying it verbatim handed the
  // reader "NEEDS MORE INFO — traced end to end" as the fact still missing.
  const graded = impact && (impact.result === 'NOT_VERIFIED' || impact.result === 'DISPROVEN')
  const reason = !impact
    ? 'impact agent returned nothing'
    : graded
      ? String(impact.evidence || '').trim() || `impact agent reported ${impact.result} but gave no evidence`
      : `impact agent graded checkpoint 2.4 ${impact.result ? `'${impact.result}'` : 'with nothing'}, which is not one of VERIFIED, NOT_VERIFIED or DISPROVEN, so no impact grade was established`
  log(`${status}: impact ${stated}. ${reason}`)
  return {
    status,
    reason,
    route,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
    impact,
    ...severityFields,
  }
}

// Checkpoint 2.4b passes only if "the required external precondition is stated
// explicitly" for any root cause that is not internal. JSON Schema cannot
// express "required when rootCause is not internal", so the schema marks
// externalPrecondition optional and the rule is applied here. Without it a
// finding that only fires when some upstream system misbehaves reaches the PoC
// stage with the precondition that makes it exploitable left unsaid — and the
// severity cap has nothing to cap against.
//
// `externalRootCause` rather than `!== 'internal'` inline: this gate and the cap
// have to read the same value the same way, and they did not.
function missingPrecondition(verified) {
  if (!verified || !externalRootCause(verified.rootCause)) return false
  return !String(verified.externalPrecondition || '').trim()
}

if (missingPrecondition(impact)) {
  // The same label the three cap notes use, for the same reason and on the same
  // predicate: this branch is reached by every root cause that is not `internal`,
  // blank and absent included, and "root cause is , so …" / "root cause is
  // undefined, so …" is what SKILL.md then relays to the user verbatim.
  const cause = String(impact.rootCause || '').trim() || 'non-internal'
  const why = `root cause is ${cause}, so the external precondition the attack requires must be stated explicitly, and it was not`
  log(`NEEDS_MORE_INFO: ${why}`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: why,
    route,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
    impact,
    ...severityFields,
  }
}

// An ambiguous rating is an unusable answer, and it is refused HERE rather than
// carried into the verdict. `capSeverity` hands it back instead of guessing at
// it, so if nothing caught it the finding would ship the agent's own string —
// `Critical (affects low-privilege users)` — as its severity with no cap
// applied, which is precisely the escape this gate exists to close.
// NEEDS_MORE_INFO, not a dismissal: nothing about the bug was disproven, the
// impact agent wrote a rating nobody can read, and the reason names the fix.
//
// LAST of the three, after the impact guard and after `missingPrecondition`.
// Both of those are facts about the finding and the stronger thing to report;
// this one is a clerical failure, and a finding that fails all three should be
// told about the substance first.
if (capped.ambiguous) {
  log(`NEEDS_MORE_INFO: ${capped.ambiguous}`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: capped.ambiguous,
    route,
    layers: layerVerdicts,
    recovery,
    threat,
    history,
    proofs,
    blockingProofs: blockingProof,
    impact,
    ...severityFields,
  }
}

// Checkpoint 2.4b ("integration -> requires an external failure to trigger, cap
// at Medium", "external -> workaround only") and 2.5 ("hardening gap -> medium
// priority, defense-in-depth") are arithmetic, not judgement. The prompt states
// both, and a prompt is not an enforcement mechanism: what comes back is
// whatever severity the agent chose, and an inflated severity on a finding that
// only fires when a third party misbehaves is exactly the failure this skill
// exists to prevent.
//
// It CORRECTS rather than blocks. BLOCKED is the right answer once an agent has
// written the severity into a report file — that file is now wrong and re-running
// the workflow will not fix it, which is why Stage 3 blocks. On the cheap path
// there is no file, Stage 1 owes the
// user a verdict, and the cap is arithmetic: applying it is strictly better than
// refusing to answer. The correction is reported, never silent.
//
// Self-contained so it can be extracted and graded without the surrounding
// script.
// Pure. Every DISTINCT rating level a string names, WORD-BOUNDED, most severe
// first. The boundaries are the whole point: `low` sits inside "Allowlist",
// `high` inside "highly" and `critical` inside "critically", and an unbounded
// substring test read all three as ratings.
//
// It reports what the string names and decides nothing. Every rule that tries to
// make one string yield one rating — leftmost name, highest named,
// highest-only-where-it-lowers — trades a false accept for a false reject,
// because "Critical (affects low-privilege users)" and "Low (the path is not
// business-critical)" are the same shape with opposite intent. No positional rule
// can separate them. Reading the levels out and letting the caller refuse the
// ambiguous ones can.
function namedLevels(severity) {
  const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
  return LEVELS.filter((name) => new RegExp(`\\b${name}\\b`, 'i').test(String(severity)))
}

// One reading of "not internal", shared by `missingPrecondition`, by the cap and
// by the three gate-prompt conditionals below. They disagreed: the cap matched
// `integration` or `external` affirmatively while the other three branched on
// `!== 'internal'`, so `third-party` — a spelling nothing rejects, because
// `required` is the only thing the runtime validator enforces — took the external
// branch everywhere EXCEPT the cap. The gate agent was handed "the severity is
// already capped at Critical because of it", which was false, and forbidden on
// that false premise from failing gateReachability, gateRealImpact or
// gatePocValidation on the external trigger. The relaxation's own argument is
// that the trigger "has been priced once already, in the cap"; it holds only
// where the cap was actually paid.
//
// Unrecognised reads as NOT internal. `internal` is the stronger claim — the
// trigger originates inside this repository, so the severity stands as rated and
// gate 2 keeps its trust-boundary half — and an agent that did not write one of
// the three enum values has not made it. The other reading hands back the
// agent's own uncapped number, which is the escape 2.4b exists to close. Case
// and surrounding space are forgiven for the reason `namedLevels` forgives them:
// the enum is advisory, so `Internal` is the same claim.
function externalRootCause(rootCause) {
  return String(rootCause || '').trim().toLowerCase() !== 'internal'
}

function capSeverity(severity, rootCause, classification) {
  const CAP = 'Medium'
  // Affirmative — "is this rating at or above the cap?" — rather than by
  // exclusion. `severity !== 'Critical' && severity !== 'High'` returns early for
  // every spelling the enum does not enforce, and `required` is the only thing
  // the runtime validator enforces: 'critical', 'CRITICAL' and 'Critical (RCE)'
  // then escape the cap uncorrected, which is the whole mechanism gone.
  //
  // EXACTLY ONE level named is a rating. More than one is not: 'Medium/High',
  // 'Critical (affects low-privilege users)' and 'Low (the affected path is not
  // business-critical)' each name two, and picking one of them is a guess in a
  // direction that is wrong half the time — guess high and a Low is raised to
  // Medium under a note reading "severity lowered from Low", guess low and an
  // inflated Critical ships uncorrected with `low` inside "low-privilege" as its
  // licence. So it is not guessed.
  //
  // NONE named is not a rating either, and reading it as one below the cap was
  // the same escape from the other side: 'Sev-1', 'P0', a CVSS number and a blank
  // were returned untouched with no note and no flag, so an integration root
  // cause reached TRUE_POSITIVE with checkpoint 2.4b never applied — and that
  // uncapped string is what Stages 2 and 3 are forwarded. There is no caller-side
  // guard here to fall back on: Stage 3's `reportProblem` refuses an unreadable
  // rating, Stage 1's only post-cap check was this function's own ambiguity flag.
  //
  // Either way the rating is an unusable agent answer and is handed back to the
  // caller as one, exactly as a missing verdict is, and the caller counts it
  // against the finding rather than shipping a number nobody can defend.
  const named = namedLevels(severity)
  if (named.length !== 1) {
    const stated = String(severity || '').trim()
    return {
      severity,
      note: '',
      ambiguous: !stated
        ? 'no severity was stated, and no cap can be applied to a blank rating: state exactly one of Critical, High, Medium, Low, Informational'
        : named.length === 0
          ? `severity "${stated}" names none of Critical, High, Medium, Low or Informational; no cap can be applied to a rating that is not one of them: state exactly one`
          : `severity "${stated}" names ${named.length} levels (${named.join(', ')}), so there is no single rating to cap: state exactly one of Critical, High, Medium, Low, Informational`,
    }
  }
  const level = named[0]
  if (level !== 'critical' && level !== 'high') return { severity, note: '', ambiguous: '' }
  if (externalRootCause(rootCause)) {
    // Named, so the note says which value was read. A blank one is not internal
    // either, and `a  root cause` is not a sentence.
    const cause = String(rootCause || '').trim() || 'non-internal'
    return {
      severity: CAP,
      ambiguous: '',
      note: `severity lowered from ${severity} to ${CAP}: a ${cause} root cause requires an external failure to trigger (checkpoints.md 2.4b)`,
    }
  }
  if (classification === 'hardening_gap') {
    return {
      severity: CAP,
      ambiguous: '',
      note: `severity lowered from ${severity} to ${CAP}: a hardening gap is defense-in-depth, not an exploited vulnerability (checkpoints.md 2.5)`,
    }
  }
  return { severity, note: '', ambiguous: '' }
}


// ------------------------------------------------------- Stages 1f and 1g

phase('Verdict')

// Gate 2 is stated TWICE below, under one `impact.rootCause` conditional, and the
// duplication is the point. Stating the criterion as being about the PATH only —
// so an integration finding is not charged twice for its external trigger — is
// correct where that trigger is the accepted premise and wrong everywhere else,
// and `decideVerdict` branches on the enum alone, so one relaxed wording for all
// findings drops the trust-of-source requirement out of the pipeline entirely.
// Checkpoint 2.4b does NOT answer it for an internal root cause: 2.4b asks whether
// the trigger comes from outside this repository, not whether the value at the sink
// is attacker-controlled. `internal` therefore keeps the strict wording — the one
// that catches a real sink fed by a value no attacker can influence — and the
// relaxation applies only where the premise it relies on is actually established.
//
// The by-design objection that did NOT reach the dismissal bar. Checkpoint 3.3
// puts that bar at two indicators plus a search, so one is "a flag to check, not
// a verdict" — but a bar with nothing below it routes the below-bar signal
// NOWHERE: the impact prompt, this prompt and `decideVerdict` otherwise never see
// `threat` at all, so a documented design-intent objection is dropped and the
// finding comes back TRUE_POSITIVE with no record it was ever raised. It is
// carried here, to the one agent holding every other piece of evidence, and
// deliberately NOT added to `overruled`: that list forbids TRUE_POSITIVE
// outright, which is the terminal dismissal on a single indicator that raising
// the bar removed.
//
// Keyed on the INDICATORS, not on `byDesign`. That bar has two halves — two
// indicators AND a confirming search — and the boolean carries only whether the
// second was done, so keying the carry on it dropped the STRONGER of the two
// objections: an agent that obeys the prompt and reports three indicators
// without having finished the search returns `byDesign: false`, and that shape
// reached no prompt in this file at all while a one-indicator hunch was carried.
// Either signal carries now, so whichever half of the bar was missed, the
// objection still reaches the agent that can answer it.
const byDesignCount = Number(threat && threat.byDesignIndicators) || 0
const softByDesign =
  threat && (threat.byDesign || byDesignCount >= 1)
    ? `${byDesignCount} of 3 design-intent indicators fired${threat.byDesign ? '' : ', though the agent did not itself mark the finding by-design'}: ${String(threat.evidence || '').trim() || 'no evidence given'}`
    : ''

const verdictAgent = await agent(
  `The adversarial pass, then the six gates. Everything below was established by
agents that each saw one narrow question; you are the first to see all of it.

Finding: ${finding.summary}
Sink: ${finding.sink}
Bug class: ${finding.bugClass}
Verified impact: ${impact.impact}
Root cause: ${impact.rootCause}${!externalRootCause(impact.rootCause) ? '' : ` (external precondition: ${impact.externalPrecondition})`}
Classification: ${impact.classification}
Severity after the caps: ${capped.severity}${capped.note ? ` — ${capped.note}` : ''}
Recovery: ${recovery.recoveryExists ? `EXISTS, ${recovery.mechanism || 'mechanism not named'}` : 'none found'} — ${recovery.effectiveImpact}
${layerSummary}${layerVerdicts.length ? `\n  ${layerVerdicts.map((l) => `${l.layer} (${l.location}): ${l.evidence}`).join('\n  ')}` : ''}
Already-fixed search: ${history.fixed} — ${history.searched}
${softByDesign ? `Design intent, raised by the threat-model agent and carried rather than acted on:\nit did not clear the bar checkpoint 3.3 sets at two indicators plus a confirming\nsearch, so it did not dismiss the finding. Answer it here — ${softByDesign}` : ''}
${proofs.length ? `Deep-route proofs:\n  ${proofs.map((p) => `${p.key}: ${p.verdict ? `${p.verdict.applies === true ? p.verdict.verdict : `${p.verdict.verdict} (does not apply to this finding)`} — ${p.verdict.evidence}` : 'agent returned nothing'}`).join('\n  ')}` : ''}
Route: ${route}
${blockingProof.length ? `\nDeep-route proof(s) reporting the finding impossible. They were carried rather\nthan made terminal, because a single auxiliary proof is not above the traced path:\n  ${blockingProof.map((p) => `${p.key}: ${p.what}`).join('\n  ')}\n` : ''}
First, argue against the finding, then for it. Work through
${baseDir}/references/false-positive-patterns.md — the 13-item checklist and the
four red-flag lists. ${route === 'deep' ? 'All 13 devil\'s-advocate questions.' : 'The 7 spot-check questions of the standard route.'}
You are biased toward seeing bugs and toward rating them critical; the questions
exist to work against that.

Then the other direction, which is not optional and carries equal weight. The
guards against wrongly DISMISSING a valid finding are in
${baseDir}/references/dismissal-grounds.md: "only reachable in debug mode" needs debug
mode proven off in production; "the attacker would need local access" is a real
threat model for containerised services; "nobody uses that API" needs usage
data, not an assumption; and inventing a mitigation you have not read in the
source is the failure mode that loses real findings.

Then apply the six gates and report each as PASS or FAIL. The criteria are here
rather than in a reference file on purpose: a gate criterion that exists in two
places is one an agent can read the stale copy of.

  gateProcess         every stage above produced concrete evidence, not assertion
  gateReachability    ${!externalRootCause(impact.rootCause) ? `attacker-controlled data reaches the sink through a path a
                      real caller can drive. A demonstration that constructs
                      state no real caller could reach does NOT pass this gate,
                      however genuine the sink is. Neither does a value no
                      attacker can influence: a compile-time constant, a value
                      only a trusted installer or operator sets, a field this
                      repository itself computes. Trust boundary confusion is
                      item 6 of the checklist above and this gate is where it is
                      priced` : `the sink is reached through a path a real caller can drive.
                      A demonstration that constructs state no real caller could
                      reach does NOT pass this gate, however genuine the sink is.
                      This gate is about the PATH. Where the tainted VALUE
                      originates is the question checkpoint 2.4b asks, and for
                      THIS finding it is answered above, under Root cause: the
                      value originates outside this repository`}
  gateRealImpact      RCE, privilege escalation or information disclosure —
                      distinguished from operational robustness, and from a
                      defense-in-depth failure behind intact primary controls
  gatePocValidation   the attack path is demonstrated end to end. On this route
                      that is the traced path and its evidence; a built PoC is
                      Stage 3's job and its absence is not a FAIL here
  gateMathBounds      the algebra permits the vulnerable condition. N/A when this
                      is not a bounds or arithmetic finding
  gateEnvironment     no compiler, runtime, OS or framework protection prevents
                      exploitation ENTIRELY. Raising the bar is not preventing

${!externalRootCause(impact.rootCause) ? '' : `The root cause of this finding is ${impact.rootCause}: the trigger originates outside
this repository BY CONSTRUCTION. The precondition is stated — ${impact.externalPrecondition} —
and the severity is already capped at ${capped.severity} because of it.

Do NOT fail gateReachability, gateRealImpact or gatePocValidation on the ground
that the trigger comes from outside this repository, or that no in-repo caller
supplies the value. That is the premise this finding was accepted under and it has
been priced once already, in the cap. Failing a gate on it prices it twice, and the
second charge cancels the first.

Judge the three GIVEN that precondition. gateReachability fails only if the in-repo
segment is broken: a check between the entry point and the sink that the stated
precondition does not defeat, or no path at all from that entry point to the sink.
The absence of an in-repo caller is that same external premise restated, not a
second ground — the caller is outside this repository BY CONSTRUCTION, so searching
for it in here will always come up empty, and a gate that fails on the empty result
is the double charge again under another name.
gateRealImpact fails only if what survives is operational robustness rather than a
security consequence. gatePocValidation fails only if the traced path has a gap in
it.

`}Put anything you could not resolve with the evidence at hand into
unresolvedUncertainty, and leave it empty when there is nothing. An honest
"unresolved" routes this to NEEDS MORE INFO, which is a supported outcome; a
guess dressed as a verdict is not.

No speculative language in verdictReason: "probably", "likely", "might", "would",
"could bypass" are all disallowed. Say what the evidence shows.`,
  { label: 'gates', phase: 'Verdict', schema: VERDICT_SCHEMA, effort: 'high' },
)

// Pure. The rule is "all six gate reviews must pass" before anything is reported
// as a vulnerability. As prose in a reference file that is something an agent is
// asked to honour; here it is arithmetic over six enums.
//
// That rule decides TRUE POSITIVE and nothing else. Which of the other two
// verdicts a run that did not clear all six lands on is a second question, and
// answering it "any FAIL is a FALSE POSITIVE" is what the gate table below exists
// to stop.
//
// A missing verdict counts AGAINST the finding, and unresolved uncertainty is
// its own outcome rather than being resolved in either direction.
//
// `overruled` is the second input and the one that makes deferral safe: it is the
// list of arguments some earlier stage already made FOR dismissing this finding —
// today, a deep-route proof that reported the finding impossible. They were
// carried here instead of ending the stage, and the invariant that makes that
// legal is enforced below rather than asked for: nothing on this list can be
// silently dropped, because a non-empty list forbids TRUE_POSITIVE. Deferring is
// therefore only ever a decision to keep analysing, never a decision to report.
//
// Two inputs and no more: a parameter no stage still fills would read as coverage
// while always arriving empty.
function decideVerdict(result, overruled) {
  const dismissals = (overruled || []).filter(Boolean)
  if (!result) {
    return { status: 'NEEDS_MORE_INFO', reason: 'the gate-review agent returned nothing; no gate was evaluated' }
  }
  // The third column is what a FAIL on that gate MEANS, and it is what stops a
  // thin write-up being reported as a refutation. Four of the six grade the BUG:
  // no reachable path, no security consequence, algebra that forbids the
  // condition, a protection that prevents exploitation. A FAIL there says the bug
  // is not there. The other two grade the EVIDENCE — gateProcess asks whether the
  // stages above produced evidence rather than assertion, and gatePocValidation
  // on this route asks whether the traced path has a gap in it — and neither says
  // anything about whether the bug exists.
  //
  // Mapping those two to FALSE POSITIVE retired a finding whose Reachability,
  // Real Impact, Math Bounds and Environment gates had all PASSED, on the ground
  // that the write-up behind them was thin. That is the rounding
  // references/gate-reviews.md calls the most expensive mistake available here,
  // and it is reachable on a supported dispatch: `layers: []` with
  // `layersSearched` tells this same prompt that the layer stage rests on a
  // caller assertion rather than on agent verification, which is a Process FAIL
  // an honest agent can write. VERDICT_SCHEMA gives gateProcess the enum
  // ['PASS', 'FAIL'] and no third value, so the conflation was forced by the
  // schema rather than chosen by the agent.
  //
  // One table and not two, so the affirmative sweep below still covers all six.
  const GATES = [
    ['gateProcess', 'Process', 'evidence'],
    ['gateReachability', 'Reachability', 'bug'],
    ['gateRealImpact', 'Real Impact', 'bug'],
    ['gatePocValidation', 'PoC Validation', 'evidence'],
    ['gateMathBounds', 'Math Bounds', 'bug'],
    ['gateEnvironment', 'Environment', 'bug'],
  ]
  const why = String(result.verdictReason || '').trim() || String(result.evidence || '').trim()

  // A refutation first: a gate that says the bug is not there is a FALSE POSITIVE
  // and says which one, which is more useful than "something was uncertain".
  const refuted = GATES.filter(([key, , grades]) => grades === 'bug' && result[key] === 'FAIL').map(([, name]) => name)
  if (refuted.length > 0) {
    return {
      status: 'FALSE_POSITIVE',
      reason: `gate ${refuted.join(' and ')} failed: ${why || 'agent reported FAIL with no reason'}`,
    }
  }

  // Then the two that grade the evidence, and only once no gate has refuted the
  // finding — checked second so a run that failed both kinds still reports the
  // refutation. "There is no reachable path" is an answer; "the stages asserted
  // rather than showed" is a missing fact, and the weaker statement must not
  // displace the stronger one in the reason the orchestrator relays verbatim.
  const thin = GATES.filter(([key, , grades]) => grades === 'evidence' && result[key] === 'FAIL').map(([, name]) => name)
  if (thin.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `gate ${thin.join(' and ')} failed and no gate refuted the finding, so the evidence is incomplete rather than the finding disproven: ${why || 'agent reported FAIL with no reason'}`,
    }
  }

  const unresolved = String(result.unresolvedUncertainty || '').trim()
  if (unresolved) {
    return { status: 'NEEDS_MORE_INFO', reason: `unresolved after the adversarial pass: ${unresolved}` }
  }

  // Read the affirmative value, per gate, rather than grading by exclusion. Only
  // Math Bounds may be N/A; a gate this script does not recognise on any other
  // must not fall through to TRUE POSITIVE.
  const notPassed = GATES.filter(
    ([key]) => !(result[key] === 'PASS' || (key === 'gateMathBounds' && result[key] === 'N/A')),
  ).map(([, name]) => name)
  if (notPassed.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `gate ${notPassed.join(' and ')} returned no PASS verdict, so the six-gate review is incomplete`,
    }
  }

  if (!why) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: 'all six gates passed but the agent gave no reason; a verdict with nothing behind it is not evidence',
    }
  }

  // The other half of deferral. A dismissal that was carried here rather than
  // acted on has to be answered by the six gates, and "answered" means a FAIL on
  // a gate that grades the BUG — which is checked first, above, and returns
  // FALSE_POSITIVE. A Process or PoC Validation FAIL does not answer it: those
  // report that the evidence is thin, which leaves the dismissal exactly where it
  // was, and the branch above returns NEEDS_MORE_INFO for the same reason this
  // one does. Six passes with a dismissal still standing means the two disagree
  // and nothing reconciled them, so the finding is not confirmed.
  //
  // The reason quotes the dismissal rather than summarising it: the whole point
  // of deferring was that this argument survives to the reader.
  if (dismissals.length > 0) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `all six gates passed, but ${dismissals.length} earlier dismissal(s) were deferred here and none was answered: ${dismissals
        .map((d) => `${d.title} — ${d.what}`)
        .join('; ')}`,
    }
  }
  return { status: 'TRUE_POSITIVE', reason: why }
}

const verdict = decideVerdict(verdictAgent, blockingProof)

const payload = {
  route,
  layers: layerVerdicts,
  recovery,
  threat,
  history,
  proofs,
  blockingProofs: blockingProof,
  impact,
  severity: capped.severity,
  severityCorrection: capped.note,
  gates: verdictAgent,
}

if (verdict.status !== 'TRUE_POSITIVE') {
  log(`${verdict.status}: ${verdict.reason}`)
  return { status: verdict.status, reason: verdict.reason, ...payload }
}

log(`TRUE_POSITIVE at ${capped.severity}. ${verdict.reason}`)
return { status: 'TRUE_POSITIVE', reason: verdict.reason, ...payload }
