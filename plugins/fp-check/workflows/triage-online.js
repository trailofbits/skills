export const meta = {
  name: 'triage-online',
  description:
    "Stage 2: check the project's current public posture — disclosure policy, bounty scope, advisories, past reports, and a census of the public downstream users when severity turns on how they consume the target — and correct the scope or severity Stage 1 reached",
  whenToUse:
    'Only when the user asked for online checks, and only after triage-static has produced a verdict. Requires network access to a real upstream project; it fails closed rather than triaging policy from memory.',
  phases: [{ title: 'Policy' }, { title: 'Scope' }, { title: 'History' }, { title: 'Summary' }],
}

// args: { baseDir, finding, verification, project, sources[] }
//
// Every conclusion here rests on a document that could be read today and may say
// something different next month, so the one rule this script enforces above all
// others is that a claim without a citation is not a verdict. The failure it is
// built against is not a wrong answer; it is a confident answer produced from the
// model's memory of a policy that has since changed.

const { baseDir, finding, verification, project, sources = [] } = args || {}

const MAX_SOURCES = 6

const POLICY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['reachedNetwork', 'sourcesRead', 'inScopeClasses', 'outOfScopeClasses', 'evidence'],
  properties: {
    // The only field in this workflow that can halt it before any judgement is
    // formed. See offlineProblem.
    reachedNetwork: { type: 'boolean', description: 'a live fetch of a project document actually succeeded' },
    sourcesRead: {
      type: 'string',
      description: 'the URLs read, and where you looked and found nothing — both, so a null result is auditable',
    },
    policyUrl: { type: 'string', description: 'the canonical policy document, when one exists' },
    inScopeClasses: { type: 'string' },
    outOfScopeClasses: { type: 'string' },
    severityRubric: { type: 'string', description: "the project's own severity scale, when it publishes one" },
    proofRequirements: { type: 'string' },
    evidence: { type: 'string' },
  },
}

const SCOPE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'clause', 'severity', 'evidence'],
  properties: {
    verdict: { enum: ['in-scope', 'out-of-scope', 'unclear'] },
    // Out-of-scope requires a clause. "It's probably out of scope" is `unclear`,
    // and `unclear` does not stop the workflow — which is the whole reason this
    // field is required rather than encouraged.
    clause: { type: 'string', description: 'the policy text that controls the verdict, quoted' },
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    eligibilityCaveats: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// A shape of its own rather than a reuse of SCOPE_SCHEMA. One schema loosened to
// fit two jobs carries fields no prompt asks for and no code reads — an agent
// answering a policy `verdict` and a quoted `clause` it was never asked for — and
// leaves the fact this step exists to establish with nowhere to live: whether the
// sink is driven by the project's own code or only by a consumer's, which is the
// one thing `needsUserCensus` turns on.
//
// Every field here is required and every field here is read.
const REACHABILITY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['driver', 'eligibilityCaveats', 'evidence'],
  properties: {
    // Who drives the sink in the PUBLISHED project. `client-code` is the library
    // shape — the bug needs an unsafe usage a consumer writes — and it is what
    // makes the downstream-consumer census worth an agent.
    driver: {
      enum: ['in-repo-caller', 'client-code', 'unknown'],
      description:
        "'in-repo-caller' when the project's own code reaches the sink, 'client-code' when only a consumer's code can, 'unknown' when the published evidence does not settle it",
    },
    // Required rather than optional, for the same reason SUMMARY_SCHEMA requires
    // openQuestions: the prompt asks for the unknowns that would change the
    // verdict, and an omitted gap reads as none.
    eligibilityCaveats: { type: 'string', description: 'the unknowns that would change the verdict, and the mitigating factors' },
    evidence: { type: 'string' },
  },
}

const PAST_BUGS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['result', 'coverage', 'duplicate', 'evidence'],
  properties: {
    result: { enum: ['nothing', 'similar-bugs-found'] },
    coverage: {
      type: 'string',
      description: 'the query used and the pagination or cursors exhausted; one query is not a source',
    },
    links: { type: 'string' },
    similarity: { type: 'string', description: 'trigger, actor, impact, component and policy match' },
    historicalSeverity: { type: 'string' },
    recommendedSeverity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    // Required, because the terminal DUPLICATE outcome branches on it and
    // `required` is the only thing the runtime validator enforces. Omitted, it
    // reads as `undefined` — falsy — so a genuine duplicate the agent found but
    // did not flag is reported as a live finding.
    duplicate: { type: 'boolean', description: 'this exact bug is already publicly reported' },
    evidence: { type: 'string' },
  },
}

// The one agent in this stage whose subject is the WORLD rather than the project.
//
// `result` is an enum rather than a count because the two answers are not
// symmetrical. `affected-users-found` is a positive claim backed by links;
// `no-confirmed-users` bounds what was looked at and says nothing about what was
// not. `coverage` is required so the second one is auditable, and the summary is
// told in as many words not to read it as proof.
const CENSUS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['reachedNetwork', 'result', 'pattern', 'coverage', 'confirmed', 'severityEffect', 'evidence'],
  properties: {
    // Same fail-closed rule the policy agent lives by, for the same reason: a
    // census answered from memory is a claim about which projects are vulnerable
    // today, made from a snapshot of a package ecosystem that has since moved.
    reachedNetwork: { type: 'boolean', description: 'a live search of a real code or package index actually succeeded' },
    result: { enum: ['no-confirmed-users', 'affected-users-found'] },
    pattern: {
      type: 'string',
      description: 'the client-side usage that makes the bug exploitable, written as it would appear in a consumer',
    },
    coverage: {
      type: 'string',
      description: 'the queries actually run, the indexes searched, and where you looked and found nothing — one query is not a census',
    },
    confirmed: {
      type: 'string',
      description:
        'each confirmed consumer: name, a link to the exact occurrence, and the context that tells it from a string match. Empty when none was confirmed',
    },
    severityEffect: {
      enum: ['raise', 'lower', 'none'],
      description: 'raise on a confirmed unsafe consumer, lower when the misuse is only theoretical, none when the evidence does not settle it',
    },
    evidence: { type: 'string' },
  },
}

const SUMMARY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['finalSeverity', 'scopeVerdict', 'reasoning', 'confidence', 'openQuestions', 'evidence'],
  properties: {
    finalSeverity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown'] },
    // `out-of-scope` is deliberately NOT offered here, and this schema is the only
    // place that can withhold it. It is the one verdict that ends the work, so
    // SCOPE_SCHEMA makes it cost a quoted `clause` and `scopeHalt` refuses it
    // without one. This schema has no clause field at all, and SKILL.md tells the
    // orchestrator to adopt `summary.scopeVerdict` — so an out-of-scope written
    // here routes around that asymmetry and leaves SKILL.md's "OUT OF SCOPE — <the
    // clause>" with no clause to print.
    scopeVerdict: {
      enum: ['in-scope', 'unclear'],
      description: 'out-of-scope is decided in the Scope step, on a quoted clause; the honest answer here is unclear',
    },
    duplicateOf: { type: 'string' },
    reasoning: { type: 'string' },
    confidence: { enum: ['high', 'medium', 'low'] },
    // Required, not optional: this stage's honest answer is often "the policy
    // does not address this", and a summary that omits the gap reads as though
    // the question was settled.
    openQuestions: { type: 'string' },
    evidence: { type: 'string' },
  },
}

// Pure.
function missingArgs(a) {
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
  const proj = (a && a.project) || {}

  need('baseDir', a && a.baseDir)

  // `need` above validates baseDir's PRESENCE. Its SHAPE is checked separately
  // because the wrong shape is silent: the dispatch that gets this wrong passes
  // the TARGET REPO's path where the skill directory's belongs, and then every
  // read under `${baseDir}/references/` 404s. The impact agent never opens
  // dismissal-grounds.md, the gate agent never opens false-positive-patterns.md,
  // and an agent that cannot read its reference file does not stop — it carries on
  // and answers from memory, which is indistinguishable from a real answer in the
  // transcript.
  //
  // A workflow has no filesystem access, so existence cannot be checked here. The
  // SHAPE can be, and it is exactly what a misdirected dispatch gets wrong: an
  // absolute path ending in the skill directory. Reported rather than silently
  // tolerated, because the failure is otherwise invisible.
  //
  // Written without a regex literal on purpose: the Python contract suite lexes
  // these scripts to strip strings and comments, and it REJECTS a regex literal
  // rather than risk mis-lexing one (test_a_regex_literal_is_rejected_rather_than_mis_lexed).
  // One here turns the whole suite red on unmutated code, and a mutation whose
  // baseline is red proves nothing.
  //
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
  // Without an identified upstream project there is nothing to look up, and the
  // agents would search for a plausible-sounding project instead of this one.
  // A collision between two projects' analysis directories is how this goes wrong
  // quietly.
  need('project.name', proj.name)
  need('project.url', proj.url)

  // Statuses from triage-static that Stage 2 can still act on. A finding already
  // dismissed on the code does not need a policy check, and running one anyway
  // invites the online evidence to argue a dead finding back to life.
  //
  // OUT_OF_SCOPE is deliberately absent, even though a DECLARED scope is exactly
  // what a published policy can overturn. It cannot be honoured here: triage-static
  // decides OUT_OF_SCOPE inside `decideGate`, BEFORE the impact agent is dispatched,
  // so the payload it returns carries no `impact` and no `severity` — and the two
  // `need` calls below require both, because all three prompts here interpolate them
  // and a Stage 2 run on an unverified impact would tell its agents "Stage 1 already
  // traced the path in the code" when it did not. Admitting the status here would
  // only move the refusal four lines down. Overturning a declared scope means
  // re-running Stage 1 with the corrected `scope` arg, which is where that input
  // lives.
  //
  // Inline rather than a module const: the tests extract this function and
  // evaluate it alone, where a free variable is a ReferenceError. The alternative
  // — the test carrying its own copy of the list — lets the two disagree silently
  // about which findings Stage 2 will touch.
  const actionable = ['TRUE_POSITIVE', 'NEEDS_MORE_INFO']
  const status = (a && a.verification && a.verification.status) || ''
  if (!actionable.includes(status)) {
    missing.push(
      `verification.status (must be one of ${actionable.join(', ')}; got ${status ? `'${status}'` : 'nothing'} — a finding already dismissed on the code does not need a policy check)`,
    )
  }
  const impact = (a && a.verification && a.verification.impact) || {}
  need('verification.impact.impact', impact.impact)
  // `impactLine` branches on this. Omitted, it reads as `undefined` and every one
  // of the five prompts below opens "Impact CLAIMED but NOT established offline —
  // Stage 1 graded it not at all", priming each agent to talk down a finding whose
  // impact Stage 1 may well have VERIFIED. IMPACT_SCHEMA requires it, so a verbatim
  // forward always carries it; SKILL.md's Stage 2 arg list names it as read.
  need('verification.impact.result', impact.result)
  // Both are read by `needsUserCensus`, by the census prompt and by `censusWhy`.
  // Required rather than optional because omitting them fails silently in both
  // directions at once: an absent rootCause matches neither branch, so the
  // integration/external census trigger is switched off without a word, and the
  // literal string "undefined" is what the census agent is handed. triage-poc
  // requires both; this is the same requirement, and SKILL.md's Stage 2 arg list
  // names them.
  need('verification.impact.rootCause', impact.rootCause)
  need('verification.impact.classification', impact.classification)
  need('verification.severity', a && a.verification && a.verification.severity)

  const srcs = a && a.sources
  if (srcs !== undefined && srcs !== null && !Array.isArray(srcs)) {
    missing.push('sources (must be an array)')
  } else {
    const list = Array.isArray(srcs) ? srcs : []
    // Zero sources means the past-bug search is skipped entirely and the summary
    // is written as though nothing similar had ever been reported. That is the
    // same vacuous pass an empty `layers` is in Stage 1.
    if (list.length === 0) {
      missing.push(
        'sources (name at least one public venue to search — github-issues, github-advisories, a mailing list, a bounty platform; with none, the duplicate check silently does not happen)',
      )
    }
    for (const [i, s] of list.entries()) {
      // Through `need`, so the same type discipline covers the per-item fields:
      // a non-string query is interpolated into a search prompt verbatim.
      need(`sources[${i}].label`, s && s.label)
      need(`sources[${i}].query`, s && s.query)
    }
  }
  return missing
}

// Pure. Stage 2 is optional and can only narrow or correct what Stage 1 returned,
// so a clerical failure here — no network, a dead agent, a summary that left
// `openQuestions` empty — leaves Stage 1's answer exactly where it was. Without
// this the five non-terminal exits returned a bare BLOCKED / OFFLINE /
// NEEDS_MORE_INFO, and SKILL.md's Verdicts table collapses all three onto NEEDS
// MORE INFO: an optional stage failing at its own paperwork printed "NEEDS MORE
// INFO" over a TRUE_POSITIVE Stage 1 had established from the code, and the next
// reader paid for the whole static analysis again to get it back.
//
// A field BESIDE the status rather than a replacement for it, for the reason
// Stage 3 carries `settledBy`: the status still has to say THIS STAGE DID NOT
// RUN, and outcomes told apart by pattern-matching the `reason` are told apart
// wrong. The number rides under `severity`, the key SKILL.md already reads for
// TRIAGED, so one instruction covers every status this stage returns.
//
// Guarded on the status and on the number rather than assumed, because the arg
// gate calls this on args that did NOT validate: a dispatch that forwarded no
// verification at all must carry nothing rather than a verdict of `undefined`.
// The two accepted statuses are inline, and are `missingArgs`' `actionable` list —
// the tests extract this function and evaluate it alone, where a free variable is
// a ReferenceError.
function stageOneStands(a) {
  const v = (a && a.verification) || {}
  const status = typeof v.status === 'string' ? v.status.trim() : ''
  const severity = String(v.severity || '').trim()
  if (!['TRUE_POSITIVE', 'NEEDS_MORE_INFO'].includes(status)) return {}
  return severity ? { stageOneStatus: status, severity } : { stageOneStatus: status }
}

const argProblems = missingArgs(args)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-online received an unusable arg shape: ${argProblems.join(', ')}. See the Dispatch section of SKILL.md.`,
    ...stageOneStands(args),
  }
}

// Stage 2 accepts NEEDS_MORE_INFO, and the commonest NEEDS_MORE_INFO Stage 1
// returns is an impact agent that answered NOT_VERIFIED — "no impact could be
// established either way". Announcing that to the prompts below as "Impact
// established offline: <it>" is the self-report the comment above refuses for
// OUT_OF_SCOPE arriving one field over: an unestablished impact asserted as fact
// to the agents whose job is to price it.
const impactVerified = verification.impact.result === 'VERIFIED'
const impactLine = impactVerified
  ? `Impact established offline: ${verification.impact.impact}`
  : `Impact CLAIMED but NOT established offline — Stage 1 graded it ${verification.impact.result || 'not at all'}, so treat it as the reported claim: ${verification.impact.impact}`

// ------------------------------------------------------------------ Policy

phase('Policy')

const policy = await agent(
  `Determine this project's published threat model and disclosure posture. From
online documentation, not from the code in front of you.

Project: ${project.name} (${project.url})
Finding to be triaged against it: ${finding.summary}
Component: ${finding.component}

Search for and read:
  - SECURITY.md, SECURITY.txt, and any vulnerability disclosure policy
  - the GitHub security/policy page and any wiki pages covering it
  - public documentation outside the repository
  - bug bounty scope and eligibility pages
  - any published severity, impact or vulnerability classification guidance

Use the \`gh\` CLI for GitHub. Record the URL of every material claim; separate
what a source says from what you infer from it.

Set reachedNetwork according to whether a live fetch of one of these documents
actually SUCCEEDED. This is not a formality and it is not about effort: if you
could not reach the network, set it false and stop there. Everything downstream
of this stage is a claim about the project's *current* posture, and policies and
bounty scopes change — answering from memory produces a confident, cited-looking
verdict that may describe a policy that no longer exists. A halt here is the
correct outcome, not a failure.

If you reached the network and the project simply publishes nothing, that is a
different answer: reachedNetwork true, and sourcesRead listing where you looked
and found nothing.`,
  { label: 'policy', phase: 'Policy', schema: POLICY_SCHEMA, effort: 'medium' },
)

// Pure. The rule — stop when offline rather than triage from memory — is enforced
// here in code rather than stated as prose in a reference file, because prose
// inverts under pressure: an agent with no network still has a prompt asking it
// for a scope verdict, and the most likely completion is a plausible one.
//
// A dead agent is treated exactly like an offline one. Both mean the same thing —
// nothing was read — and the failure direction has to be the same.
function offlineProblem(result) {
  if (!result) return 'the policy agent returned nothing, so no project document was read'
  if (result.reachedNetwork !== true) {
    return `no project document could be fetched: ${String(result.sourcesRead || '').trim() || 'the agent did not say where it looked'}`
  }
  if (!String(result.sourcesRead || '').trim()) {
    return 'the policy agent reported reaching the network but named no source it read; an uncitable policy claim is not evidence'
  }
  return null
}

const offline = offlineProblem(policy)
if (offline) {
  log(`OFFLINE: ${offline}`)
  return {
    status: 'OFFLINE',
    reason: `${offline}. Stage 2 makes claims about the project's current public posture and will not make them from memory; re-run it with network access, or rely on Stage 1's verdict alone.`,
    ...stageOneStands(args),
  }
}

// ------------------------------------------------------------------- Scope

phase('Scope')

const reachability = await agent(
  `How is this bug reached, according to public evidence rather than the local tree?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Sink: ${finding.sink}
${impactLine}
Severity so far: ${verification.severity}

Stage 1 already traced the path in the code. You are answering the questions it
could not: which call sites and entry points exist in the published project, which
actors can reach them, and what preconditions — privileges, configuration, timing,
deployment shape — a real deployment imposes.

State the mitigating factors and the reasons exploitation might fail in practice.
Then state the unknowns that would change the verdict. "It's probably not
reachable" is an open question, not a mitigation: record what would have to be
true rather than quietly downgrading the severity.

Then set \`driver\`, which decides whether anyone needs to look at this project's
consumers at all:
  - in-repo-caller — the project's own published code reaches the sink, so the
    bug is exploitable in the target itself
  - client-code — only code a CONSUMER writes reaches it: an exported API, a
    pattern the docs tell clients to implement, a callback the project never
    calls itself
  - unknown — the published evidence does not settle which

Cite a link for every material claim.`,
  { label: 'reachability', phase: 'Scope', schema: REACHABILITY_SCHEMA, effort: 'medium' },
)

// Guarded, and not for symmetry with the other agents: `reachability.evidence` is
// interpolated into the two prompts below and into the summary, so an unguarded
// dead agent throws a TypeError out of the workflow instead of returning a status.
// That is not a fail-closed outcome — the orchestrator is left holding a user
// request for a triage with no verdict to relay, and the worst shape this plugin
// can fail in is exactly that: the gate stops, and the analysis happens by hand
// outside it. BLOCKED, matching scopeHalt's answer to a dead scope agent: nothing
// was read, so nothing can be claimed.
if (!reachability) {
  const why = 'the reachability agent returned nothing; public call sites, actors and preconditions are unverified'
  log(`BLOCKED: ${why}`)
  return { status: 'BLOCKED', reason: why, ...stageOneStands(args), policy }
}

const scope = await agent(
  `Does this finding fit the project's published threat model?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Component: ${finding.component}
Claimed impact: ${finding.claimedImpact}
${impactLine}
Severity so far: ${verification.severity}

Read ${baseDir}/references/validation-dimensions.md before you decide. Its scope
red flags are the ones that matter here — infrastructure outside the stated focus,
a shared library spanning several systems, a component that does not match the
declared objectives — and its rule that an ambiguous scope is UNCERTAIN rather
than YES is the same asymmetry this verdict is built on.

The policy, as read in the previous step:
  in scope: ${policy.inScopeClasses}
  out of scope: ${policy.outOfScopeClasses}
  severity rubric: ${policy.severityRubric || 'the project publishes none'}
  proof requirements: ${policy.proofRequirements || 'none stated'}
  sources: ${policy.sourcesRead}

Public reachability findings:
  ${reachability.evidence}
  caveats: ${reachability.eligibilityCaveats || 'none recorded'}

Map the reachability facts onto the policy clauses and return a verdict.

out-of-scope requires a matching clause, quoted in \`clause\`. Without one the
verdict is unclear, not out-of-scope — and unclear does not stop the analysis.
This asymmetry is deliberate: out-of-scope is the one verdict here that ends the
work, so it is the one that has to be earned.

Then set the severity from the project's OWN rubric where it publishes one. A CVE
number or a vendor CVSS is a claim, not evidence; re-derive it from the rubric and
the reachability facts. Use Unknown rather than guessing.`,
  { label: 'inscope', phase: 'Scope', schema: SCOPE_SCHEMA, effort: 'medium' },
)

// Pure. The halt, and the asymmetry that makes it safe: out-of-scope ends the
// analysis, so it needs a quoted clause; `unclear` does not end anything.
function scopeHalt(result) {
  if (!result) {
    return { status: 'BLOCKED', reason: 'the scope agent returned nothing; the policy verdict is unverified' }
  }
  if (result.verdict !== 'out-of-scope') return null
  const clause = String(result.clause || '').trim()
  if (!clause) {
    return {
      status: 'NEEDS_MORE_INFO',
      reason:
        'the scope agent answered out-of-scope but quoted no policy clause, which by its own rule makes the verdict unclear rather than out-of-scope',
    }
  }
  return {
    status: 'OUT_OF_SCOPE',
    reason: `out of scope per ${clause}${String(result.evidence || '').trim() ? ` — ${result.evidence}` : ''}`,
  }
}

const halt = scopeHalt(scope)
if (halt) {
  log(`${halt.status}: ${halt.reason}`)
  // Affirmative on the two statuses that mean this stage did not run, rather than
  // excluding the one that does: OUT_OF_SCOPE is this stage ANSWERING on a quoted
  // clause, and SKILL.md reports it with no severity because nothing here
  // established one — carrying Stage 1's number under it would put a rating on the
  // one verdict that is about scope and not about whether the bug is real.
  const stands = halt.status === 'BLOCKED' || halt.status === 'NEEDS_MORE_INFO' ? stageOneStands(args) : {}
  return { status: halt.status, reason: halt.reason, ...stands, policy, reachability, scope }
}

// ----------------------------------------------------------------- History

phase('History')

// Capped at MAX_SOURCES, and one agent per source rather than one agent over all
// of them: the rule each has to honour is "exhaust the pagination for YOUR
// source", and an agent handed six venues satisfies that for none of them.
const pastBugs = await parallel(
  sources.slice(0, MAX_SOURCES).map((source) => () =>
    agent(
      `Find bugs similar to this one in ONE source, and only that source.

Project: ${project.name} (${project.url})
Source you are assigned: ${source.label}
Query or URL to start from: ${source.query}

Finding: ${finding.summary}
Component: ${finding.component}
${impactLine}
Public reachability: ${reachability.evidence}

Search only your assigned source. Exhaust its pagination or API cursors, and try
the obvious alternate terms before concluding there is nothing: one query is not a
source, and "the first search found nothing" is the most common way a duplicate
gets filed. Record what you covered, including the limits you hit, in \`coverage\`.

If you find similar bugs, decide whether they change the severity of THIS bug —
but confirm the trigger, actor, impact and component actually match before
importing a historical severity, and record the differences and your confidence.
A superficially similar bug with a different actor is not a precedent.

Set duplicate: true only when this exact bug is already publicly reported, with
the link.`,
      { label: `past-bugs:${source.label}`, phase: 'History', schema: PAST_BUGS_SCHEMA, effort: 'medium' },
    ).then((v) => (v ? { ...v, source: source.label, query: source.query } : null)),
  ),
)
const searched = pastBugs.filter(Boolean)

const attempted = Math.min(sources.length, MAX_SOURCES)

// The venues the cap dropped, by name and carried rather than logged. A log is not
// something any consumer reads: the summary prompt below is built from `attempted`,
// so a 9-source dispatch tells the summary agent about 6 venues and nothing about
// the other 3, and the agent has no way to tell a venue that was never dispatched
// from one that came back clean. That is the same "an absent duplicate
// check becomes a clean bill of health" that `unsearched` exists to stop, arriving
// by the other route. Kept separate from `unsearched` because they are different
// facts — never dispatched, versus dispatched and dead — and the summary is told
// both.
const beyondCap = sources.slice(MAX_SOURCES).map((s) => s.label)
if (beyondCap.length > 0) {
  log(`${beyondCap.length} source(s) beyond the cap of ${MAX_SOURCES} were NOT searched: ${beyondCap.join(', ')}`)
}

// A source whose agent died was not searched, and "not searched" must never be
// summarised as "nothing found there" — that is how an absent duplicate check
// becomes a clean bill of health. Reported rather than fatal: the remaining
// sources are still evidence, and the summary is told which venues are blind.
//
// Matched by POSITION rather than by label: `parallel` preserves position and
// substitutes null in place, and two sources sharing a label would let the
// survivor answer for its twin — one agent dies, `searched.some(r => r.source ===
// label)` finds the other, and the dead venue is summarised as searched.
const unsearched = sources
  .slice(0, MAX_SOURCES)
  .filter((s, i) => !pastBugs[i])
  .map((s) => s.label)
if (unsearched.length > 0) {
  log(`${unsearched.length} of ${attempted} source(s) returned nothing at all: ${unsearched.join(', ')}`)
}

// ------------------------------------------------- Downstream-user census

// Pure. The consumer census is gated rather than always run: for a bug directly
// exploitable in the target itself, a census of that project's consumers answers a
// question nobody asked.
//
// A gate in code rather than a third question at Step 0, because whether severity
// turns on downstream usage is a FINDING of the reachability analysis and not
// something the user knows when they start — and because every extra question is
// one more thing a non-interactive harness silently defaults to `no`, which is how
// a capability ships and then fires zero times.
//
// The last clause is read by exclusion, and that is deliberate. Everywhere else in
// this stage the affirmative value is the one that counts, because there the risk
// is a claim made on no evidence. Here the risk runs the other way: the failure to
// guard against is a capability that never fires, and an omitted `driver` reading
// as "no census needed" is exactly that. A false positive costs one agent; a false
// negative loses the capability entirely.
function needsUserCensus(verification, reachability, scope) {
  // Unreachable from the call site below — `scopeHalt` has already returned on an
  // out-of-scope verdict. Kept because the predicate is unit-tested on its own and
  // "census a project's consumers over a finding its policy excludes" must not be
  // something it says yes to when someone reuses it.
  if (scope && scope.verdict === 'out-of-scope') return false

  const impact = (verification && verification.impact) || {}
  // A root cause that is not internal means the attack needs a failure outside
  // this project, which is the client's side of the boundary.
  //
  // Through `externalRootCause`, and not because this clause was ever read the
  // wrong way round — the exclusion below is the deliberate part. It is here
  // because the CAP reads the same field through that predicate, and the two
  // disagreed the moment it did: `third-party` and `Internal` are spellings the
  // advisory enum does not stop, so a finding could be priced as external by
  // 2.4b and as in-repo by this gate, and the census that severity now turned on
  // was the one thing not dispatched. The direction it moves is the one this
  // comment already argues for — a false positive costs one agent.
  if (externalRootCause(impact.rootCause)) return true
  // A hardening gap is by definition not exploitable on its own; whether it
  // matters is a question about how it is used. Not narrowed to "in an exported
  // surface" — nothing structural tells us that, and guessing narrows toward the
  // failure that costs the capability.
  if (impact.classification === 'hardening_gap') return true

  const driver = (reachability && reachability.driver) || ''
  return driver !== 'in-repo-caller'
}

const censusWanted = needsUserCensus(verification, reachability, scope)

const census = censusWanted
  ? await agent(
      `Do real, popular public consumers of this project actually exhibit the unsafe
pattern this finding depends on?

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Component: ${finding.component}
Sink: ${finding.sink}
${impactLine}
Root cause: ${verification.impact.rootCause}
Public reachability: ${reachability.evidence}

First derive the pattern. From the reachability findings above, write down what
the unsafe usage looks like in a CONSUMER's code — the call, the argument, the
missing check, the order of operations — and put it in \`pattern\`. Everything
after this depends on searching for the right thing.

Then look for it. Use the dependents graph, public code search, the package
index's reverse dependencies, and the project's own list of users. Prefer
consumers with real usage over toy repositories and forks.

Keep only CONFIRMED hits: a real occurrence, a link to the exact file and line,
and enough surrounding context to tell it from a string match on the same
identifier. A consumer that calls the API safely is not a hit. Record each one in
\`confirmed\`, with the link.

Record in \`coverage\` the queries you actually ran and the indexes you searched,
including where you looked and found nothing. Finding nothing bounds what you
looked at; it is not evidence that no consumer is affected, and \`coverage\` is
what lets the next reader tell those apart.

severityEffect: raise when a confirmed consumer exhibits the pattern, lower when
the misuse is only theoretical, none when the search does not settle it.

Set reachedNetwork according to whether a live search actually SUCCEEDED. If you
could not reach the network, set it false and stop there. A census answered from
memory is a claim about which projects are vulnerable today, drawn from a snapshot
of an ecosystem that has since moved.`,
      { label: 'downstream-users', phase: 'History', schema: CENSUS_SCHEMA, effort: 'medium' },
    )
  : null

// Pure. The same rule the rest of this stage lives by — no claim about the world
// without having looked — applied to the one agent whose subject IS the world.
// The failure it exists to stop is the census degrading into "no users found",
// which is a positive claim, when what happened is that nothing was searched.
function censusProblem(result) {
  if (!result) return 'the census agent returned nothing, so no consumer was looked at'
  if (result.reachedNetwork !== true) {
    return `no consumer index could be searched: ${String(result.coverage || '').trim() || 'the agent did not say where it looked'}`
  }
  if (!String(result.coverage || '').trim()) {
    return 'the census named no query it ran; an uncitable "no affected consumers" is not evidence'
  }
  if (result.result === 'affected-users-found' && !String(result.confirmed || '').trim()) {
    return 'the census reported affected consumers but named none, so there is nothing to raise the severity on'
  }
  return null
}

const censusIssue = censusWanted ? censusProblem(census) : null

// Carried, not merely logged. `beyondCap` is the precedent and the lesson: a log
// is not something any consumer reads, so a silently skipped step reaches the
// summary as an absence and reads as a clean result. Both the summary prompt and
// every return below get this.
const censusState = !censusWanted ? 'not-applicable' : censusIssue ? 'unperformed' : 'performed'
// `why` is answered on ALL THREE states, including the one where the census
// SUCCEEDED. `censusIssue` alone will not do: it is null exactly then, so every
// terminal return would carry `census.why: null` on the one path where there is
// something to say, and a reader looking for the rationale finds nothing.
// `censusProblem` has already refused a blank `coverage` on this path, so the
// fallback is unreachable rather than load-bearing.
const censusWhy = !censusWanted
  ? `the bug is exploitable in the target itself — root cause ${verification.impact.rootCause}, classification ${verification.impact.classification}, and the published call sites are driven by ${reachability.driver}`
  : censusIssue || `consumers searched: ${String(census.coverage || '').trim() || 'the agent named no query'}`
if (censusState !== 'performed') log(`downstream-users census ${censusState}: ${censusWhy}`)

// A blind census is reported to the summary as unchecked rather than halting the
// stage, which is where this departs from `offlineProblem`. The policy read is
// this stage's premise and nothing downstream of it means anything; the census is
// one input, and killing a completed policy read, scope verdict and past-bug
// fan-out over it would throw away evidence that is still good. `unsearched` sets
// the precedent for exactly this shape. What must not happen — a census that
// searched nothing summarised as "no consumer is affected" — is what the wording
// below prevents.
const censusReport =
  censusState === 'performed'
    ? `Downstream-consumer census: ${census.result} (severityEffect ${census.severityEffect}).
  unsafe pattern searched for: ${census.pattern}
  confirmed consumers: ${String(census.confirmed || '').trim() || 'none confirmed'}
  coverage: ${census.coverage}
  A census that confirmed nothing bounds what was looked at. It is NOT proof that no consumer is affected.`
    : censusState === 'unperformed'
      ? `Downstream-consumer census: NOT PERFORMED — ${censusWhy}. Severity here turns on how consumers use this project, and that is UNCHECKED rather than clear; it belongs in openQuestions.`
      : `Downstream-consumer census: not applicable — ${censusWhy}.`

// ----------------------------------------------------------------- Summary

phase('Summary')

const duplicates = searched.filter((r) => r.duplicate)

// Pure. Duplicated verbatim from triage-static.js — see the reasoning there.
// A third copy because these scripts have no module system, and the alternative
// to three copies is three divergent rules for the one question all three
// retraction sites ask.
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

// What a duplicate is relayed with, in the summary prompt and in the DUPLICATE
// return. A CITATION, by the same token test `upstreamFixStands` and
// `alreadyFixedStands` hold the other two retraction sites to, for the reason all
// three share: an unreferenced retraction is the one failure mode that silently
// discards a real finding.
//
// Non-blank will not do here for the reason it does not there, and one field over:
// `evidence` is `required` of every past-bug return, so `cited` was a filter
// nothing could fail — "I believe this is the same class of issue as one discussed
// on the mailing list" ended the stage as a terminal retraction, on one agent, with
// no link, and SKILL.md prints DUPLICATE "with their reference". `links` first
// because that is the field that exists to hold the reference; `evidence` is fallen
// back to only when it carries one, since an agent that writes "filed as issue
// 1204" there has still cited something. The old `links: '   '` hazard is subsumed:
// `citedReference` is null on blank space, so a whitespace `links` no longer
// displaces the `evidence` it was meant to fall back to.
const dupCite = (r) => citedReference(r.links) || citedReference(r.evidence)
const cited = duplicates.filter(dupCite)

// The uncited claim, still relayed. `dupCite` returning null no longer means the
// agent said nothing — it means what it said points at nothing anyone can look up —
// so dropping the prose along with the retraction would delete the reason the claim
// was made, and the summary agent is the one reader that can put it in
// openQuestions.
const dupClaim = (r) =>
  `${r.source}: ${dupCite(r) || `NO citable reference — the claim is "${String(r.evidence || '').trim() || 'nothing recorded'}", and a claim is not a citation; it belongs in openQuestions`}`

const summary = await agent(
  `Write the online triage summary. Everything below was gathered by agents that
each saw one narrow question.

Project: ${project.name} (${project.url})
Finding: ${finding.summary}
Severity Stage 1 arrived at, offline: ${verification.severity}${verification.severityCorrection ? ` — ${verification.severityCorrection}` : ''}
${impactLine}
Root cause: ${verification.impact.rootCause}, classification ${verification.impact.classification}

Scope: ${scope.verdict}${String(scope.clause || '').trim() ? ` per ${scope.clause}` : ' — no controlling clause quoted'}
Severity the policy rubric implies: ${scope.severity}
Policy sources: ${policy.sourcesRead}

Public reachability: ${reachability.evidence}
Unknowns that would change it: ${reachability.eligibilityCaveats || 'none recorded'}

Past-bug searches, ${searched.length} of ${attempted} dispatched source(s) returned a result:
  ${searched.map((r) => `${r.source}: ${r.result}${r.recommendedSeverity && r.recommendedSeverity !== 'Unknown' ? ` → ${r.recommendedSeverity}` : ''} — ${r.similarity || r.evidence} [coverage: ${r.coverage}]`).join('\n  ')}
${unsearched.length ? `NOT searched, because those agents returned nothing — treat these venues as unchecked, not as clear:\n  ${unsearched.join('\n  ')}` : ''}
${beyondCap.length ? `NOT searched, because they were beyond the cap of ${MAX_SOURCES} and no agent was dispatched — unchecked, not clear:\n  ${beyondCap.join('\n  ')}` : ''}
${duplicates.length ? `Reported as an existing public duplicate:\n  ${duplicates.map(dupClaim).join('\n  ')}` : searched.length ? 'No source reported this as an existing duplicate.' : 'NOT ONE source returned a result, so the duplicate check did not happen. That is unchecked, not clear, and it belongs in openQuestions — "no source reported a duplicate" would be a claim about searches that were never completed.'}

${censusReport}

Give the final severity recommendation and the reasoning that gets you there,
mapping the reachability facts onto the policy clauses. Where the online evidence
contradicts the offline severity, say which one you are following and why.

An integration or external root cause caps severity at Medium, and a hardening
gap is not written up as an exploited vulnerability. Those caps are arithmetic and
are applied in code after you answer, so a higher rating is corrected rather than
adopted — and a confirmed downstream consumer is a reason to say the cap binds
tightly, not a reason to exceed it.

openQuestions is required and may not be empty. If the policy does not address
this class of bug, if a venue went unsearched, if the consumer census could not be
performed, or if the rubric is ambiguous, that belongs here — a summary that omits
the gap reads as though the question was settled.

scopeVerdict cannot be out-of-scope: that verdict ended the analysis two steps
ago, on a quoted clause, and none was. If you believe the policy excludes this
finding, the verdict is unclear and the clause you could not find is an open
question.`,
  { label: 'summary', phase: 'Summary', schema: SUMMARY_SCHEMA, effort: 'high' },
)

// Pure. The two fields the summary is defined by, checked for content rather than
// presence, for the same reason every other schema in this plugin is: `required`
// validates `openQuestions: ''`.
function summaryProblem(result) {
  if (!result) return 'the summary agent returned nothing'
  if (!String(result.reasoning || '').trim()) return 'summary gave no reasoning'
  if (!String(result.openQuestions || '').trim()) {
    return 'summary left openQuestions empty; every online triage has at least one, and an omitted gap reads as a settled question'
  }
  return null
}

// Pure, and the same arithmetic Stage 1 applies — checkpoints.md 2.4b and 2.5,
// duplicated because a workflow script is standalone and cannot import Stage 1's
// copy. Without it this stage undoes that cap: Stage 1 caps an integration or
// external root cause at Medium, the summary agent is then asked for a
// `finalSeverity`, and SKILL.md tells the orchestrator to adopt it. The census
// feeding that agent fires PRECISELY on the capped root causes, and its
// `severityEffect: raise` invites the number back up. The correction is reported,
// never silent.
//
// `namedLevels` is duplicated from triage-static.js alongside `capSeverity` — see
// the reasoning there. Every DISTINCT rating level a string names, WORD-BOUNDED,
// most severe first: `low` sits inside "Allowlist", `high` inside "highly".
function namedLevels(severity) {
  const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
  return LEVELS.filter((name) => new RegExp(`\\b${name}\\b`, 'i').test(String(severity)))
}

// Duplicated from triage-static.js alongside `capSeverity` — see the reasoning
// there. One reading of "not internal", and unrecognised reads as NOT internal:
// `third-party` and `External` are spellings the advisory enum does not stop, and
// neither of them is the claim that the trigger originates inside the repository,
// which is what buys an uncapped rating.
function externalRootCause(rootCause) {
  return String(rootCause || '').trim().toLowerCase() !== 'internal'
}

function capSeverity(severity, rootCause, classification) {
  const CAP = 'Medium'
  // Affirmative — "is this rating at or above the cap?" — rather than by
  // exclusion. `severity !== 'Critical' && severity !== 'High'` returns early
  // for every spelling the enum does not enforce, and `required` is the only
  // thing the runtime validator enforces: 'critical', 'CRITICAL' and
  // 'Critical (RCE)' would each escape the cap uncorrected.
  //
  // EXACTLY ONE level named is a rating. More than one is not: 'Medium/High',
  // 'Critical (affects low-privilege users)' and 'Low (the affected path is not
  // business-critical)' each name two, and no positional rule separates them —
  // guess high and a Low is raised under a note saying it was lowered, guess low
  // and an inflated Critical ships with `low` inside "low-privilege" as its
  // licence. NONE named is not a rating either: reading 'Sev-1' or 'P0' as below
  // the cap passed it straight through as this stage's `finalSeverity`, which is
  // the number SKILL.md tells the orchestrator to report. Both are handed back
  // rather than resolved, and the fallback below keeps Stage 1's number.
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

// `Unknown` is not a correction. This stage may narrow or correct the severity
// Stage 1 established; replacing a rated finding with "Unknown" — which the cap
// passes through untouched — does neither, and SKILL.md tells the orchestrator to
// take the reported severity from here. Falling back keeps the offline rating,
// which is the one that was actually derived from evidence.
// And the fallback is REPORTED, for the reason the cap two lines up is: this
// stage substitutes a number the reader is told came from here, and `summary.
// reasoning` is relayed verbatim beside it — so an unnoted substitution prints
// Stage 1's `High` next to a paragraph saying no severity could be determined.
// `summary` may be null or incomplete here: this block runs BEFORE the duplicate
// and summary gates, so that DUPLICATE — a terminal, non-BLOCKED status carrying
// a `summary` — is not the one path whose only available number is the UNCAPPED
// `summary.finalSeverity`.
const claimedSeverity = String((summary && summary.finalSeverity) || 'Unknown').trim()
const unknownSeverity = claimedSeverity.toLowerCase() === 'unknown'
const claimed = capSeverity(claimedSeverity, verification.impact.rootCause, verification.impact.classification)
// An AMBIGUOUS claim falls back the same way an Unknown one does, and for the
// same reason: `Medium/High` and `Critical (affects low-privilege users)` are
// not corrections either — nobody can say which number they assert — and this
// stage exists to narrow or correct Stage 1's rating, not to replace a decided
// one with a string. `capSeverity` refuses to guess (see it), so the guess is not
// made here either; Stage 1's number, which was derived from evidence, stands.
// Reported, never silent.
const unusable = unknownSeverity
  ? `online triage returned finalSeverity Unknown, which is not a correction`
  : claimed.ambiguous
const finalSeverity = unusable ? verification.severity : claimedSeverity
const capped = unusable
  ? capSeverity(finalSeverity, verification.impact.rootCause, verification.impact.classification)
  : claimed
const severityNote = [
  // `derived from the code` is claimed only where it is true. Stage 1 reaches
  // NEEDS_MORE_INFO with `impact.result` NOT_VERIFIED, which is a rating on a
  // CLAIMED impact — the same fact `impactLine` tells every agent above — and
  // asserting it was derived from the code in the same run contradicts them.
  unusable
    ? `${unusable}: Stage 1's ${verification.severity} stands${impactVerified ? ', derived from the code' : ', which was rated on a CLAIMED impact Stage 1 did not establish'}`
    : '',
  capped.note,
  // The fallback can land on a number that is itself unreadable. Stage 1 refuses to
  // return one, so this needs an upstream that is not Stage 1 — but `verification`
  // arrives as an argument, and a rating that no cap could be applied to must say
  // so rather than ship under a note claiming Stage 1's number stands.
  capped.ambiguous ? `and no cap could be applied to it: ${capped.ambiguous}` : '',
]
  .filter(Boolean)
  .join('; ')
if (severityNote) log(severityNote)

// BEFORE the summary's own gate, and the order is load-bearing. A duplicate is a
// fact a past-bug agent established with a link; the summary agent's job is to write
// it up, and its failure to do so cannot unmake it. The other way round, the single
// most likely summary defect — an empty `openQuestions`, which is why that gate
// exists at all — would downgrade "already publicly reported at GHSA-x" to
// NEEDS_MORE_INFO, discarding a terminal answer the stage had already paid for and
// sending the next reader to buy it again.
//
// `summary` is still returned, and may be null or incomplete: the duplicate finding
// does not depend on it.
if (cited.length > 0) {
  const where = cited.map((r) => `${r.source}: ${dupCite(r)}`).join('; ')
  log(`DUPLICATE: already publicly reported — ${where}`)
  return {
    status: 'DUPLICATE',
    reason: `already publicly reported — ${where}`,
    // Under the same keys every other terminal return uses. Without them this is
    // the one non-BLOCKED status carrying a `summary` and no corrected number,
    // leaving the pre-cap `summary.finalSeverity` as the only one a reader can reach.
    severity: capped.severity,
    severityCorrection: severityNote,
    policy,
    reachability,
    scope,
    pastBugs: searched,
    unsearched,
    beyondCap,
    census: { state: censusState, why: censusWhy, result: census },
    summary,
  }
}

const summaryIssue = summaryProblem(summary)
if (summaryIssue) {
  log(`NEEDS_MORE_INFO: ${summaryIssue}`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: summaryIssue,
    ...stageOneStands(args),
    policy,
    reachability,
    scope,
    pastBugs: searched,
    unsearched,
    beyondCap,
    census: { state: censusState, why: censusWhy, result: census },
  }
}


// SUMMARY_SCHEMA withholds `out-of-scope` from this enum, and an enum is not a
// gate: `required` is the only thing the runtime validator enforces, as three
// comments in this file already say. So the one verdict that ends the analysis —
// the one SCOPE_SCHEMA makes cost a quoted clause, and `scopeHalt` refuses
// without one — can still be written here, where there is no clause field at
// all, and SKILL.md tells the orchestrator to take the scope from `summary`. The
// output is "OUT OF SCOPE" with nothing after the dash.
//
// Read affirmatively, like every other gate in this file, and surfaced at the top
// level beside the corrected severity, which is where SKILL.md reads it.
const scopeVerdict = summary.scopeVerdict === 'in-scope' ? 'in-scope' : 'unclear'
if (scopeVerdict !== summary.scopeVerdict) {
  log(`summary returned scopeVerdict '${summary.scopeVerdict}', which this step cannot decide; reporting unclear`)
}

log(`Online triage complete: ${scopeVerdict}, severity ${capped.severity} (confidence ${summary.confidence}).`)
return {
  status: 'TRIAGED',
  // Normalised, not the agent's own string. See above.
  scopeVerdict,
  // The cap corrects the NUMBER, and `summary.reasoning` is the argument for the
  // pre-cap one. Relayed verbatim, as SKILL.md's Completion Gate requires, it
  // prints a Medium next to a paragraph arguing Critical, so the correction rides
  // with the text it corrects rather than only in `severityCorrection`.
  reason: severityNote ? `${summary.reasoning} — ${severityNote}` : summary.reasoning,
  // The corrected number, under the same keys Stage 1 surfaces it with. Reading
  // `summary.finalSeverity` directly reads the pre-cap one.
  severity: capped.severity,
  severityCorrection: severityNote,
  policy,
  reachability,
  scope,
  pastBugs: searched,
  unsearched,
  beyondCap,
  census: { state: censusState, why: censusWhy, result: census },
  summary,
}
