export const meta = {
  name: 'triage-poc',
  description:
    'Stage 3: build a working PoC against the real code, execute it, then have five agents that did not build it try to reject it, and derive the confidence band',
  whenToUse:
    'Only when the user asked to validate by PoC, and only after triage-static returned TRUE_POSITIVE. Builds in an isolated worktree; every challenge is judged by an agent that did not build the PoC.',
  phases: [{ title: 'Build' }, { title: 'Challenges' }, { title: 'Report' }],
}

// args: { baseDir, finding, verification, envelope, candidates[] }
//
// `verification` is triage-static's return value, forwarded verbatim.
//
// Build and review are one script rather than two dispatches because the PoC is
// the only thing that crosses between them, and split, that hand-off is a
// standing hazard: the build gate and the review stage's arg validator would have
// to agree on eight field names by hand, with nothing checking that they do. A
// builder returning whitespace for `path` or `pocType` clears one and is rejected
// by the other, discarding a build that has already been paid for. One script
// means one definition of an acceptable build, in one place.

// `args || {}`: an absent args object makes this destructure throw before
// missingArgs can return BLOCKED.
const { baseDir, finding, verification, envelope, candidates = [] } = args || {}

const MAX_ATTEMPTS = 2

const POC_SCHEMA = {
  type: 'object',
  // Extra keys are rejected rather than accepted and ignored: a builder that
  // returns a field this script never contracted for means the prompt and the
  // schema have drifted, and silently dropping it hides which one is stale.
  additionalProperties: false,
  // EVERY field isAcceptableBuild gates on is required. Being named in the
  // prompt is a request; `required` is enforced by the runtime validator, which
  // retries the agent until it complies. Omit one and a PoC that built, executed
  // and linted clean fails the gate, burns the retry, and comes back as
  // BUILD_FAILED. A failed build satisfies these with empty strings, which the
  // gate reads as falsy anyway, so requiring them costs a failure nothing.
  required: [
    'built',
    'pocType',
    'path',
    'absolutePath',
    'executed',
    'lintPassed',
    'command',
    'output',
    'invokedSymbol',
  ],
  properties: {
    built: { type: 'boolean' },
    pocType: { enum: ['test-integrated', 'standalone', 'testnet'] },
    path: { type: 'string', description: 'repo-relative path to the PoC' },
    absolutePath: {
      type: 'string',
      description:
        'absolute path to the PoC file; the builder runs in an isolated worktree, so a repo-relative path does not resolve for the reviewers',
    },
    command: { type: 'string', description: 'exact command that runs it' },
    executed: { type: 'boolean' },
    outputPath: { type: 'string', description: 'file holding the captured run output' },
    output: { type: 'string', description: 'the captured output itself, verbatim' },
    invokedSymbol: { type: 'string', description: 'the real symbol under test that the PoC calls' },
    lintPassed: { type: 'boolean' },
    failureReason: { type: 'string', description: 'set when built is false' },
  },
}

const CHALLENGE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['challenge', 'rebuttal', 'winner', 'evidence', 'reference', 'complete'],
  properties: {
    challenge: { type: 'string', description: 'the strongest argument against the finding' },
    rebuttal: { type: 'string', description: 'the evidence-based answer, or why there is none' },
    winner: { enum: ['CHALLENGE', 'REBUTTAL'] },
    evidence: { type: 'string' },
    // Challenge 4's win RETRACTS the finding, so it has to point at something —
    // and `evidence` cannot be that something, because every one of the five
    // challenges is required to fill it, so a non-blank check on it is satisfied
    // by any prose at all ("the sink was rewritten during a later refactor").
    // Same field, same rule and same reason as HISTORY_SCHEMA's `reference` one
    // workflow over: required so the model is asked, empty when there is nothing
    // to cite, and `alreadyFixedStands` reads it rather than the prose.
    reference: {
      type: 'string',
      description: 'challenge 4 only: the commit, PR, issue or advisory ID for the fix. Empty for the other four',
    },
    // Required for the same reason `reference` is, and against the same failure.
    // A fix that closes one of two sinks is not a retraction, but with no field
    // for it the complete-or-partial answer challenge 4's prompt asks for arrives
    // as prose and nothing reads it — leaving `alreadyFixedStands` to retract on
    // ANY cited award and discard a demonstrated, still-live bug whole. Required
    // rather than optional, because an omitted boolean is `undefined`, which is
    // not `false`, and the gate below reads anything but an affirmative `true` as
    // partial — so an optional field would silently switch the retraction off
    // rather than default it to the safe answer.
    complete: {
      type: 'boolean',
      description: 'challenge 4 only: true only if the fix is WHOLE. false for a partial fix and for the other four',
    },
    impactCorrection: { type: 'string', description: 'set if the true impact is weaker than claimed' },
  },
}

// A workflow script has no Bash, so nothing here can confirm the linter ran or
// the PoC executed — `built`, `executed` and `lintPassed` are three booleans the
// builder fills in itself. This agent is what makes "enforced by poc-lint.sh,
// not by good intentions" true: it has Bash and, because the builder reports
// absolutePath, it has a file it can actually open.
const ARTIFACT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['fileExists', 'lintExitZero', 'reimplementation', 'reRun', 'reRunNotes', 'evidence'],
  properties: {
    fileExists: { type: 'boolean' },
    lintExitZero: { type: 'boolean', description: 'poc-lint.sh exited 0 when YOU ran it' },
    lintOutput: { type: 'string' },
    // Principle 5, and the ONLY place it is decided. poc-lint.sh's
    // `possible-reimplementation` is a NOTE that exits 0, because a grep cannot
    // tell a façade re-export, a pytest fixture or a local driver from a copy of
    // the target — made fatal it would return BUILD_FAILED on all three. But a
    // note enforces nothing on its own: a PoC that pastes the vulnerable function
    // in and exercises the copy passes the note AND rule 8, because the copy's
    // own definition supplies the mention rule 8 looks for. So the linter reports
    // the fact and this gate decides on it: the reviewer compares the logic, and
    // only the two clearing values clear. This agent has Bash and both files, so
    // it is the one reader that can answer it; `artifactProblem` reads the answer.
    //
    // Required, and graded affirmatively below: an omitted or unrecognised value
    // is not a clearance. Three values rather than a boolean because the note
    // names three outcomes and "false" would collapse "no definition at all" with
    // "a definition I checked and cleared".
    reimplementation: {
      enum: ['NOT_DEFINED', 'LOCAL_DRIVER', 'COPY_OF_TARGET'],
      description:
        'does the PoC contain a copy of the code under test, under ANY name? NOT_DEFINED: it holds no copy and calls the imported symbol. LOCAL_DRIVER: it defines that name but the body is not the target\'s logic. COPY_OF_TARGET: the vulnerable logic was pasted in, whatever it was renamed to',
    },
    // The independent re-run, and the only field here filled by someone who
    // actually ran the PoC — the builder's `executed` is a self-report in a script
    // with no Bash. Three values for the reason `reimplementation` above has
    // three: as a boolean, `false` meant both "I ran it and the impact did not
    // happen" and "there is no Elasticsearch on this host", and the prompt asked
    // for the same `false` for both. Those are opposite results, so the field
    // could not be gated on in either direction and was gated on in neither —
    // which is how a PoC whose independent reviewer reported the balance
    // unchanged came back REPORTED at High, the status SKILL.md maps to TRUE
    // POSITIVE. Graded affirmatively below: an omitted or unrecognised answer is
    // not a reproduction.
    reRun: {
      enum: ['REPRODUCED', 'DID_NOT_REPRODUCE', 'COULD_NOT_RUN_HERE'],
      description:
        'you ran the PoC command yourself. REPRODUCED: it ran and the impact happened. DID_NOT_REPRODUCE: it ran to completion and the impact did not happen. COULD_NOT_RUN_HERE: it could not be run on this host at all — a missing service, a target that is not this machine',
    },
    reRunNotes: {
      type: 'string',
      description: 'what you observed; for COULD_NOT_RUN_HERE, what stopped it running here',
    },
    evidence: { type: 'string' },
  },
}

const REPORT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['severity', 'severityRationale', 'reportPath', 'unproven'],
  properties: {
    severity: { enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'] },
    severityRationale: { type: 'string' },
    reportPath: { type: 'string' },
    unproven: { type: 'string', description: 'what this PoC does not establish' },
  },
}

// Checkpoint 5.1 asks the author to write both the challenge and the rebuttal and
// then declare a winner. The author awards the rebuttal. These five are the same
// questions, judged by agents that never saw the PoC being built, so the verdict
// is a verdict rather than a formality.
const CHALLENGES = [
  {
    key: 'reachable',
    prompt: `Challenge 1. Argue that the attacker CANNOT reach the vulnerable code.
Look for validation, authorization, or routing that the PoC's setup bypasses
artificially — a test fixture that constructs state no real caller could reach is
the usual way this finding is wrong.

This is the challenge that separates a real finding from the most common false
positive there is, so hold it to the entry point rather than to the sink. A PoC
that calls the vulnerable function directly genuinely demonstrates attacker
control OF THE SINK; that is not control of any reachable entry point.`,
  },
  {
    key: 'recoverable',
    prompt: `Challenge 2. Argue that the impact is LESS than claimed.
Read ${baseDir}/references/recovery-mechanisms.md. Check the runtime's actual
recovery behaviour rather than assuming none. Two facts flip a Critical to a Low
more often than any others: Go's net/http recovers per-connection in conn.serve,
so a handler panic closes that one connection and writes no status — it is not a
500 and not a dead server; and recover() does not cross goroutine boundaries. If
the true impact is weaker, set impactCorrection.`,
  },
  {
    key: 'by-design',
    prompt: `Challenge 3. Argue that this is INTENDED behaviour.
Read ${baseDir}/references/validation-dimensions.md. Check privilege indicators,
symmetric guarded/unguarded sibling paths, and whether documentation or tests
cover it as normal operation. Centralized control is not by itself a bug.

Also apply the specified- and documented-behaviour grounds from
${baseDir}/references/dismissal-grounds.md: behaviour a
specification requires, or that the project documents and warns about, is not a
bug in this project. Both carry a nuance that inverts them — an implementation
claiming stricter behaviour than the spec, and downstream code violating
documented guidance — so check those before awarding the challenge.`,
  },
  {
    key: 'already-fixed',
    prompt: `Challenge 4. Argue that this is ALREADY FIXED.
Search the git log for the relevant paths, the issue tracker, release notes, and
published advisories. Report what you searched and what you found. If a fix
exists, set \`complete\`: true only if it closes the finding outright, false if
it leaves any part of it live — a second sink, one caller of two, a narrower
input class.

Stage 1 ran this search too, and its result is quoted above. You are not
repeating it for its own sake: a fix landing one layer up from the sink is the
shape that gets missed, and you are looking at a built, executed PoC that Stage 1
did not have. If the PoC passes against HEAD, that is evidence; say so.

Awarding this challenge on a WHOLE fix retracts the finding outright, so it has
to point at something: put the commit, PR, issue or advisory ID in \`reference\`,
on its own and not merely described in \`evidence\`. Both conditions are enforced
in code and neither is refused quietly. A \`complete\`: true win whose
\`reference\` is not a citation — blank, \`n/a\`, \`see evidence\`, a bare
file:line — ENDS THE STAGE as NEEDS_MORE_INFO, so award it that way only if you
can name the fix. A win on a partial fix does not retract and does not end
anything: the finding is reported, with the partial fix recorded against it.`,
  },
  {
    key: 'real-deployment',
    prompt: `Challenge 5. Argue that this is NOT exploitable in real deployments.
Is the vulnerable path reachable in a default configuration? Do real deployments
add protections in front of it — a proxy, a WAF, a non-default flag? Is the code
path ever actually used?`,
  },
]

// Pure. The Stage 1 statuses that are a SETTLED ANSWER rather than a defective
// dispatch: the finding was analysed and did not survive.
//
// It exists because the arg gate below is right about the outcome and wrong
// about the reason, and the wrong reason is what this plugin's most expensive
// failure mode feeds on. Without it, a settled finding comes back as "triage-poc
// received an unusable arg shape: verification.status (...). Forward
// triage-static's return value verbatim" — a complaint about the CALLER, on a
// dispatch where the caller did everything right. The orchestrator is still
// holding a user request for a PoC, reads that as "your dispatch was wrong, try
// again", finds it cannot be made right, and builds the exploit by hand instead.
//
// What it falls back to is the behaviour this whole stage exists to replace: a
// hand-built PoC calls the sink directly, executes real command injection, and
// leads with "Confirmed command injection" — while the route that reaches the
// sink does not exist.
//
// So this path builds nothing, spends nothing and relaxes nothing; the exploit is
// refused exactly as the arg gate would refuse it. All it changes is that the
// refusal is stated in terms of the finding rather than in terms of the
// arguments, and names the deliverable that takes the PoC's place.
//
// NEEDS_MORE_INFO and BLOCKED are deliberately NOT here. Neither is an answer:
// one is a fact still to establish, the other an analysis that could not run,
// and both are resolved by re-running Stage 1 rather than by writing anything
// up. They keep the arg gate's message, which is the one that tells the caller
// to go back. An unrecognised status is absent for the reason a fall-through
// pass is wrong everywhere else in this plugin.
//
// The list is inline rather than hoisted to a const: the tests extract this
// function and evaluate it alone, where a free variable is a ReferenceError.
// review.test.mjs pins the literal against the statuses SKILL.md tells the
// orchestrator how to report, so the two cannot drift.
function settledByStageOne(a) {
  const verification = (a && a.verification) || {}
  const status = typeof verification.status === 'string' ? verification.status.trim() : ''
  // Every entry must be a status triage-static can actually emit. A status no
  // workflow can produce reads as coverage this list does not have, and nothing
  // fails when it drifts out of the producing end — it simply never matches.
  const settled = [
    'FALSE_POSITIVE',
    'NOT_EXPLOITABLE',
    'NOT_VULNERABLE',
    'ALREADY_FIXED',
    'OUT_OF_SCOPE',
  ]
  if (!settled.includes(status)) return null
  // Trimmed for the same reason every other relayed string in this file is:
  // `reason: '   '` is truthy and would reach the orchestrator as a verdict
  // that explains itself with blank space.
  return { status, reason: String(verification.reason || '').trim() }
}

// Pure. Same guard as triage-static, and here the failure is worse than an
// `undefined` in a prompt: `envelope.hosts.join()` and
// `verification.impact.impact` are nested accesses, so a missing or misnamed arg
// throws a TypeError and kills the run mid-prompt-construction.
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
  const impact = (a && a.verification && a.verification.impact) || {}
  const history = (a && a.verification && a.verification.history) || {}
  const envelope = (a && a.envelope) || {}

  need('baseDir', a && a.baseDir)

  // `baseDir` needs its SHAPE checked and not only its PRESENCE, because the two
  // paths a caller might supply are equally present and only one of them works.
  // The working directory is the TARGET repo, so a caller that reconstructs the
  // path instead of copying it passes the target's root: every read under
  // `${baseDir}/references/` 404s, the impact agent cannot open
  // dismissal-grounds.md, the gate agent cannot open false-positive-patterns.md,
  // and both answer from memory. Nothing else about the dispatch differs — the
  // finding, the impact and the severity are identical — so the whole of the
  // difference is which files the agents downstream can open, which is why this
  // is worth a gate rather than a convention.
  //
  // A workflow has no filesystem access, so existence cannot be checked here. The
  // SHAPE can be, and the shape is what a reconstructed path gets wrong: the one
  // that works is an absolute path ending in the skill directory. Reported rather
  // than silently tolerated, because the failure is otherwise invisible — an agent
  // that cannot read its reference file carries on and answers from memory.
  //
  // Written without a regex literal on purpose: the Python contract suite lexes
  // these scripts to strip strings and comments, and it REJECTS a regex literal
  // rather than risk mis-lexing one (test_a_regex_literal_is_rejected_rather_than_mis_lexed).
  // One here turns that whole suite red on unmutated code, and a mutation whose
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
  need('verification.impact.impact', impact.impact)
  need('verification.impact.rootCause', impact.rootCause)
  need('verification.impact.classification', impact.classification)
  need('verification.severity', a && a.verification && a.verification.severity)
  // Challenge 4 is told what Stage 1 already searched so it can look somewhere
  // else rather than repeat it. Required rather than optional: a nested access
  // on a missing `history` throws mid-prompt-construction, and forwarding
  // triage-static's return value verbatim always carries it.
  need('verification.history.fixed', history.fixed)
  need('verification.history.searched', history.searched)
  // "Only a TRUE POSITIVE justifies building" cannot be left to the orchestrator
  // to honour. triage-static's failing returns carry a fully populated `impact`
  // and `severity`, so forwarding a FAILED verification verbatim — exactly what
  // the orchestrator is told to do with a passing one — satisfies every other
  // field here and buys a PoC for a finding that failed its own gates. A blocking
  // gate the caller can skip by not reading it is not a gate.
  //
  // This is still the only gate on the build path. settledByStageOne runs
  // earlier and reaches the same outcome for the five statuses that are a
  // verdict; what is left here is everything else — NEEDS_MORE_INFO, BLOCKED, a
  // status this script does not recognise, and an absent one — for which "go
  // back and correct the dispatch or re-run Stage 1" is the right instruction.
  // Removing this check would let all of those through.
  const status = (a && a.verification && a.verification.status) || ''
  if (status !== 'TRUE_POSITIVE') {
    // The message says TRUE_POSITIVE and not "cleared all six gates", because
    // those are not the same criterion: a carried question blocks a TRUE_POSITIVE
    // in code, so Stage 1 can pass all six gates and still return
    // NEEDS_MORE_INFO. An open question is a fact to resolve rather than a finding
    // to demonstrate, and this gate refuses it either way — but a rejection that
    // names a criterion the finding DID meet sends the reader to the wrong place
    // to fix it.
    missing.push(
      `verification.status (must be 'TRUE_POSITIVE'; got ${status ? `'${status}'` : 'nothing'} — only a finding Stage 1 confirmed outright justifies building an exploit. Six passing gates are necessary and not sufficient: an unresolved uncertainty still returns NEEDS_MORE_INFO, and that is a missing fact to answer rather than a bug to demonstrate)`,
    )
  }
  // 'any': `level` is an INTEGER, and its type and range are graded by the 1-5
  // check below. Demanding a string here would reject every well-formed envelope.
  need('envelope.level', envelope.level, 'any')
  if (!Array.isArray(envelope.hosts)) missing.push('envelope.hosts (must be an array)')
  if (typeof envelope.destructive !== 'boolean') {
    missing.push('envelope.destructive (must be a boolean)')
  }
  // safety-guidelines.md defines exactly five levels. Anything else reaches the
  // builder as "target level: 9", which reads as authoritative and constrains
  // nothing.
  if (envelope.level !== undefined && envelope.level !== null && envelope.level !== '') {
    if (!Number.isInteger(envelope.level) || envelope.level < 1 || envelope.level > 5) {
      missing.push('envelope.level (must be an integer 1-5, per safety-guidelines.md)')
    }
  }
  // An envelope may not authorise what the level forbids. Level 3 is read-only,
  // 4 is a minimal non-destructive probe on a live system, and 5 is nothing at
  // all without written authorization — so `destructive: true` above level 2 is
  // self-contradictory. Telling the builder it may not widen the envelope does
  // not help when the envelope itself is the thing that is wrong: it would read
  // "destructive operations authorised: yes" against production.
  if (envelope.destructive === true && Number.isInteger(envelope.level) && envelope.level >= 3) {
    missing.push(
      `envelope.destructive (true is not permitted at level ${envelope.level}; safety-guidelines.md allows destructive operations only at levels 1-2)`,
    )
  }
  // A non-array `candidates` must be REPORTED, not thrown on: `.entries()` is
  // undefined on an object or string, and the throw would escape missingArgs
  // itself, killing the run with no BLOCKED result.
  const cands = a && a.candidates
  if (cands !== undefined && cands !== null && !Array.isArray(cands)) {
    missing.push('candidates (must be an array)')
  } else {
    for (const [i, c] of (Array.isArray(cands) ? cands : []).entries()) {
      // Through `need`, so the same type discipline covers the per-item fields:
      // each of these is interpolated into the builder prompt verbatim.
      need(`candidates[${i}].description`, c && c.description)
      need(`candidates[${i}].entryPoint`, c && c.entryPoint)
      need(`candidates[${i}].payload`, c && c.payload)
    }
  }
  return missing
}

// Ahead of the arg gate, deliberately. A settled finding is the more useful
// answer than a list of fields, and it is the same answer whether or not the
// rest of the dispatch is well formed — nothing below this line runs either way.
// Dispatched with only a `verification`, the arg gate buries "Stage 1 already
// decided this" under a dozen field names.
//
// The status stays BLOCKED because BLOCKED means "this stage did not run", which
// is exactly and correctly what happened. What tells a settled finding from a
// malformed dispatch is `settledBy`, a field rather than a prefix of prose. When
// several outcomes share one status and are told apart by pattern-matching the
// `reason`, whatever mapping the reader settles on is wrong for most of them:
// that is how a retraction, a false positive and an incomplete report all end up
// reported as FALSE POSITIVE under DO_NOT_SUBMIT.
const settled = settledByStageOne(args)
if (settled) {
  log(`BLOCKED: Stage 1 settled this as ${settled.status}; there is no exploit to build.`)
  return {
    status: 'BLOCKED',
    settledBy: settled.status,
    reason: `Stage 1 settled this finding as ${settled.status}${settled.reason ? `: ${settled.reason}` : ''}. No exploit is owed and nothing here is missing — a finding that did not survive Stage 1 has nothing to demonstrate.`,
    deliverable:
      "Report Stage 1's verdict and the evidence behind it as the answer to the PoC request; that verdict IS the deliverable. Do not build an exploit by hand and do not re-dispatch this workflow — see \"When the user asked for a PoC and Stage 1 said no\" in SKILL.md, including what a negative PoC may and may not do.",
  }
}

const argProblems = missingArgs(args)
if (argProblems.length > 0) {
  log(`BLOCKED: dispatch contract violated — ${argProblems.join(', ')}`)
  return {
    status: 'BLOCKED',
    reason: `triage-poc received an unusable arg shape: ${argProblems.join(', ')}. Forward triage-static's return value verbatim as \`verification\`; see the Dispatch section of SKILL.md.`,
  }
}

// Pure, so the cap and the empty case can be graded without a model.
function selectAttempts(all, max) {
  const chosen = Array.isArray(all) ? all.slice(0, max) : []
  return { chosen, heldBack: Array.isArray(all) ? all.length - chosen.length : 0 }
}

// Built, executed, and lint-clean. Anything less is a failure, including a null
// from a dead builder agent.
//
// Trimmed, not merely truthy. JSON Schema `required` checks presence and not
// content, so `output: '   '` is schema-valid: on a truthiness test a builder
// reporting whitespace for all of them clears this gate and returns BUILT, and
// that whitespace reaches all five challenge prompts as the "Captured output"
// they are meant to judge.
//
// The string list is inline rather than hoisted to a const: the tests extract
// this function and evaluate it alone, where a free variable is a ReferenceError.
// test_the_build_gate_covers_every_field_the_reviewers_read pins it against the
// fields the challenge and artifact prompts interpolate, so a field this gate
// lets through cannot reach a reviewer as blank.
// The three booleans are compared to `true` rather than read by truthiness, for
// the reason every other gate in this file grades affirmatively: `required` is
// the only thing the runtime validator enforces and `type` is advisory, so
// `built: 'no'`, `executed: 'false'` and `lintPassed: 'failed'` are all
// schema-valid answers that a truthiness test reads as YES. Each one cleared this
// gate, and a build the builder itself said did not happen went on to five
// reviewers and reached REPORTED at HIGH confidence. `!result` stays in front of
// the chain because a dead builder agent yields null and `null.built` throws.
function isAcceptableBuild(result) {
  if (!result || result.built !== true || result.executed !== true || result.lintPassed !== true) return false
  return ['absolutePath', 'path', 'pocType', 'command', 'output', 'invokedSymbol'].every(
    (f) => typeof result[f] === 'string' && result[f].trim() !== '',
  )
}

// ------------------------------------------------------------------- Build
//
// This deliberately does NOT fan out. PoC construction needs one long context
// with an iterative debug loop; N parallel builders would burn N environments to
// produce one artifact. The retry re-attempts with a different attack path rather
// than taking a second opinion on the same one.

phase('Build')

const { chosen: attempts, heldBack } = selectAttempts(candidates, MAX_ATTEMPTS)
if (heldBack > 0) {
  log(`${heldBack} candidate path(s) held in reserve, not attempted.`)
}
if (attempts.length === 0) {
  log('No candidate attack paths supplied; nothing to build.')
  return { status: 'NO_CANDIDATES', reason: 'no candidate attack paths supplied' }
}

let poc = null
let lastFailure = null

for (let i = 0; i < attempts.length; i++) {
  const candidate = attempts[i]
  const retryContext = lastFailure
    ? `\n\nA previous attempt on a different path failed. Do not repeat it.\nPrevious path: ${lastFailure.candidate}\nWhy it failed: ${lastFailure.failureReason || 'unknown'}`
    : ''

  const result = await agent(
    `Build a working PoC for this finding. It cleared all six gates in Stage 1; your
job is to demonstrate it, and to fail honestly if it cannot be demonstrated.

Finding: ${finding.summary}
Verified impact: ${verification.impact.impact}
Classification: ${verification.impact.classification}
Severity so far: ${verification.severity}
Attack path to use: ${candidate.description}
Entry point: ${candidate.entryPoint}
Payload: ${candidate.payload}

Choose the PoC type, cheapest first:
  1. test-integrated  (PREFERRED when a test suite exists — the project's own
     harness gives you the real-code invocation for free)
  2. standalone script
  3. testnet demonstration
See ${baseDir}/references/test-integration.md for framework patterns. A
test-integrated PoC must FAIL while the vulnerability exists and PASS once it is
fixed; write the docstring to match the assertion, not the other way round.

Implement it. This rule is not negotiable: import and call the real code under
test. Never copy the vulnerable function into the PoC and exercise the copy.
Mocking dependencies is fine; mocking the vulnerable component itself is not.
Record the real symbol you invoke as invokedSymbol. See
${baseDir}/references/poc-anti-patterns.md.

Drive it through the ENTRY POINT, not the sink. A PoC that calls the vulnerable
function directly proves the sink is dangerous in isolation, which was never in
question — an independent reviewer's first challenge is that your setup
constructs state no real caller could reach, and a direct-to-sink PoC hands them
that argument. If reaching the sink through the entry point turns out to be
impossible, that is the finding: set built=false and say so.

Then actually run it and capture the full output to a file. A PoC that has not
been executed does not pass this stage.

You are working in an isolated git worktree, not the session's working tree.
Nothing downstream shares it: the reviewers who judge this PoC, the report that
cites it, and the user who has to run it all sit outside this directory, so a
repo-relative path resolves to nothing for every one of them. Report
absolutePath, and make outputPath absolute too.

Safety envelope, which you may not widen:
  permitted hosts: ${envelope.hosts.length ? envelope.hosts.join(', ') : 'NONE — local process only, no network target'}
  destructive operations authorised: ${envelope.destructive ? 'yes' : 'NO'}
  target level: ${envelope.level}
If the exploit cannot be demonstrated inside this envelope, set built=false and
say so. Do not improvise a broader target.

Before returning, run:
  ${baseDir}/scripts/poc-lint.sh --symbol <the symbol under test> <your poc file>
It must exit 0. Fix what it reports; do not work around it. A
\`possible-reimplementation\` NOTE does not fail it — grep cannot tell your own
driver from a copy of the target — but it is exactly the Principle 5 question,
so satisfy it by importing the real symbol rather than by renaming anything. A
reviewer who can open both files settles it after you — on the logic, under
whatever name — and a copy ends this stage as BLOCKED, so renaming past the note
buys nothing.
Report the outcome as
lintPassed — the build gate reads that field, and an independent reviewer re-runs
this exact command against your absolutePath afterwards, so reporting true
without a clean run is caught rather than believed.

A successful return must carry all of: built, executed, lintPassed, pocType,
path, absolutePath, the exact command that runs it, the captured output verbatim,
and invokedSymbol. The gate rejects a build missing any of them, so omitting one
discards a PoC that actually worked.${retryContext}`,
    {
      label: `build:${candidate.name || i + 1}`,
      phase: 'Build',
      schema: POC_SCHEMA,
      isolation: 'worktree',
      effort: 'high',
    },
  )

  if (isAcceptableBuild(result)) {
    poc = result
    log(`PoC built (${result.pocType}) at ${result.path} and executed.`)
    break
  }

  // Trimmed, not merely truthy, for the same reason isAcceptableBuild trims: a
  // schema-valid `failureReason: '   '` is truthy, and this string is both
  // BUILD_FAILED's `reason` — which SKILL.md tells the orchestrator to relay as the
  // missing fact — and the next attempt's "Why it failed:", either of which would
  // otherwise read as blank space.
  lastFailure = {
    candidate: candidate.description,
    failureReason: result
      ? String(result.failureReason || '').trim() || 'built/executed/lint gate not satisfied'
      : 'builder agent failed',
  }
  log(`Attempt ${i + 1} failed: ${lastFailure.failureReason}`)
}

if (!poc) {
  log('Every attempted path failed to produce an executed, lint-clean PoC.')
  return {
    status: 'BUILD_FAILED',
    reason: lastFailure.failureReason,
    attempted: attempts.length,
    heldBack,
  }
}

// -------------------------------------------------------------- Challenges

phase('Challenges')

// Hoisted so the parallel() call below stays short enough for
// test_no_unbounded_fanout to see that it fans out over CHALLENGES, a
// script-local array literal, and is therefore bounded by construction.
const ARTIFACT_PROMPT = `Verify the PoC artifact itself. Steps 1, 2 and 4 are facts; step 3 is the one
judgement here, and it is yours because you are the only reader with both files
open.

PoC file: ${poc.absolutePath}
Symbol under test: ${poc.invokedSymbol}
Command the builder says runs it: ${poc.command}

Do these, with Bash:
  1. Confirm the file exists and read it.
  2. Run: ${baseDir}/scripts/poc-lint.sh --symbol '${poc.invokedSymbol}' '${poc.absolutePath}'
     Set lintExitZero TRUE if it exited 0 and FALSE otherwise, and paste its
     output as lintOutput. It is a boolean, not the exit code: reporting the
     number 0 there says the opposite of what a clean run means.
     The builder reported that this passes; you are the one who checks.
     If it prints a \`possible-reimplementation\` NOTE, that is not a lint
     failure and must not be reported as one — it is the one Principle 5
     question grep cannot answer, handed to you because you can open both files.
  3. Answer that question in \`reimplementation\`, whether or not the note
     printed. Open the PoC and open ${finding.sink}, and compare the LOGIC, not
     the name:
       NOT_DEFINED      the PoC holds no copy of that logic under ANY name;
                        it imports ${poc.invokedSymbol} and calls the real one
       LOCAL_DRIVER     it defines that name, but the body is setup, a fixture,
                        a façade re-export or a harness — not the target's logic
       COPY_OF_TARGET   the vulnerable logic itself was pasted in, whatever it
                        was renamed to. A copy under a DIFFERENT name is this
                        answer and not NOT_DEFINED: rule 6 keys on the leaf, so
                        it prints no note, and rule 8 is satisfied by a mention
                        in a comment — you are the only check left
     COPY_OF_TARGET ends this stage as BLOCKED, because such a PoC proves the
     copy is broken and nothing about the application. Put the two locations you
     compared in \`evidence\`, whichever of the three you answer; a blank one
     ends this stage as BLOCKED too.
  4. Run the command above yourself and answer \`reRun\` with ONE of three, which
     is the whole of checkpoint 4.3 — "the output demonstrates the vulnerability",
     decided by the one reader who did not build this:
       REPRODUCED          it ran and the impact happened
       DID_NOT_REPRODUCE   it ran to completion and the impact did not happen
       COULD_NOT_RUN_HERE  it could not be run on this host at all
     Grade the impact, not the exit code: the preferred test-integrated PoC is
     written to FAIL while the vulnerability exists, so a red test there IS a
     reproduction and \`reRun\` is REPRODUCED.
     DID_NOT_REPRODUCE ends this stage as BLOCKED: the builder's captured output
     is otherwise the only evidence the PoC ever worked. Say what you saw in
     \`reRunNotes\`.
     COULD_NOT_RUN_HERE is for an environmental boundary and only that — a missing
     service, a target that is not this machine. It is a boundary to record rather
     than a failure to hide, and not a result: the stage continues and the report
     puts it in "unproven". Say what stopped it in \`reRunNotes\`; a blank one ends
     this stage as BLOCKED, because "could not run" with no reason given cannot be
     told apart from not having tried. Do not answer it for a PoC that ran here and
     disappointed you — that is DID_NOT_REPRODUCE.

Report what you observed. Do not repair the PoC and do not re-run the linter
until it passes; a failing check is the finding.`

// The artifact check runs at `medium`, not `low`: three of its four steps are
// shell facts, but the Principle 5 verdict is a logic comparison across two
// files and does not survive a cheaper model. The comment sits here rather than
// beside the call so that test_no_unbounded_fanout still sees CHALLENGES inside
// its window.
const checks = await parallel([
  () => agent(ARTIFACT_PROMPT, { label: 'artifact-check', phase: 'Challenges', schema: ARTIFACT_SCHEMA, effort: 'medium' }),
  ...CHALLENGES.map((c) => () =>
      agent(
        `You are a skeptical auditor reviewing a PoC you did not build. Your job is to
REJECT it if you honestly can.

Finding: ${finding.summary}
Location: ${finding.sink}
Claimed impact: ${verification.impact.impact}
Root cause: ${verification.impact.rootCause}
Severity so far: ${verification.severity}
Stage 1's already-fixed search: ${verification.history.fixed} — ${verification.history.searched}
PoC: ${poc.path} (${poc.pocType})
Read it at: ${poc.absolutePath}
  (it was built in an isolated worktree, so it is NOT under your working
   directory; open that absolute path. Challenge 1 in particular cannot be
   answered from the captured output alone — the PoC's setup is the evidence.)
Command: ${poc.command}
Symbol the PoC invokes: ${poc.invokedSymbol}
Captured output:
${poc.output}

${c.prompt}

State the strongest form of the challenge, then whether the evidence rebuts it.
If you cannot rebut it with evidence, the CHALLENGE wins. Uncertainty is not a
rebuttal.

\`reference\` and \`complete\` are required of all five of you and belong to
challenge 4 alone. Unless you are challenge 4 and are awarding it, return
\`reference\` as an empty string and \`complete\` as false. Omitting either fails
validation, and a challenge whose agent dies is counted as won by the challenge —
so leaving one out costs the finding a band step.`,
        { label: `challenge:${c.key}`, phase: 'Challenges', schema: CHALLENGE_SCHEMA, effort: 'high' },
        // `{...null}` is `{}`, so spreading unconditionally turns a dead agent
        // into a truthy phantom verdict: it survives .filter(Boolean), makes the
        // missing-agent count permanently 0, and reaches the report prompt as
        // "reachable: undefined".
      ).then((v) => (v ? { ...v, key: c.key } : null)),
  ),
])
const artifact = checks[0]
const verdicts = checks.slice(1).filter(Boolean)

// The barrier is justified: the confidence band is a decision over all five.

// Re-decided on what the reviewer observed rather than on what the builder
// claimed: the file is there, the linter exits 0, Principle 5 clears, and the
// PoC reproduced for someone who did not build it.
//
// That last one used to gate on nothing at all. `reRunSucceeded: false` said both
// "I ran it and the impact did not happen" and "there is no cluster on this host",
// so it could not be blocked on without turning an environmental boundary into a
// false dismissal — and was blocked on in neither direction. A PoC whose
// independent reviewer wrote "ran it; the balance is unchanged, the impact does
// not reproduce" therefore reached REPORTED at High, which SKILL.md maps to TRUE
// POSITIVE, on the strength of output the BUILDER captured. Every challenge
// prompt interpolates that same builder output, so the five reviewers could not
// catch it either. `reRun` splits the two, and only the environmental half is
// still carried to the report rather than blocking.
function artifactProblem(check) {
  if (!check) return 'the artifact-check agent returned nothing; the PoC was never independently verified'
  // Both compared to `true`, not read by truthiness, and the two directions this
  // closes are opposite. Reading by exclusion, `fileExists: 'no'` and
  // `lintExitZero: 'false'` are truthy strings that CLEARED the gate — a PoC with
  // no file at all, and one whose lint failed, each reached REPORTED at HIGH.
  // Reading a boolean field as an exit code fails the other way: `0` means a
  // clean run and is falsy, so a reviewer who answered the prompt literally
  // blocked a correct PoC. The prompt above now asks for the boolean in as many
  // words; this is the half of that fix the prompt cannot enforce.
  if (check.fileExists !== true) return 'no PoC file exists at the reported absolutePath'
  if (check.lintExitZero !== true) {
    return `poc-lint.sh did not exit 0 when an independent reviewer ran it, though the builder reported lintPassed: ${check.lintOutput || 'no output captured'}`
  }
  // Principle 5, decided here because it is decidable here and nowhere else.
  // Graded affirmatively — only the two values that CLEAR the PoC clear it — for
  // the reason every other gate in this plugin is: the enum is advisory, the
  // runtime validator enforces `required` alone, and by exclusion an omitted or
  // misspelt answer would read as a clearance. A copy is BLOCKED, not
  // DO_NOT_SUBMIT: the finding was not disproven, the artifact was.
  if (check.reimplementation !== 'NOT_DEFINED' && check.reimplementation !== 'LOCAL_DRIVER') {
    return `the PoC reimplements the code under test rather than importing it (reviewer verdict: ${check.reimplementation || 'none given'}): ${String(check.evidence || '').trim() || 'no evidence given'}. It proves the copy is broken, not that the application is exploitable — see the reimplementation section of references/poc-anti-patterns.md`
  }
  // And the CLEARING path is trimmed too, as every sibling gate in this file is.
  // `required` checks presence, not content, so `evidence: ''` validates: a
  // reviewer can clear Principle 5 having compared nothing, and the one check that
  // decides it collapses into a self-report. Both clearing answers are judgements
  // about the two bodies — NOT_DEFINED means no copy under ANY name, not merely
  // no symbol of that name — so both owe the locations they were reached from.
  if (!String(check.evidence || '').trim()) {
    return `the artifact check answered ${check.reimplementation} for Principle 5 without saying what it compared; the two locations opened are what makes that a check rather than an assertion`
  }
  // LAST, after the file, the lint and Principle 5, so that when several things
  // are wrong at once the more actionable reason still wins — the same ordering
  // rule 'file existence is checked before lint' pins one gate up.
  if (check.reRun === 'DID_NOT_REPRODUCE') {
    return `the PoC ran to completion for an independent reviewer and did not reproduce the impact: ${String(check.reRunNotes || '').trim() || 'no observation recorded'}. The builder's captured output is then the only evidence it ever worked, and checkpoint 4.3 asks that the output demonstrate the vulnerability`
  }
  // The environmental half owes its reason. "Could not run here" with nothing
  // behind it is indistinguishable from not having tried, and it is the answer
  // that BUYS a pass through this gate — so it is held to the standard the
  // Principle 5 clearance above is held to, and for the same reason.
  if (check.reRun === 'COULD_NOT_RUN_HERE' && !String(check.reRunNotes || '').trim()) {
    return 'the artifact check reported it could not run the PoC here but did not say what stopped it; an environmental boundary is only a boundary if it names itself'
  }
  // Affirmative, like `reimplementation` above and for the same reason: the enum
  // is advisory, the runtime validator enforces `required` alone, and by
  // exclusion an omitted or misspelt answer would buy the same pass a genuine
  // reproduction does.
  if (check.reRun !== 'REPRODUCED' && check.reRun !== 'COULD_NOT_RUN_HERE') {
    return `the artifact check gave no usable answer for the independent re-run (${check.reRun || 'nothing returned'}); REPRODUCED, DID_NOT_REPRODUCE and COULD_NOT_RUN_HERE are the three, and only the first says checkpoint 4.3 was met`
  }
  return null
}

// Pure. Tallies against the EXPECTED challenge list, not against whatever came
// back: a challenge with no verdict counts as won by the challenge, which is the
// stated rule. Tallying the returned array instead lets a dead agent raise
// confidence by shrinking the denominator.
//
// `answered` because "won by the challenge" and "nobody was there to argue" are
// the same entry otherwise, and the band branch below reported them with the same
// string — the one SKILL.md maps to FALSE POSITIVE. `missing` counts EXPECTED
// keys nobody answered rather than the size of the map, which a verdict filed
// under an unknown key — ignored everywhere else here — deflated, making the log
// undercount the agents that died.
function tallyChallenges(challengeVerdicts, expectedKeys) {
  const byKey = new Map((challengeVerdicts || []).filter(Boolean).map((v) => [v.key, v]))
  const unrebutted = []
  let defeated = 0
  for (const key of expectedKeys) {
    const v = byKey.get(key)
    if (v && v.winner === 'REBUTTAL') defeated += 1
    else unrebutted.push({ key, challenge: v ? v.challenge : 'no verdict returned', answered: Boolean(v) })
  }
  return { defeated, unrebutted, missing: unrebutted.filter((u) => !u.answered).length }
}

// checkpoints.md 5.1 challenge 4: "a fix exists -> the band does not get a vote".
// Takes the UNREBUTTED list, not the returned verdicts: every other challenge
// counts a missing verdict as won by the challenge, and the one challenge whose
// win overrides the band must not be the exception that escapes when its agent
// dies.
//
// It then requires the fix to be CITED, and returns that citation or null. This
// is triage-static's `upstreamFixStands` rule — `fixed: YES` with no reference is
// not a retraction — applied one stage later, and it matters more here: an
// unreferenced retraction is the one failure mode that silently discards a real
// finding, and what it would discard at this point is a built, executed,
// lint-clean PoC, on nothing better than an agent that died. The missing verdict
// still counts against the finding, in the only place it can honestly count:
// `tallyChallenges` has already lowered the band by it, and the report has to
// address it as unrebutted.
function alreadyFixedStands(unrebutted, challengeVerdicts) {
  if (!(unrebutted || []).some((v) => v && v.key === 'already-fixed')) return null
  const verdict = (challengeVerdicts || []).find((v) => v && v.key === 'already-fixed')
  // A PARTIAL fix is not a retraction — checkpoints.md 5.1: "an incomplete or
  // partial fix is reported as such". `!== true`, and for the same reason Stage
  // 1's `upstreamFixStands` uses it one workflow over: an omitted flag is
  // `undefined`, which is not `false`, so under a truthiness test a fix that
  // closed one of two sinks discards a demonstrated, still-live bug whole. A
  // partial fix falls through from here to the band, which has already counted
  // the challenge against the finding.
  if (!verdict || verdict.complete !== true) return null
  // `reference`, not `evidence`. Every challenge is required to fill `evidence`,
  // so reading the citation out of it makes the check unfalsifiable — any argued
  // win retracts. `reference` is the field that exists only to hold the commit,
  // PR, issue or advisory ID, exactly as HISTORY_SCHEMA's is, and `'   '` is
  // schema-valid in both. `citedReference` is the shared test of what counts.
  return citedReference(verdict.reference)
}

// Pure. Duplicated verbatim from triage-static.js — see the reasoning there.
// Two copies because these scripts have no module system, and the alternative to
// a duplicate is two divergent rules for one question.
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

// checkpoints.md 5.1, applied as code rather than self-reported.
// `total` is a defaulted parameter rather than a reference to CHALLENGES.length:
// the tests extract this function and evaluate it alone, where a free variable is a
// ReferenceError. test_the_band_total_matches_the_challenge_count pins the two.
function confidenceBand(defeated, total = 5) {
  if (defeated === total) return { label: 'HIGH', range: '90-100%', action: 'PROCEED' }
  if (defeated >= 3) return { label: 'MEDIUM', range: '50-89%', action: 'PROCEED_WITH_UNCERTAINTIES' }
  if (defeated >= 1) return { label: 'LOW', range: '10-49%', action: 'DO_NOT_SUBMIT' }
  return { label: 'NONE', range: '0-9%', action: 'DO_NOT_SUBMIT' }
}

const tally = tallyChallenges(verdicts, CHALLENGES.map((c) => c.key))
const defeated = tally.defeated
const lost = tally.unrebutted
const band = confidenceBand(defeated, CHALLENGES.length)

if (tally.missing > 0) {
  log(`${tally.missing} challenge agent(s) returned nothing; counted as won by the challenge.`)
}
log(`${defeated}/${CHALLENGES.length} challenges defeated → ${band.label} (${band.range})`)

// The band alone would let 4/5 defeated proceed on an already-patched bug.
//
// FIRST, and ahead of the artifact gate below, because 5.1's rule is that this
// outcome "overrides everything else". The two are different in kind: the artifact
// check is a judgement about whether this PoC is real, and challenge 4 is a fact
// about the codebase — a fix, with a reference, which no amount of PoC
// verification makes less true. Put the artifact gate first and a dead artifact
// agent or a failing lint turns "already patched, retract it" into BLOCKED, which
// SKILL.md relays as NEEDS MORE INFO and whose completion gate tells the
// orchestrator to re-dispatch, buying the same answer twice for a bug that no
// longer exists.
const fixCitation = alreadyFixedStands(lost, verdicts)
if (fixCitation) {
  log(`ALREADY_FIXED: the already-fixed challenge stands. ${fixCitation}`)
  return {
    // ALREADY_FIXED, not DO_NOT_SUBMIT. The bug was real and a fix landed, so this
    // is a RETRACTION with a reference — and Stage 1 already returns exactly this
    // status for exactly this rule. Under one shared DO_NOT_SUBMIT the orchestrator
    // has to pattern-match the reason prefix to tell a retraction from a false
    // positive from an incomplete report, and any mapping it writes reports all
    // three as FALSE POSITIVE. Two of the three are then the rounding error this
    // plugin exists to prevent.
    status: 'ALREADY_FIXED',
    reason: `already-fixed challenge unrebutted: ${fixCitation}. Retract rather than report at a lowered severity.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// Now the artifact, and it outranks everything below it: the band is a tally of
// judgements about a PoC, so it means nothing until someone other than the builder
// has confirmed the PoC is there and lints clean. Only the already-fixed rule above
// escapes it, and only because it is a fact about the code rather than about the
// artifact.
const artifactIssue = artifactProblem(artifact)
if (artifactIssue) {
  log(`PoC validation unsatisfied: ${artifactIssue}`)
  return { status: 'BLOCKED', reason: artifactIssue, poc, artifact, verdicts, band, defeated, unrebutted: lost }
}

if (band.action === 'DO_NOT_SUBMIT') {
  const unrebuttedKeys = lost.map((v) => v.key).join(', ')
  // Silence can withhold a PROCEED; it cannot produce a REFUTATION. The tally
  // counting a challenge nobody answered against the band is the stated rule and
  // stays, but the status below asserts more than that: SKILL.md reads
  // `confidence NONE (0/5 defeated)` as "the reviewers refuted the finding" and
  // reports FALSE POSITIVE on it, so five agents that never ran retracted a built,
  // executed, independently lint-checked PoC of a real bug on the strength of
  // nothing anyone said. The two reasons were byte-identical; only
  // `unrebutted[].challenge` differed, and nothing told the orchestrator to read
  // it. Carried by the STATUS rather than by a reason prefix the orchestrator has
  // to parse, for the reason the ALREADY_FIXED branch above is: any mapping
  // written over one shared status reports all of its outcomes the same way.
  const silent = lost.filter((v) => !v.answered)
  if (silent.length > 0) {
    const silentKeys = silent.map((v) => v.key).join(', ')
    log(`NEEDS_MORE_INFO: ${silent.length} challenge agent(s) never answered; the band rests on silence.`)
    return {
      status: 'NEEDS_MORE_INFO',
      reason: `${silent.length} of ${CHALLENGES.length} challenge agents returned no verdict (${silentKeys}), so confidence ${band.label} (${defeated}/${CHALLENGES.length} defeated) rests on silence rather than on a refutation. Re-run those challenges; the PoC and the artifact check stand. Unrebutted: ${unrebuttedKeys}`,
      band,
      defeated,
      poc,
      artifact,
      verdicts,
      unrebutted: lost,
    }
  }
  log(`Confidence ${band.label}. Not submitting. Unrebutted: ${unrebuttedKeys}`)
  return {
    status: 'DO_NOT_SUBMIT',
    reason: `confidence ${band.label} (${defeated}/${CHALLENGES.length} defeated); unrebutted: ${unrebuttedKeys}`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// Challenge 4 AWARDED on a WHOLE fix, citing nothing lookupable.
// `alreadyFixedStands` refuses to retract on that — a retraction has to point at
// something — and the band must not quietly decide instead: four other challenges
// defeated puts the band at MEDIUM, so a bug a reviewer says is entirely patched
// comes back REPORTED, which SKILL.md maps to TRUE POSITIVE. That claim is neither
// a retraction nor a clean bill of health; it is a fact still to establish, and
// this is the branch that says so.
//
// `complete === true`, so a PARTIAL fix never reaches here whether it cited
// anything or not. checkpoints.md 5.1 and challenge 4's own prompt both say a
// partial fix does not retract — the finding survives it and the report records
// it — so the citation is only load-bearing for the outcome that DISCARDS the
// finding. Halting on an uncited partial claim would stop the stage over a bug
// nobody disputes is still live. Stage 1's `downgradeUnreferencedFix` takes the
// same line: it downgrades `fixed` to UNCERTAIN and carries on to a verdict.
//
// A DEAD challenge-4 agent is deliberately not here — it returns no claim to
// establish, and `tallyChallenges` has already counted it against the finding.
//
// AFTER the artifact gate and the band, because it outranks neither. Ahead of
// them, a PoC whose file does not exist comes back NEEDS_MORE_INFO instead of
// BLOCKED, and one that lost ALL FIVE challenges comes back NEEDS_MORE_INFO
// instead of the FALSE POSITIVE that SKILL.md maps `confidence NONE (0/5)` to —
// an uncited claim outranking four independent refutations that did not need it.
//
// `winner !== 'REBUTTAL'`, not `=== 'CHALLENGE'`, so that this and
// `tallyChallenges` grade the same field the same way. The enum is advisory —
// `required` is the only thing the runtime validator enforces — so an off-enum
// `winner: 'challenge'` counts AGAINST the finding in the tally while escaping an
// `=== 'CHALLENGE'` test entirely, landing on REPORTED at MEDIUM for a finding the
// reviewer said was entirely patched. A dead agent is still not here, because it
// leaves no entry in `verdicts` at all.
const uncitedFix = verdicts.find(
  (v) => v.key === 'already-fixed' && v.winner !== 'REBUTTAL' && v.complete === true && !citedReference(v.reference),
)
if (uncitedFix) {
  const claim = String(uncitedFix.evidence || '').trim() || 'no evidence given'
  // What was in `reference`, said rather than denied. `citedReference` refuses a
  // string for two different reasons — nothing was offered, or a real registry
  // it has never heard of was — and a single "no commit, PR, issue or advisory
  // in `reference`" over both wrote that denial across a reference that was
  // there. `reference` reaches the user only through this sentence, so denying
  // it here throws away the one string that would settle the question.
  const cited = String(uncitedFix.reference || '').trim()
  const missing = cited
    ? `citing "${cited}" in \`reference\`, which is not a commit, PR, issue or advisory ID this script recognises`
    : 'with no commit, PR, issue or advisory in `reference`'
  log(`NEEDS_MORE_INFO: the already-fixed challenge was awarded with nothing cited.`)
  return {
    status: 'NEEDS_MORE_INFO',
    reason: `the already-fixed challenge was awarded on a complete fix ${missing}: ${claim}. Establish the reference — it retracts if one exists — rather than reporting this as live.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    unrebutted: lost,
  }
}

// ------------------------------------------------------------------ Report

phase('Report')

const corrections = verdicts.filter((v) => v.impactCorrection).map((v) => `${v.key}: ${v.impactCorrection}`)

// The artifact-check line below reads `lintExitZero === true` rather than by
// truthiness. `artifactProblem` refuses anything else first, so nothing off-type
// reaches here today — but this is the sentence the report agent is told the lint
// result by, and a read that prints "yes" for the string 'no' is one deleted
// guard away from telling a reviewer a failed lint passed.
const report = await agent(
  `Calibrate the severity, then write the report. You did not build this PoC.

Finding: ${finding.summary}
Verified impact from Stage 1: ${verification.impact.impact}
Root cause: ${verification.impact.rootCause}
Classification: ${verification.impact.classification}
Severity Stage 1 arrived at: ${verification.severity}${verification.severityCorrection ? ` (${verification.severityCorrection})` : ''}
PoC: ${poc.path} (${poc.pocType}), readable at ${poc.absolutePath}
Confidence: ${band.label} (${band.range}), ${defeated}/${CHALLENGES.length} challenges defeated
${corrections.length ? `Impact corrections raised by reviewers:\n  ${corrections.join('\n  ')}` : 'No reviewer raised an impact correction.'}
${lost.length ? `Unrebutted challenges you must address in the report:\n  ${lost.map((v) => `${v.key}: ${v.challenge}`).join('\n  ')}` : ''}

Calibrate severity against the challenge verdicts and the corrections above.
Where a reviewer showed the impact is weaker than claimed, the weaker impact is
the one that goes in the report. An integration OR external root cause caps
severity at Medium; a hardening gap is not written up as an exploited
vulnerability. Those caps are checked in code after you answer and a rating above
them is rejected, so the report would have to be corrected by hand — get it right
here.

Write the report with all seven required sections: Executive Summary, Technical
Details, Proof of Concept, Attack Path Verification, False Positive Analysis,
Remediation, References. Remediation must be a specific fix, not "add
validation".

Save it next to the PoC, as finding-<short-slug>.md in the directory holding
${poc.absolutePath}, and return that path as reportPath. reportPath must be a
file you actually wrote, not a path you intend to use.

Independent artifact check (a reviewer re-ran these; the builder self-reported):
  poc-lint.sh exit 0: ${artifact.lintExitZero === true ? 'yes' : 'no'}
  PoC re-ran and reproduced the impact: ${artifact.reRun === 'REPRODUCED' ? 'yes' : `no — ${artifact.reRunNotes || 'no reason given'}`}
${artifact.reRun === 'REPRODUCED' ? '' : 'The reviewer could not run this PoC here at all, so nobody but the builder has seen it work. That is a boundary: say so in "unproven" rather than omitting it.'}
${band.action === 'PROCEED_WITH_UNCERTAINTIES' ? '\nConfidence is MEDIUM: the False Positive Analysis section must document the uncertainties explicitly, not gloss them.' : ''}

Fill the "unproven" field with what this PoC does not establish. It is not
allowed to be empty — every PoC has a boundary.

No speculative language: "probably", "likely", "might", "would", "could bypass"
are all disallowed. Say what the evidence shows.`,
  { label: 'report', phase: 'Report', schema: REPORT_SCHEMA, effort: 'high' },
)

// The report is unsatisfied if the agent died or left a field the report is
// defined by blank. JSON Schema `required` checks presence, not content, so
// `unproven: ''` and `reportPath: ''` both validate.
//
// Pure, and duplicated from triage-static.js with the cap it serves — see the
// reasoning there. Every DISTINCT rating level a string names, WORD-BOUNDED,
// most severe first: `low` sits inside "Allowlist", `high` inside "highly", and
// an unbounded substring test reads both as ratings.
function namedLevels(severity) {
  const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
  return LEVELS.filter((name) => new RegExp(`\\b${name}\\b`, 'i').test(String(severity)))
}

// Pure, so both branches can be graded without a model.
function reportProblem(result) {
  if (!result) return 'report agent returned nothing'
  if (!String(result.unproven || '').trim()) return 'report omitted what remains unproven'
  if (!String(result.reportPath || '').trim()) {
    return 'report gave no reportPath; the report has to be the path of a file that was written, not one that was planned'
  }
  // EXACTLY ONE of the five levels, which is one check rather than the three
  // separate failures it covers. `required` validates `severity: ''`, the enum is
  // advisory, and SKILL.md tells the orchestrator the top-level `severity` IS the
  // number the finding ships with — so a blank ships a finding with no rating at
  // all; `Unknown`, `n/a` and `TBD` ship one that names no level; and
  // `Medium/High` and `Critical (affects low-privilege users)` ship two ratings
  // at once. Stage 2 can fall back to Stage 1's number for the unreadable shapes.
  // This stage has nothing to fall back to, so it refuses and names the fix.
  //
  // `severityCapViolation` refuses both unreadable shapes too, so neither would
  // now escape as "below the cap" — the reason this gate is still here is that it
  // runs FIRST and names the fix in the report agent's own vocabulary, which is
  // the argument the paragraph above already makes.
  const stated = String(result.severity || '').trim()
  const levels = namedLevels(stated)
  if (levels.length !== 1) {
    if (!stated) {
      return 'report gave no severity; the top-level severity is the number the finding ships with, and no cap can be applied to a blank one'
    }
    return levels.length === 0
      ? `report gave severity "${stated}", which names none of Critical, High, Medium, Low or Informational; no cap can be applied to a rating that is not one of them`
      : `report gave severity "${stated}", which names ${levels.length} levels (${levels.join(', ')}); state exactly one`
  }
  // Severity passes on "the rating is supported by evidence", so the rationale is
  // trimmed for the same reason the two fields above are: untrimmed, a blank
  // rationale returns REPORTED, and `severityCapViolation` below inspects only
  // Critical and High — which leaves a Medium asserted with nothing behind it and
  // nothing else looking at it.
  if (!String(result.severityRationale || '').trim()) {
    return 'report gave no severityRationale; the rating has to be justified, not just stated'
  }
  return null
}

const reportIssue = reportProblem(report)
if (reportIssue) {
  // NEEDS_MORE_INFO, not DO_NOT_SUBMIT. Nothing was disproven here — five
  // challenges were defeated and the PoC ran; the report agent left a field the
  // report is defined by blank. Calling that a false positive discards a finding
  // for a clerical failure.
  log(`NEEDS_MORE_INFO: ${reportIssue}`)
  return { status: 'NEEDS_MORE_INFO', reason: reportIssue, band, defeated, poc, artifact, verdicts, unrebutted: lost }
}

// Duplicated from triage-static.js alongside the cap it serves — see the
// reasoning there. One reading of "not internal", and unrecognised reads as NOT
// internal: `third-party` and `External` are spellings the advisory enum does not
// stop, and neither of them is the claim that the trigger originates inside the
// repository, which is what buys an uncapped rating in the report.
function externalRootCause(rootCause) {
  return String(rootCause || '').trim().toLowerCase() !== 'internal'
}

// checkpoints.md 2.4b and 2.5, as arithmetic rather than judgement. Stage 1
// CORRECTS an over-rated severity because it has no artifact to correct; here the
// agent has already written the number into a report file, so correcting the
// return value would leave the file wrong and re-running the workflow would not
// fix it. This blocks and names the file instead.
function severityCapViolation(severity, rootCause, classification) {
  // Affirmative, and for the reason `capSeverity` is one workflow over: the
  // REPORT_SCHEMA enum is advisory — `required` is the only thing the runtime
  // validator enforces — so grading by exclusion lets 'critical', 'CRITICAL' and
  // 'Critical (RCE)' through the gate that exists to catch exactly them.
  //
  // EXACTLY ONE level named is a rating; anything else is an unusable answer, not
  // a number to pick from. `reportProblem` above refuses both shapes first and
  // with a better message, so this branch is normally unreachable — it is here
  // because the alternative is that a gate whose whole job is to bound a number
  // returns "no violation" for a string it could not read, and this function is
  // called and graded on its own. It cannot be allowed to become a silent pass.
  const named = namedLevels(severity)
  if (named.length !== 1) {
    return named.length === 0
      ? `severity "${String(severity || '').trim()}" names none of Critical, High, Medium, Low or Informational, so no cap can be checked against it: state exactly one of them`
      : `severity ${severity} names ${named.length} levels (${named.join(', ')}), so no cap can be checked against it: state exactly one of Critical, High, Medium, Low, Informational`
  }
  const level = named[0]
  if (level !== 'critical' && level !== 'high') return null
  if (externalRootCause(rootCause)) {
    // Named, so the block says which value was read. A blank one is not internal
    // either, and `a  root cause` is not a sentence.
    const cause = String(rootCause || '').trim() || 'non-internal'
    return `severity ${severity} exceeds the Medium cap for a ${cause} root cause (checkpoints.md 2.4b)`
  }
  if (classification === 'hardening_gap') {
    return `severity ${severity} exceeds the Medium cap for a hardening gap (checkpoints.md 2.5)`
  }
  return null
}

const capViolation = severityCapViolation(
  report.severity,
  verification.impact.rootCause,
  verification.impact.classification,
)
if (capViolation) {
  log(`Severity calibration unsatisfied: ${capViolation}`)
  return {
    status: 'BLOCKED',
    reason: `${capViolation}. The report at ${report.reportPath} carries a severity the root cause does not support; correct it there rather than re-running this workflow.`,
    band,
    defeated,
    poc,
    artifact,
    verdicts,
    // As every other Stage 3 return carries it. This return is reachable at
    // MEDIUM with a challenge still standing, so without it nothing here names
    // the challenge the orchestrator has to report.
    unrebutted: lost,
    report,
  }
}

log(`REPORTED at ${report.severity}, confidence ${band.label} (${defeated}/${CHALLENGES.length}).`)
// A `reason`, as every terminal status here carries one: SKILL.md's Completion
// Gate tells the orchestrator to relay it verbatim, so a return without one is
// relayed as nothing.
//
// `unrebutted` too, and this is the only SUCCESSFUL status reachable with a
// challenge still standing: at MEDIUM the band proceeds and documents it. A dead
// agent leaves no verdict object, so without this key nothing in the return names
// the challenge that stood, and SKILL.md asks the orchestrator only for the band
// and the tally.
//
// `severity` at the TOP LEVEL, as Stage 1 and Stage 2 both surface it. SKILL.md
// tells the orchestrator to state the verdict "with the severity"; nothing tells
// it to look inside `report`, so a number that lives only at `report.severity`
// reaches the user as `undefined`.
return {
  status: 'REPORTED',
  reason: report.severityRationale,
  severity: report.severity,
  band,
  defeated,
  poc,
  artifact,
  verdicts,
  unrebutted: lost,
  report,
}
