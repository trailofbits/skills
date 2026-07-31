export const meta = {
  name: 'spec-compliance',
  description: 'Check code against its specification: extract requirements, hunt each one in the code, verify divergences',
  whenToUse:
    'When you have documentation describing intended behavior and want to know where the code disagrees with it. Pass a path, or {path, spec, limit}.',
  phases: [
    { title: 'Extract', detail: 'find the documentation; turn it into individually checkable requirements' },
    { title: 'Align', detail: 'one agent per requirement hunts the code for it; one sweeps the reverse direction' },
    { title: 'Verify', detail: 'independent agents try to refute each divergence before it is reported' },
    { title: 'Report', detail: 'alignment matrix, surviving divergences, contradictions between documents' },
  ],
}

const target = typeof args === 'string' ? { path: args } : args ?? {}
const root = target.path ?? '.'
const specHint = target.spec ?? null
const outDir = target.outDir ?? 'spec-compliance'

// Per-requirement analysis goes to disk. Only these records travel back through the script, which is what
// keeps a whole-codebase behavioral model from ever having to fit in one context window.
const DISCOVERY_SCHEMA = {
  type: 'object',
  required: ['documents', 'codePaths'],
  properties: {
    documents: {
      type: 'array',
      description: 'Files that describe intended behavior, most authoritative first.',
      items: {
        type: 'object',
        required: ['path', 'describes'],
        properties: {
          path: { type: 'string' },
          describes: { type: 'string', description: 'what part of the system this document specifies' },
          kind: {
            type: 'string',
            enum: ['whitepaper', 'design-doc', 'readme', 'inline-docs', 'transcript', 'other'],
          },
          unreadable: {
            type: 'string',
            description:
              'Set only if the file could not be read as text (e.g. a binary .docx with no converter available). Name the file and why.',
          },
        },
      },
    },
    codePaths: {
      type: 'array',
      description: 'Directories or files holding the implementation these documents describe.',
      items: { type: 'string' },
    },
    language: { type: 'string' },
  },
}

const REQUIREMENTS_SCHEMA = {
  type: 'object',
  required: ['requirements'],
  properties: {
    requirements: {
      type: 'array',
      description: 'One entry per independently checkable claim. Split compound sentences into separate entries.',
      items: {
        type: 'object',
        required: ['id', 'quote', 'location', 'kind', 'force'],
        properties: {
          id: { type: 'string', description: 'stable short id, e.g. REQ-04' },
          quote: { type: 'string', description: 'the requirement verbatim from the document, not paraphrased' },
          location: { type: 'string', description: 'e.g. "§4.1" or "README.md, Fees"' },
          kind: {
            type: 'string',
            enum: [
              'invariant',
              'formula',
              'access-control',
              'state-machine',
              'error-handling',
              'ordering',
              'economic',
              'trust-boundary',
              'other',
            ],
          },
          force: {
            type: 'string',
            enum: ['mandatory', 'recommended', 'optional', 'descriptive'],
            description: 'mandatory for MUST/NEVER/ALWAYS; descriptive for prose that states what the system does',
          },
          checkable: {
            type: 'string',
            description: 'what would have to be true of the code for this to hold, in one line',
          },
        },
      },
    },
  },
}

const ALIGNMENT_SCHEMA = {
  type: 'object',
  // analysisFile is required so that not writing the analysis is a schema failure rather than a silent omission
  // the report then tells a reader to go and read.
  required: ['requirementId', 'verdict', 'confidence', 'searched', 'reasoning', 'analysisFile'],
  properties: {
    requirementId: { type: 'string' },
    analysisFile: { type: 'string', description: 'path the analysis was actually written to' },
    verdict: {
      type: 'string',
      enum: ['implemented', 'partial', 'contradicted', 'absent', 'stronger-than-spec', 'undecidable'],
      description:
        'undecidable when the requirement is too vague to check against code — that is a finding about the document',
    },
    confidence: {
      type: 'string',
      enum: ['high', 'medium', 'low'],
      description: 'how sure you are of the verdict, not how severe it is',
    },
    evidence: {
      type: 'array',
      description: 'The code that implements, contradicts, or partially covers the requirement.',
      items: {
        type: 'object',
        required: ['file', 'lines', 'quote'],
        properties: {
          file: { type: 'string' },
          lines: { type: 'string', description: 'e.g. L108 or L89-L135' },
          quote: { type: 'string' },
          role: { type: 'string', description: 'what this line does for the requirement' },
        },
      },
    },
    searched: {
      type: 'array',
      description:
        'Where you looked, and what you found. An absent verdict rests entirely on this: a reader must be able to tell a real absence from a search that stopped early.',
      items: {
        type: 'object',
        required: ['where', 'result'],
        properties: {
          where: { type: 'string', description: 'pattern, symbol, or file searched' },
          result: { type: 'string', description: 'e.g. "3 hits, all in tests" or "0 hits"' },
        },
      },
    },
    reasoning: { type: 'string', description: 'why this verdict and not the adjacent one' },
    documentProblem: {
      type: 'string',
      description: 'Set if the requirement itself is ambiguous, self-contradictory, or contradicts another document.',
    },
  },
}

const UNDOCUMENTED_SCHEMA = {
  type: 'object',
  required: ['behaviors'],
  properties: {
    behaviors: {
      type: 'array',
      description: 'Externally reachable behavior the documentation does not describe. Empty is a valid answer.',
      items: {
        type: 'object',
        required: ['what', 'file', 'lines', 'whyItMatters'],
        properties: {
          what: { type: 'string' },
          file: { type: 'string' },
          lines: { type: 'string' },
          whyItMatters: {
            type: 'string',
            description: 'what a reader of the documentation alone would wrongly believe',
          },
          reachableBy: { type: 'string', description: 'which actor can trigger it' },
        },
      },
    },
  },
}

const REFUTATION_SCHEMA = {
  type: 'object',
  required: ['refuted', 'reasoning'],
  properties: {
    refuted: {
      type: 'boolean',
      description: 'true if the claimed divergence does not hold up',
    },
    reasoning: { type: 'string' },
    correction: {
      type: 'string',
      description: 'If the divergence is real but described wrongly, the accurate version.',
    },
    revisedVerdict: {
      type: 'string',
      enum: ['implemented', 'partial', 'contradicted', 'absent', 'stronger-than-spec', 'undecidable'],
      description: 'Set only if the original verdict was the wrong category.',
    },
  },
}

const REPORT_SCHEMA = {
  type: 'object',
  required: ['reportFile', 'divergences', 'documentProblems'],
  properties: {
    reportFile: { type: 'string' },
    divergences: {
      type: 'array',
      items: {
        type: 'object',
        required: ['requirementId', 'severity', 'title'],
        properties: {
          requirementId: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          title: { type: 'string' },
        },
      },
    },
    documentProblems: {
      type: 'array',
      description: 'Ambiguities and contradictions in the documentation itself, including between documents.',
      items: { type: 'string' },
    },
  },
}

const EVIDENCE_RULE = `Cite a file and line for every claim about the code, and quote the document verbatim for every
claim about intent. Where you cannot cite, do not assert — say what you could not establish. A short answer with
cited claims is worth more than a long one with padded ones.`

phase('Extract')

const discovery = await agent(
  `Find the documentation describing intended behavior for the codebase at ${root}, and the code it describes.
${specHint ? `The user pointed at ${specHint} — start there, and include anything else that also specifies behavior.` : ''}

Documentation is whatever states what the system is supposed to do: a whitepaper, a design note, a README section,
a protocol description, doc comments carrying real semantics. Judge by content, not filename. Skip changelogs,
contributor guides, build instructions, and license text — they describe the project, not its behavior.

If a file plainly holds a specification but you cannot read it as text, record it under 'unreadable' rather than
guessing at its contents.`,
  { schema: DISCOVERY_SCHEMA, label: 'discover', phase: 'Extract', effort: 'low' },
)

if (!discovery || discovery.documents.length === 0) {
  return {
    error: 'No documentation describing intended behavior was found, so there is nothing to check the code against.',
    root,
  }
}

const unreadable = discovery.documents.filter(d => d.unreadable)
if (unreadable.length > 0) {
  log(`Could not read ${unreadable.length} document(s): ${unreadable.map(d => `${d.path} (${d.unreadable})`).join('; ')}`)
}

const readable = discovery.documents.filter(d => !d.unreadable)
if (readable.length === 0) {
  return { error: 'Every document found was unreadable as text.', root, unreadable }
}

log(`Found ${readable.length} document(s): ${readable.map(d => d.path).join(', ')}`)

// Barrier: the requirement set has to be whole before it can be deduplicated and before contradictions
// between documents can be spotted at all.
const extracted = await parallel(
  readable.map(doc => () =>
    agent(
      `Extract the checkable requirements from ${doc.path} (repo root ${root}). It specifies: ${doc.describes}

A requirement is any claim that could be true or false of an implementation: an invariant, a formula, who is
allowed to do what, the order things must happen in, what must revert or error, an economic assumption. Quote each
one verbatim — the quote is what a later agent will check the code against, so a paraphrase loses the thing being
checked.

Split compound claims. "Swaps must charge 0.3% and enforce 1% maximum slippage" is two requirements, because the
code can get one right and the other wrong.

Extract what the document says, however many that is. Do not pad the list to look thorough, and do not promote a
background sentence into a requirement to reach a count. If a claim is too vague to check, extract it anyway and
say so in 'checkable' — a requirement nobody can verify is worth reporting.

Set 'force' from the document's own language: mandatory for MUST/NEVER/ALWAYS, descriptive for prose that merely
narrates what the system does.`,
      { schema: REQUIREMENTS_SCHEMA, label: doc.path, phase: 'Extract' },
    ),
  )
)

// Each document was extracted by its own agent, so two of them numbering from REQ-01 is the normal case, not
// the exceptional one. Left alone, duplicate ids collide in the report and in the on-disk filenames.
const seenIds = new Set()
const requirements = extracted.flatMap((result, docIndex) => {
  if (!result) return []
  const document = readable[docIndex]?.path ?? 'unknown'
  return (result.requirements ?? []).map(requirement => {
    let id = requirement.id
    if (seenIds.has(id)) {
      let suffix = 2
      while (seenIds.has(`${requirement.id}-${suffix}`)) suffix += 1
      id = `${requirement.id}-${suffix}`
    }
    seenIds.add(id)
    return { ...requirement, id, document }
  })
})

if (requirements.length === 0) {
  return { error: 'No checkable requirements could be extracted from the documentation.', root, documents: readable }
}

// A large budget is permission to go deeper, not a reason to check every descriptive sentence in a README.
const DEFAULT_LIMIT = 10
const MAX_LIMIT = 30
const budgeted = budget.total ? Math.max(4, Math.floor(budget.remaining() / 70_000)) : DEFAULT_LIMIT
// Clamped below as well as above: `limit: 0` otherwise selects nothing and reports it as every check failing.
const limit = Math.max(1, Math.min(target.limit ?? budgeted, MAX_LIMIT))

// Mandatory requirements first: a MUST the code ignores is the thing this workflow exists to find.
const forceRank = { mandatory: 0, recommended: 1, optional: 2, descriptive: 3 }
const ranked = [...requirements].sort((a, b) => (forceRank[a.force] ?? 4) - (forceRank[b.force] ?? 4))
const selected = ranked.slice(0, limit)
const deferred = ranked.slice(limit)

log(`Extracted ${requirements.length} requirements. Checking ${selected.length}.`)
if (deferred.length > 0) {
  log(`Not checked (${deferred.length}, ranked below the cut): ${deferred.map(r => r.id).join(', ')}`)
}

phase('Align')

const specContext = JSON.stringify({
  language: discovery.language,
  codePaths: discovery.codePaths,
  documents: readable.map(d => ({ path: d.path, describes: d.describes })),
})

const slug = id => id.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'req'

// The reverse direction. Per-requirement fan-out is driven by the documentation, so by construction it cannot
// find behavior the documentation never mentions; this agent is the only thing covering that.
const undocumentedPromise = agent(
  `Find behavior in the code at ${root} that the documentation does not describe.

Context: ${specContext}

These are the requirements already extracted from the documentation:
${JSON.stringify(selected.map(r => ({ id: r.id, quote: r.quote })))}

Work from the code inward: look at what an outside actor can reach — entrypoints, public and external functions,
privileged operations, upgrade and admin paths, fallbacks, anything that moves value or changes permissions. For
each, ask whether a reader of the documentation alone would know it exists and what it does.

Report what is both undocumented and consequential. A helper with no external effect is not interesting; an admin
function that can redirect funds and appears in no document is. Empty is a valid answer, and a short accurate list
beats a long one padded with getters.

${EVIDENCE_RULE}`,
  { schema: UNDOCUMENTED_SCHEMA, label: 'undocumented-behavior', phase: 'Align' },
).catch(error => {
  // It runs concurrently with the per-requirement fan-out and is awaited after it, so an unhandled
  // rejection here would take down a run whose requirement checks had all succeeded.
  log(`Reverse-direction sweep failed, so undocumented behavior is not covered in this run: ${error.message}`)
  return null
})

const CHECKER = 'spec-to-code-compliance:spec-compliance-checker'

// The checker agent carries the durable judgment — what counts as evidence, why a name is not enforcement, the
// on-disk format. When it cannot be resolved, the phase has to keep working rather than take the run down with
// it: an unresolvable agent type failed all six requirement checks in testing and returned nothing salvageable,
// because the plugin had been installed after the session started and its agents were not in the registry.
let checkerAvailable = true

const FALLBACK_RULES = `
Write the analysis with these sections: the requirement quoted verbatim with its source; the verdict and
confidence; what the requirement demands of an implementation; where enforcement lives, with the code quoted and
lines cited; the paths you walked and which ones enforce it; what you searched and what each search returned; how
you reached this verdict rather than the adjacent one; and any open questions.

Do not accept a name as evidence. \`require(_check(x))\` is enforcement only if you opened \`_check\` and it
compares against the bound the document names, on the path taken. Vary the vocabulary before concluding something
is absent — a document that says "slippage" meets code that says \`minOut\` or \`limitPrice\` — and check the
modifiers, base classes, wrappers, and callers, because enforcement often does not live in the function that
needs it. Where you cannot cite a line, do not assert it.`

const checkRequirement = (prompt, options) => {
  if (!checkerAvailable) return agent(`${prompt}\n${FALLBACK_RULES}`, options)

  // Fall back on any failure of the typed dispatch rather than on a matched error string. The fallback is
  // strictly more available than the typed path, so making recovery conditional on a phrasing would reproduce
  // the outage this exists to prevent the moment the runtime words it differently. The message is only used to
  // decide whether to latch: a resolution failure will not fix itself, while a transient error should not
  // downgrade every remaining requirement.
  return agent(prompt, { ...options, agentType: CHECKER }).catch(error => {
    const message = error.message ?? String(error)
    if (/agent type|unknown agent|not found|not registered/i.test(message)) {
      if (checkerAvailable) {
        checkerAvailable = false
        log(`${CHECKER} did not resolve (${message}), so requirement checks run on the default agent with its rules inlined.`)
      }
    } else {
      log(`${CHECKER} failed on ${options.label} (${message}); retrying that requirement on the default agent.`)
    }
    return agent(`${prompt}\n${FALLBACK_RULES}`, options)
  })
}

// Each requirement runs align -> verify independently, so a divergence found early is being refuted while other
// requirements are still being hunted.
const checked = await pipeline(
  selected,
  (requirement, _item, index) =>
    checkRequirement(
      `Determine whether the code at ${root} implements this one requirement.

Requirement ${requirement.id} (${requirement.kind}, ${requirement.force}), from ${requirement.document} ${requirement.location}:
"${requirement.quote}"
${requirement.checkable ? `Holds if: ${requirement.checkable}` : ''}

Context: ${specContext}

Find the code responsible for this requirement and read it. Read the functions it calls — a bound looks enforced
when the value came back from a function whose name implies a check, and the check turns out to sit on a branch
this path does not take. Where a requirement is enforced across several functions, follow it across them.

Write the analysis to ${outDir}/requirements/${String(index + 1).padStart(2, '0')}-${slug(requirement.id)}.md
using the Write tool, then return the record. The record is a compact index into that file, not a summary of it.

If you have an analysis format and per-domain notes in your instructions, follow them: what counts as
enforcement, and where it hides, differs between contracts, C, services, and firmware, and the places worth
searching before concluding an absence are listed there per domain.

Choosing a verdict:
- 'implemented' means you found the enforcement and read it. Not that you found a function with a promising name.
- 'partial' means it holds on some paths and not others. Say which paths, in 'reasoning'.
- 'contradicted' means the code does something incompatible with the requirement.
- 'stronger-than-spec' means the code enforces more than the document asks for.
- 'absent' means you looked and it is not there. This verdict rests entirely on 'searched': record the patterns
  and symbols you tried and what each returned, so a reader can tell a real absence from a search that stopped
  early. An absence claimed without that record is worthless.
- 'undecidable' means the requirement is too vague to check. That is a finding about the document; put the reason
  in 'documentProblem'.

Judge the code against this requirement only. If you notice something else wrong, that is not this record's
business. Use only the documentation and code in front of you — what a protocol of this kind usually does is not
evidence about what this one does.

${EVIDENCE_RULE}`,
      { schema: ALIGNMENT_SCHEMA, label: requirement.id, phase: 'Align' },
    ),
  async (alignment, requirement) => {
    if (!alignment) return null
    if (alignment.verdict === 'implemented') return { requirement, alignment, refutations: [] }

    // Independent agents, told to refute. Claude favors its own findings when asked to check them, so the
    // check has to come from an agent that did not produce the finding.
    const lenses = [
      'Read the code yourself before deciding. The most common way this verdict is wrong is that the enforcement exists somewhere the first agent did not look: a modifier, a base contract, a wrapper, a caller that checks before calling, a constructor invariant, a type that makes the case impossible.',
      'Check the reading of the document rather than the code. The most common way this verdict is wrong is that the requirement does not say what the finding claims it says: a scope limited elsewhere in the document, a definition given earlier, a sentence that recommends rather than requires, or an example that narrows it.',
    ]

    const votes = await parallel(
      lenses.map(lens => () =>
        agent(
          `Try to refute this claimed divergence between documentation and code at ${root}.

Requirement ${requirement.id}, from ${requirement.location}: "${requirement.quote}"
Claimed verdict: ${alignment.verdict} (confidence: ${alignment.confidence})
Reasoning given: ${alignment.reasoning}
Evidence cited: ${JSON.stringify(alignment.evidence ?? [])}
Where it searched: ${JSON.stringify(alignment.searched ?? [])}
Full analysis: ${alignment.analysisFile ?? '(not written)'}

${lens}

Refute it if it does not hold up. If it holds up, say so — do not manufacture a refutation, and do not refute
merely because you would have worded it differently. If the divergence is real but described inaccurately, leave
'refuted' false and put the accurate version in 'correction'. If it is real but the wrong category — an 'absent'
that is really a 'partial' — set 'revisedVerdict'.

${EVIDENCE_RULE}`,
          { schema: REFUTATION_SCHEMA, label: `refute:${requirement.id}`, phase: 'Verify', effort: 'medium' },
        ),
      ),
    )

    return { requirement, alignment, refutations: votes.filter(Boolean) }
  },
)

// pipeline() preserves input order and drops a failed item to null, so the nulls name which requirements were
// never checked. Unrecorded, they are indistinguishable in the report from requirements that were never selected.
const failed = selected.filter((_, index) => !checked[index])
const results = checked.filter(Boolean)
if (results.length === 0) {
  return {
    error: 'Every requirement check failed, so there is no compliance result. Check the per-agent journal.',
    root,
    checkerAgentResolved: checkerAvailable,
    selected: selected.map(r => r.id),
  }
}

const undocumented = await undocumentedPromise

// Either verifier refuting is enough to drop it. A divergence nobody could confirm is not worth a client's time,
// and both lenses have to miss for a real one to be lost.
const survived = results.filter(r => r.alignment.verdict !== 'implemented' && !r.refutations.some(v => v.refuted))
const dropped = results.filter(r => r.alignment.verdict !== 'implemented' && r.refutations.some(v => v.refuted))
const unverified = results.filter(r => r.alignment.verdict !== 'implemented' && r.refutations.length === 0)

log(
  `Checked ${results.length}/${selected.length}. ${survived.length} divergence(s) survived verification, ` +
    `${dropped.length} refuted, ${undocumented?.behaviors.length ?? 0} undocumented behavior(s).`,
)
if (failed.length > 0) {
  log(`Check failed outright, so no verdict exists for these: ${failed.map(r => r.id).join(', ')}`)
}
if (unverified.length > 0) {
  log(`Unverified (both refutation agents failed): ${unverified.map(r => r.requirement.id).join(', ')}`)
}

phase('Report')

// Genuine barrier: the matrix and the contradictions between documents need every record at once.
const report = await agent(
  `Write the compliance report for ${root} to ${outDir}/REPORT.md using the Write tool, then return the summary.

Documents checked: ${JSON.stringify(readable.map(d => d.path))}

Requirements that hold:
${JSON.stringify(results.filter(r => r.alignment.verdict === 'implemented').map(r => ({ id: r.requirement.id, quote: r.requirement.quote, evidence: r.alignment.evidence })))}

Divergences that survived refutation:
${JSON.stringify(survived.map(r => ({ requirement: r.requirement, alignment: r.alignment, corrections: r.refutations.map(v => v.correction).filter(Boolean), revisedVerdicts: r.refutations.map(v => v.revisedVerdict).filter(Boolean) })))}

Divergences a refutation agent knocked down:
${JSON.stringify(dropped.map(r => ({ id: r.requirement.id, verdict: r.alignment.verdict, quote: r.requirement.quote, whyRefuted: r.refutations.filter(v => v.refuted).map(v => v.reasoning) })))}

These are not findings and must not appear among them. They do belong in the report, in a short "considered and
dropped" list near the end: one line each for what was claimed and why it did not hold. A single refuter is
enough to drop a divergence, so one over-confident refutation can lose a real one — a reader who can see what
was dropped can catch that, and a reader who cannot has no way to know it happened.

Undocumented behavior:
${JSON.stringify(undocumented?.behaviors ?? [])}

Per-requirement analysis is on disk under ${outDir}/requirements/ — read any of it you need.

The report opens with what a reader needs first: whether the code does what the documents say, and the divergences
that matter, worst first. Then the alignment matrix — every requirement checked, its verdict, and the line that
evidences it. Then the undocumented behavior, then the problems in the documentation itself.

For each divergence: what the document requires, what the code does instead, and what follows from the gap. Where
you can show the consequence concretely — the sequence that reaches it, who can trigger it, what they get — do,
because a divergence whose consequence is spelled out is the one that gets fixed. Where you cannot, say what would
have to be true for it to matter rather than inventing a scenario or a dollar figure.

Severity is about consequence, not about how far the code strayed. A formula off by a rounding step that drains a
pool over time outranks a MUST the code satisfies by different means than the document describes. Documentation
drift with no behavioral consequence is low, and say plainly that it is a documentation fix rather than a code one.

Carry these forward rather than smoothing them over:
- requirements marked 'undecidable', and any 'documentProblem' recorded against a requirement — contradictions
  between two documents are a real finding, and the fix is to the documents
- requirements not checked at all: ${deferred.length > 0 ? deferred.map(r => r.id).join(', ') : '(none)'}
- requirements whose check failed outright, so no verdict exists and their status is unknown rather than
  compliant: ${failed.length > 0 ? failed.map(r => r.id).join(', ') : '(none)'}
- documents that could not be read: ${unreadable.length > 0 ? unreadable.map(d => d.path).join(', ') : '(none)'}
- divergences whose refutation agents both failed, which are unverified rather than confirmed: ${unverified.length > 0 ? unverified.map(r => r.requirement.id).join(', ') : '(none)'}

Cover the substance and stop. Sections with nothing in them should say so in a line, or be left out — do not pad
the report to fill a template, and do not restate the matrix in prose after presenting it as a table.

${EVIDENCE_RULE}`,
  { schema: REPORT_SCHEMA, label: 'report', phase: 'Report' },
)

return {
  root,
  // Not defaulted to the expected path. The script cannot touch the filesystem, so a path returned here is only
  // ever the reporting agent's word that it wrote the file; inventing one when the agent named none would report
  // a document that does not exist.
  report: report?.reportFile ?? null,
  ...(report?.reportFile ? {} : { reportWarning: `No report path was returned; ${outDir}/REPORT.md may not have been written.` }),
  documents: readable.map(d => d.path),
  requirementsExtracted: requirements.length,
  requirementsChecked: results.length,
  checksFailed: failed.map(r => r.id),
  holds: results.filter(r => r.alignment.verdict === 'implemented').map(r => r.requirement.id),
  divergences: report?.divergences ?? survived.map(r => ({ requirementId: r.requirement.id, verdict: r.alignment.verdict })),
  refuted: dropped.map(r => ({ requirementId: r.requirement.id, verdict: r.alignment.verdict })),
  unverified: unverified.map(r => r.requirement.id),
  undocumentedBehavior: undocumented?.behaviors ?? [],
  documentProblems: report?.documentProblems ?? [],
  notChecked: deferred.map(r => r.id),
  unreadableDocuments: unreadable.map(d => ({ path: d.path, why: d.unreadable })),
}
