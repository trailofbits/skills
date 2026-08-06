export const meta = {
  name: 'audit-context',
  description: 'Build an audit context dossier: orient, analyze each function to disk, synthesize a system model',
  whenToUse:
    'Before vulnerability hunting on an unfamiliar codebase, when you want per-function depth without spending the main context window on it. Pass a path, or {path, focus, limit}.',
  phases: [
    { title: 'Orient', detail: 'map modules, entrypoints, actors, state; rank functions worth depth' },
    { title: 'Analyze', detail: 'one agent per function; prose to disk, compact record to the script' },
    { title: 'Synthesize', detail: 'state map, workflows, trust boundaries, fragility clusters' },
  ],
}

const target = typeof args === 'string' ? { path: args } : args ?? {}
const root = target.path ?? '.'
const focus = target.focus ?? null
const outDir = target.outDir ?? 'audit-context'

// The whole point of this workflow is that per-function prose lands on disk instead of
// in a context window. Only these compact records travel back through the script.
const ORIENTATION_SCHEMA = {
  type: 'object',
  required: ['modules', 'entrypoints', 'actors', 'state', 'candidates'],
  properties: {
    modules: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'path', 'role'],
        properties: { name: { type: 'string' }, path: { type: 'string' }, role: { type: 'string' } },
      },
    },
    entrypoints: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'file', 'reachableBy'],
        properties: {
          name: { type: 'string' },
          file: { type: 'string' },
          reachableBy: { type: 'string', description: 'which actor can reach this, and how' },
        },
      },
    },
    actors: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'trust'],
        properties: {
          name: { type: 'string' },
          trust: { type: 'string', enum: ['untrusted', 'semi-trusted', 'trusted', 'unclear'] },
        },
      },
    },
    state: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'file', 'writtenBy'],
        properties: {
          name: { type: 'string' },
          file: { type: 'string' },
          writtenBy: { type: 'array', items: { type: 'string' } },
        },
      },
    },
    candidates: {
      type: 'array',
      description: 'Functions worth per-function depth, most important first.',
      items: {
        type: 'object',
        required: ['name', 'file', 'why'],
        properties: {
          name: { type: 'string' },
          file: { type: 'string' },
          why: { type: 'string', description: 'why this one needs depth, in one line' },
        },
      },
    },
    language: { type: 'string', description: 'primary language of the codebase' },
  },
}

const RECORD_SCHEMA = {
  type: 'object',
  required: ['function', 'file', 'analysisFile', 'invariants', 'assumptions', 'calls', 'openQuestions'],
  properties: {
    function: { type: 'string' },
    file: { type: 'string' },
    lines: { type: 'string', description: 'e.g. L40-L88' },
    analysisFile: { type: 'string', description: 'path the full prose analysis was written to' },
    invariants: {
      type: 'array',
      description: 'What must hold. Each cites a line.',
      items: {
        type: 'object',
        required: ['claim', 'evidence'],
        properties: { claim: { type: 'string' }, evidence: { type: 'string' } },
      },
    },
    assumptions: {
      type: 'array',
      description: 'What this function takes on faith, including anything a callee is relied on to enforce.',
      items: {
        type: 'object',
        required: ['claim', 'establishedBy'],
        properties: {
          claim: { type: 'string' },
          establishedBy: {
            type: 'string',
            description: 'the function or line that establishes it, or "nothing found" if unestablished',
          },
        },
      },
    },
    calls: {
      type: 'array',
      items: {
        type: 'object',
        required: ['callee', 'kind', 'propagates'],
        properties: {
          callee: { type: 'string' },
          kind: { type: 'string', enum: ['internal', 'external-source-available', 'external-black-box'] },
          propagates: {
            type: 'string',
            description: 'what the callee establishes or assumes that the caller then depends on',
          },
        },
      },
    },
    callers: { type: 'array', items: { type: 'string' } },
    sharedState: { type: 'array', items: { type: 'string' } },
    openQuestions: {
      type: 'array',
      description: 'Unresolved items, phrased as "unclear; need to inspect X". Empty is a valid answer.',
      items: { type: 'string' },
    },
  },
}

const SYNTHESIS_SCHEMA = {
  type: 'object',
  required: ['dossierFile', 'trustBoundaries', 'fragilityClusters', 'unresolved'],
  properties: {
    dossierFile: { type: 'string' },
    trustBoundaries: {
      type: 'array',
      items: {
        type: 'object',
        required: ['actor', 'entrypoint', 'reaches'],
        properties: { actor: { type: 'string' }, entrypoint: { type: 'string' }, reaches: { type: 'string' } },
      },
    },
    fragilityClusters: {
      type: 'array',
      description: 'Where complexity concentrates. Guides the later hunting phase; not findings.',
      items: {
        type: 'object',
        required: ['area', 'why'],
        properties: { area: { type: 'string' }, why: { type: 'string' } },
      },
    },
    unresolved: { type: 'array', items: { type: 'string' } },
  },
}

const PURE_CONTEXT = `This is context building, not vulnerability hunting. Describe structure, invariants, and
assumptions. Do not name vulnerabilities, propose fixes, write exploits, or assign severity. An unenforced
assumption is recorded as an unenforced assumption, not as a bug.`

phase('Orient')

const scopeLine = focus ? `Restrict the scan to ${focus} and anything it calls.` : 'Cover the whole codebase.'

const orientation = await agent(
  `Map the codebase at ${root} well enough to decide where depth is warranted. ${scopeLine}

Read broadly and shallowly. Identify the modules and what each is for, the entrypoints reachable from outside
and by whom, the actors and how much each is trusted, and the state that outlives a single call.

Then rank the functions that warrant per-function analysis. Rank by how much of the system's correctness rests
on them: functions that validate untrusted input, enforce a bound or a permission, mutate shared state, or sit
on a path between an untrusted actor and that state. Skip getters, setters, and pass-throughs. Order the list
most important first. Return at most 40 candidates.

${PURE_CONTEXT}`,
  { schema: ORIENTATION_SCHEMA, label: 'orient', phase: 'Orient' },
)

if (!orientation || orientation.candidates.length === 0) {
  return { error: 'Orientation found no functions worth analyzing.', root, orientation }
}

// Keep the fan-out inside the session's size guideline. Budget-aware when the user set one, but capped
// either way: a large budget is permission to go deeper, not a reason to analyze every getter in the repo.
const DEFAULT_LIMIT = 12
const MAX_LIMIT = 40
const budgeted = budget.total ? Math.max(4, Math.floor(budget.remaining() / 60_000)) : DEFAULT_LIMIT
const limit = Math.min(target.limit ?? budgeted, MAX_LIMIT)
const selected = orientation.candidates.slice(0, limit)
const dropped = orientation.candidates.length - selected.length

log(
  `Oriented: ${orientation.modules.length} modules, ${orientation.entrypoints.length} entrypoints, ` +
    `${orientation.candidates.length} candidates. Analyzing ${selected.length}.`,
)
if (dropped > 0) {
  log(`Not analyzed (${dropped}, ranked below the cut): ${orientation.candidates.slice(limit).map(c => c.name).join(', ')}`)
}

phase('Analyze')

const context = JSON.stringify({
  language: orientation.language,
  actors: orientation.actors,
  entrypoints: orientation.entrypoints,
  state: orientation.state,
})

// Function names reach the filesystem here, and they are not always filename-safe: C++ operators, Solidity
// signatures carrying parameter lists, and Rust paths all appear verbatim in a codebase index.
const slug = name => name.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'function'

const records = (
  await pipeline(selected, (candidate, _item, index) =>
    agent(
      `Analyze ${candidate.name} in ${candidate.file} (repo root ${root}). It was selected because: ${candidate.why}

System context established so far:
${context}

Write the full prose analysis to ${outDir}/functions/${String(index + 1).padStart(2, '0')}-${slug(candidate.name)}.md
using the Write tool. That file is the deliverable and it should be thorough. Then return only the structured
record — it is a compact index, not a summary of the prose.

Follow every call this function makes. When the callee's source is available, read it, and record in
'propagates' what the caller depends on the callee to establish. If a precondition the caller relies on is
only established inside a callee, or only on some of the callee's paths, that belongs in 'assumptions' with
'establishedBy' naming exactly where. If nothing establishes it, say "nothing found". When source is not
available, treat the callee as adversarial and record what is assumed about it.

Cite line numbers for every claim. Where you cannot, do not assert it — put it in openQuestions as
"unclear; need to inspect X". Length is not a goal: a short record with cited claims beats a long one with
padded ones.

${PURE_CONTEXT}`,
      {
        agentType: 'audit-context-building:function-analyzer',
        schema: RECORD_SCHEMA,
        label: candidate.name,
        phase: 'Analyze',
      },
    ),
  )
).filter(Boolean)

if (records.length === 0) {
  return { error: 'Every function analysis failed.', root, selected }
}

log(`Analyzed ${records.length}/${selected.length}. Prose written to ${outDir}/functions/.`)

phase('Synthesize')

// Genuine barrier: the system model needs every record at once to derive cross-function invariants.
const unestablished = records.flatMap(r =>
  (r.assumptions ?? [])
    .filter(a => /nothing found/i.test(a.establishedBy ?? ''))
    .map(a => `${r.function}: ${a.claim}`),
)

const synthesis = await agent(
  `Build the system model for ${root} from the per-function records below. Write it to ${outDir}/DOSSIER.md
using the Write tool, and return the structured summary.

Orientation:
${JSON.stringify({ modules: orientation.modules, actors: orientation.actors, entrypoints: orientation.entrypoints, state: orientation.state })}

Per-function records:
${JSON.stringify(records)}

The per-function prose is on disk under ${outDir}/functions/ — read any of it you need.

The dossier covers: how each piece of state is read and written across functions and what invariant that
implies; the end-to-end flows and how state moves through them; which actor can reach which entrypoint and
what that reaches in turn; and where complexity concentrates.

Derive the cross-function invariants — the ones no single record could state because they only hold across
functions. Where two records disagree, say so and cite both rather than picking one. Carry every open
question forward; an honest unresolved list is the most useful part of this document for whoever hunts next.

These assumptions were recorded as established by nothing:
${unestablished.length > 0 ? unestablished.join('\n') : '(none)'}
Carry them into the dossier verbatim, as unenforced assumptions. Do not upgrade them into findings.

${PURE_CONTEXT}`,
  { schema: SYNTHESIS_SCHEMA, label: 'synthesize', phase: 'Synthesize' },
)

return {
  root,
  dossier: synthesis?.dossierFile ?? `${outDir}/DOSSIER.md`,
  analyzed: records.map(r => ({ function: r.function, file: r.file, analysis: r.analysisFile })),
  notAnalyzed: orientation.candidates.slice(limit).map(c => c.name),
  trustBoundaries: synthesis?.trustBoundaries ?? [],
  fragilityClusters: synthesis?.fragilityClusters ?? [],
  unenforcedAssumptions: unestablished,
  unresolved: synthesis?.unresolved ?? [],
}
