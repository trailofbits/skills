export const meta = {
  name: 'document',
  description:
    'Generate a Diataxis-structured documentation set: distill the framework from its upstream source, survey the codebase in parallel, then author tutorials, how-to guides, generated code reference, and explanation.',
  whenToUse:
    'When a codebase needs a complete documentation set organized by reader need rather than by module, with reference generated from the code by Doxygen, Sphinx, rustdoc, TypeDoc, or the language equivalent.',
  phases: [
    { title: 'Framework', detail: 'clone diataxis-documentation-framework and distill its rules' },
    { title: 'Survey', detail: 'five parallel readers map the target codebase' },
    { title: 'Author', detail: 'one agent per Diataxis quadrant, writing to disjoint paths' },
    { title: 'Assemble', detail: 'index, cross-links, navigation, run summary' },
  ],
}

// ---------------------------------------------------------------- inputs

// `args` should arrive as an object, but a caller that passes it as a JSON
// string gets it through verbatim — and then every field reads as undefined and
// the run aborts on a message that blames the wrong thing. Parse it back rather
// than fail on a caller's serialization choice.
let input = args || {}
if (typeof input === 'string') {
  try {
    input = JSON.parse(input)
  } catch (e) {
    throw new Error(
      'diataxis: args arrived as a string that is not JSON (' + e.message + '). ' +
        'Pass args as an object, e.g. {target: "src", docsDir: "docs", referencesDir: "..."}.',
    )
  }
}
if (typeof input !== 'object' || input === null || Array.isArray(input)) {
  throw new Error('diataxis: args must be an object with target, docsDir, and referencesDir.')
}

const target = input.target || '.'
const docsDir = input.docsDir || 'docs'
const referencesDir = input.referencesDir || ''
const briefs = referencesDir ? referencesDir + '/agent-prompts.md' : ''

if (!briefs) {
  throw new Error(
    'diataxis: args.referencesDir was not supplied. The skill passes it as ' +
      '"{baseDir}/references"; without it the agents cannot read their briefs. ' +
      'Launch through /diataxis:documenting-with-diataxis rather than calling the workflow bare.',
  )
}

const FRAMEWORK_REPO = 'https://github.com/evildmp/diataxis-documentation-framework.git'
const QUADRANTS = ['tutorial', 'how-to', 'reference', 'explanation']

// A brief is the single source of truth for what each agent does; the prompts
// here only locate it and pin the run-specific paths. Keeping the substance in
// references/ is what lets the sequential fallback in SKILL.md stay in step.
function brief(section, extra) {
  return (
    'Read `' + briefs + '` and follow the "' + section + '" brief exactly.\n\n' +
    'Reference material lives in `' + referencesDir + '`.\n' +
    'Target codebase: `' + target + '`\n' +
    'Documentation root: `' + docsDir + '`\n\n' +
    extra
  )
}

// ---------------------------------------------------------------- schemas

const strings = { type: 'array', items: { type: 'string' } }
const objects = { type: 'array', items: { type: 'object', additionalProperties: true } }

const FRAMEWORK_SCHEMA = {
  type: 'object',
  required: ['sourceCommit', 'rstFilesRead', 'readBrief', 'quadrants', 'compass', 'qualityChecks'],
  properties: {
    sourceCommit: { type: 'string', description: 'Resolved SHA of the cloned framework repo' },
    rstFilesRead: { type: 'number', description: 'How many source/*.rst files were actually read' },
    readBrief: { type: 'boolean', description: 'Whether diataxis-quadrants.md was readable' },
    cloneError: { type: 'string', description: 'Empty unless the clone failed' },
    quadrants: {
      type: 'array',
      minItems: 4,
      maxItems: 4,
      items: {
        type: 'object',
        required: ['name', 'userNeed', 'purpose', 'form', 'voice', 'antiPatterns', 'acceptanceChecks'],
        properties: {
          name: { type: 'string', enum: QUADRANTS },
          userNeed: { type: 'string' },
          purpose: { type: 'string' },
          form: { type: 'string' },
          voice: { type: 'string' },
          antiPatterns: strings,
          acceptanceChecks: strings,
        },
      },
    },
    compass: strings,
    qualityChecks: strings,
  },
}

const SURVEY_SCHEMAS = {
  inventory: {
    type: 'object',
    required: ['languages', 'sourceFileCount', 'existingDocs', 'conventions'],
    properties: {
      languages: objects,
      buildSystem: { type: 'string' },
      entryPoints: objects,
      existingDocs: objects,
      existingDocToolchain: { type: 'string' },
      conventions: { type: 'object', additionalProperties: true },
      sourceFileCount: { type: 'number' },
    },
  },
  'api-surface': {
    type: 'object',
    required: ['symbols', 'publicBoundaryRule', 'docCoverage'],
    properties: {
      symbols: objects,
      cliCommands: objects,
      configKeys: objects,
      publicBoundaryRule: { type: 'string' },
      docCoverage: { type: 'number' },
    },
  },
  onboarding: {
    type: 'object',
    required: ['firstRunPath', 'candidateTutorials'],
    properties: {
      install: { type: 'string' },
      firstRunPath: objects,
      examples: objects,
      testsAsExamples: strings,
      knownStumblingBlocks: strings,
      candidateTutorials: objects,
    },
  },
  operations: {
    type: 'object',
    required: ['tasks'],
    properties: {
      tasks: objects,
      troubleshooting: objects,
      operationalSurface: { type: 'string' },
    },
  },
  architecture: {
    type: 'object',
    required: ['modules', 'decisions'],
    properties: {
      modules: objects,
      dataFlow: { type: 'string' },
      decisions: objects,
      constraints: strings,
      rejectedAlternatives: objects,
      openQuestions: strings,
    },
  },
}

const MANIFEST_SCHEMA = {
  type: 'object',
  required: ['filesWritten', 'redirected', 'gaps'],
  properties: {
    filesWritten: strings,
    filesIntegrated: strings,
    sourceFilesEdited: strings,
    redirected: objects,
    gaps: strings,
    notes: { type: 'string' },
    generator: { type: 'string', description: 'reference agent only: the doc generator chosen' },
    buildCommand: { type: 'string', description: 'reference agent only' },
    symbolsDocumented: { type: 'number', description: 'reference agent only' },
    symbolsTotal: { type: 'number', description: 'reference agent only' },
  },
}

const ASSEMBLE_SCHEMA = {
  type: 'object',
  required: ['indexPath', 'summary'],
  properties: {
    indexPath: { type: 'string' },
    crossLinksAdded: { type: 'number' },
    navigationUpdated: { type: 'boolean' },
    brokenLinks: strings,
    summary: { type: 'string' },
  },
}

// ---------------------------------------------------- phase 1: framework

phase('Framework')

const framework = await agent(
  brief('Phase 1 — Framework',
    'Clone `' + FRAMEWORK_REPO + '` shallowly into a scratch directory and read its ' +
    '`source/*.rst` files. Return the resolved commit SHA and the count of .rst files you ' +
    'actually opened.\n\n' +
    'Do not answer from prior knowledge of Diataxis. If the clone fails, set `cloneError` ' +
    'and stop — a distillation written from memory is the specific failure this phase exists ' +
    'to catch, and it is checked below.'),
  { label: 'framework:distill', phase: 'Framework', schema: FRAMEWORK_SCHEMA },
)

// Guards. Each of these means the run would otherwise proceed on invented input.
if (!framework) {
  throw new Error('diataxis: the framework agent returned nothing; nothing downstream can proceed.')
}
if (framework.cloneError) {
  throw new Error(
    'diataxis: could not clone ' + FRAMEWORK_REPO + ' — ' + framework.cloneError +
      '\nThe run needs network access to read the framework from source. Fix connectivity and rerun.',
  )
}
if (!framework.sourceCommit || framework.sourceCommit.length < 7) {
  throw new Error(
    'diataxis: the framework agent returned no commit SHA, so the clone did not happen. ' +
      'Its output is a recollection of Diataxis, not a reading of it. Refusing to build ' +
      'documentation on it.',
  )
}
if (!(framework.rstFilesRead >= 8)) {
  throw new Error(
    'diataxis: the framework agent read only ' + framework.rstFilesRead + ' of the 10 framework ' +
      'source files. The distillation is incomplete; rerun rather than author from a partial read.',
  )
}
if (!framework.readBrief) {
  throw new Error(
    'diataxis: the framework agent could not read `' + referencesDir + '/diataxis-quadrants.md`. ' +
      'args.referencesDir is wrong, so every downstream agent would also fail to find its brief.',
  )
}
if (!framework.quadrants || framework.quadrants.length !== 4) {
  throw new Error('diataxis: expected 4 quadrant definitions, got ' + (framework.quadrants || []).length + '.')
}

const byQuadrant = {}
for (const q of framework.quadrants) byQuadrant[q.name] = q

const missing = QUADRANTS.filter(name => !byQuadrant[name])
if (missing.length) {
  throw new Error('diataxis: framework distillation is missing quadrant(s): ' + missing.join(', '))
}

log('Framework read at ' + framework.sourceCommit.slice(0, 12) + ' (' + framework.rstFilesRead + ' source files).')

// ------------------------------------------------------- phase 2: survey

phase('Survey')

// A barrier is correct here: every phase-3 writer consumes the whole survey,
// not just the dimension nominally feeding its quadrant.
const SURVEYS = [
  { key: 'inventory', feeds: 'all quadrants' },
  { key: 'api-surface', feeds: 'reference' },
  { key: 'onboarding', feeds: 'tutorials' },
  { key: 'operations', feeds: 'how-to guides' },
  { key: 'architecture', feeds: 'explanation' },
]

const surveyResults = await parallel(
  SURVEYS.map((s, i) => () =>
    agent(
      brief('2' + 'abcde'[i] + '. `' + s.key + '`',
        'You are the `' + s.key + '` survey agent; your findings feed ' + s.feeds + '.\n' +
        'Read only — write nothing. Cite a path for every claim.'),
      { label: 'survey:' + s.key, phase: 'Survey', schema: SURVEY_SCHEMAS[s.key] },
    ).then(r => ({ key: s.key, data: r })),
  ),
)

const survey = {}
const surveyFailed = []
for (let i = 0; i < SURVEYS.length; i++) {
  const r = surveyResults[i]
  if (r && r.data) survey[r.key] = r.data
  else surveyFailed.push(SURVEYS[i].key)
}

if (surveyFailed.length) log('Survey agents that returned nothing: ' + surveyFailed.join(', ') + '.')

if (!survey.inventory) {
  throw new Error(
    'diataxis: the inventory survey failed. It carries the language list, existing docs, and ' +
      'project conventions that all four writers depend on; the run cannot continue without it.',
  )
}
if (!(survey.inventory.sourceFileCount > 0)) {
  throw new Error(
    'diataxis: the inventory found 0 source files under `' + target + '`. There is nothing to ' +
      'document. Check the target path.',
  )
}
if (surveyFailed.length > 2) {
  throw new Error(
    'diataxis: ' + surveyFailed.length + ' of 5 survey agents failed (' + surveyFailed.join(', ') +
      '). Too little ground truth to author against — the writers would fill the gap by inventing.',
  )
}

log(
  'Surveyed ' + survey.inventory.sourceFileCount + ' source files; ' +
    (SURVEYS.length - surveyFailed.length) + '/5 survey dimensions available.',
)

// ------------------------------------------------------- phase 3: author

phase('Author')

// Each writer owns exactly one output path. They run concurrently, so the
// disjointness is what keeps them from clobbering each other — the reference
// agent is the only one that touches files outside docsDir.
const WRITERS = [
  { key: 'tutorial', section: '3a. `tutorials`', out: docsDir + '/tutorials/', label: 'author:tutorials' },
  { key: 'how-to', section: '3b. `how-to`', out: docsDir + '/how-to/', label: 'author:how-to' },
  { key: 'reference', section: '3c. `reference`', out: docsDir + '/reference/', label: 'author:reference' },
  { key: 'explanation', section: '3d. `explanation`', out: docsDir + '/explanation/', label: 'author:explanation' },
]

const surveyJson = JSON.stringify(survey, null, 2)

const manifests = await parallel(
  WRITERS.map(w => () => {
    const spec = byQuadrant[w.key]
    const others = QUADRANTS.filter(q => q !== w.key).join(', ')
    const extra =
      'You are the **' + w.key + '** writer. Write only under `' + w.out + '`' +
      (w.key === 'reference'
        ? ', plus doc comments in the source files and the generator config. Read `' +
          referencesDir + '/reference-toolchains.md` and follow it — comments and ' +
          'configuration only, never a change to behavior, a signature, a name, or a default.'
        : '. Write nowhere else — the other three writers are running concurrently.') +
      '\n\nYour quadrant, as distilled from the framework at ' + framework.sourceCommit.slice(0, 12) + ':\n' +
      '```json\n' + JSON.stringify(spec, null, 2) + '\n```\n\n' +
      'Compass rules:\n- ' + framework.compass.join('\n- ') + '\n\n' +
      'The other quadrants are: ' + others + '. Material belonging to them goes in ' +
      '`redirected`, named with its quadrant. Do not absorb it and do not discard it.\n\n' +
      (surveyFailed.length
        ? 'These survey dimensions are UNAVAILABLE: ' + surveyFailed.join(', ') +
          '. Where you would have relied on them, read the source directly or record a gap. ' +
          'Do not invent.\n\n'
        : '') +
      'Survey results:\n```json\n' + surveyJson + '\n```'

    return agent(brief(w.section, extra), {
      label: w.label,
      phase: 'Author',
      schema: MANIFEST_SCHEMA,
    }).then(r => ({ key: w.key, manifest: r }))
  }),
)

const written = {}
const writerFailed = []
const writerEmpty = []
for (let i = 0; i < WRITERS.length; i++) {
  const r = manifests[i]
  if (!r || !r.manifest) {
    writerFailed.push(WRITERS[i].key)
    continue
  }
  written[r.key] = r.manifest
  if (!r.manifest.filesWritten || r.manifest.filesWritten.length === 0) writerEmpty.push(r.key)
}

// A writer that produced nothing is a failure to report, not a quadrant to
// silently omit — an incomplete docs set that looks complete is the worst
// outcome this workflow can produce.
if (writerFailed.length) log('Quadrant agents that returned nothing: ' + writerFailed.join(', ') + '.')
if (writerEmpty.length) log('Quadrant agents that wrote zero files: ' + writerEmpty.join(', ') + '.')

if (writerFailed.length + writerEmpty.length === WRITERS.length) {
  throw new Error('diataxis: no quadrant produced any documentation. Nothing was written.')
}

const ref = written['reference']
if (ref && !ref.generator) {
  log('WARNING: the reference agent wrote files but named no generator — reference may be hand-written prose.')
}

// ----------------------------------------------------- phase 4: assemble

phase('Assemble')

const produced = WRITERS.filter(w => written[w.key] && written[w.key].filesWritten.length)
const shortfall = writerFailed.concat(writerEmpty)

const assembled = await agent(
  brief('Phase 4 — Assemble',
    'All quadrant agents have returned. Write `' + docsDir + '/index.md`, cross-link the ' +
    'quadrants, and update the docs site navigation if one exists.\n\n' +
    'Quadrants that produced files: ' + produced.map(w => w.key).join(', ') + '\n' +
    (shortfall.length
      ? 'Quadrants that produced NOTHING: ' + shortfall.join(', ') +
        '. Do not link to them and do not paper over them — name them in the summary.\n'
      : '') +
    '\nWriter manifests:\n```json\n' + JSON.stringify(written, null, 2) + '\n```'),
  { label: 'assemble:index', phase: 'Assemble', schema: ASSEMBLE_SCHEMA },
)

if (!assembled) {
  log('WARNING: the assemble agent returned nothing. Quadrant files exist but there is no index.')
}

// ---------------------------------------------------------------- result

return {
  target: target,
  docsDir: docsDir,
  framework: {
    repo: FRAMEWORK_REPO,
    commit: framework.sourceCommit,
    filesRead: framework.rstFilesRead,
  },
  quadrants: WRITERS.map(w => ({
    kind: w.key,
    path: w.out,
    filesWritten: (written[w.key] && written[w.key].filesWritten) || [],
    filesIntegrated: (written[w.key] && written[w.key].filesIntegrated) || [],
    gaps: (written[w.key] && written[w.key].gaps) || [],
    redirected: (written[w.key] && written[w.key].redirected) || [],
  })),
  reference: ref
    ? {
        generator: ref.generator,
        buildCommand: ref.buildCommand,
        symbolsDocumented: ref.symbolsDocumented,
        symbolsTotal: ref.symbolsTotal,
        sourceFilesEdited: ref.sourceFilesEdited || [],
      }
    : null,
  index: assembled ? assembled.indexPath : null,
  brokenLinks: (assembled && assembled.brokenLinks) || [],
  summary: assembled ? assembled.summary : 'Assemble phase failed; no index written.',
  incomplete: {
    surveyDimensionsFailed: surveyFailed,
    quadrantsFailed: writerFailed,
    quadrantsEmpty: writerEmpty,
  },
}
