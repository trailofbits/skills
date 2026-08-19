// Ships as /variant-analysis:variants. Plugin workflows are namespaced by the plugin's
// `name` field, which cannot be overridden per component, so the prefix is always
// `variant-analysis:`. meta.name below supplies the rest, not the filename.
export const meta = {
  name: 'variants',
  description: 'Hunt for variants of a known bug: root cause, baseline gate, parallel sweep across expansion axes, adversarial triage, report',
  whenToUse:
    'After a specific vulnerability has been found and you want systematic coverage of its variants across a whole codebase. Not for initial discovery. Pass args as a JSON OBJECT, not a prose string: {"bug": "...", "root": "...", "lang": "...", "out": "..."}. bug is required (the vulnerability, including file:line if known); root defaults to cwd; lang is the primary language; out is the report path. Fill them from the conversation. Do not ask the user for a plugin path; the run locates its own strategy references.',
  phases: [
    { title: 'Root cause', detail: 'Extract root cause statement, exact-match pattern, and expansion axes' },
    { title: 'Baseline', detail: 'Verify the exact pattern actually matches the known bug' },
    { title: 'Sweep', detail: 'One agent per expansion axis, climbing the abstraction ladder' },
    { title: 'Triage', detail: 'Adversarial verification of each candidate, severity attached' },
    { title: 'Report', detail: 'Synthesize into the variant report template' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
// args = {
//   bug:   string  (required) description of the original vulnerability, ideally with file:line
//   root:  string  (optional) codebase root to search; defaults to cwd
//   lang:  string  (optional) primary language, steers tool choice
//   out:   string  (optional) report path
//   skill: string  (rarely needed) override for the strategy-reference directory. The run
//                  finds this itself; supply it only if the log reports resolution failed.
// }
// A caller that passes args as prose rather than an object used to kill the run on the
// first line, before a single agent started: `args.bug is required` with nothing to show
// for it. Observed in a cold run — the model wrote
// `"bug: ...; root: /path; lang: python"` and the whole invocation died. Parsing that
// shape costs six lines and turns a hard failure into a working run.
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
  // `key: value; key: value`, where a value may itself contain colons (file:line, URLs).
  // Only the four known keys start a new field, so a bug description containing
  // "root cause:" does not get chopped in half.
  const KEYS = ['bug', 'root', 'lang', 'out', 'skill']
  const out = {}
  let key = null
  for (const part of text.split(/;\s*|\n/)) {
    const m = part.match(/^\s*(\w+)\s*:\s*([\s\S]*)$/)
    if (m && KEYS.includes(m[1].toLowerCase())) {
      key = m[1].toLowerCase()
      out[key] = m[2].trim()
    } else if (key && part.trim()) {
      out[key] = `${out[key]} ${part.trim()}`.trim()
    }
  }
  // A bare string with no recognizable key at all is the bug description.
  if (!Object.keys(out).length) out.bug = text
  return out
}

const A = parseArgs(args)
if (!A.bug) {
  throw new Error(
    'args.bug is required: describe the original vulnerability (ideally with file:line). ' +
      'Pass args as a JSON object, e.g. {"bug": "...", "root": "/path", "lang": "python"}.',
  )
}

const ROOT = A.root || '.'
const LANG = A.lang || 'auto-detect from the codebase'
const OUT = A.out || 'variant-analysis-report.md'

// Single-quote for the shell. JSON.stringify looks like quoting but yields a
// double-quoted string, where $(...) and backticks still expand — and the patterns
// interpolated below are model-generated from codebase content. An unquoted path also
// breaks on any root containing a space.
const sh = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`

// Each stage only reads its own strategy reference.
//
// Resolving where those references live has to be automatic: ${CLAUDE_PLUGIN_ROOT} is
// exported to hook, MCP, and LSP subprocesses and substituted in skill/agent content, but
// a workflow script is none of those, so it cannot be relied on here. The search below
// covers every layout the plugin can be loaded from and costs one cheap agent turn.
//
// Every candidate ends in `references/` rather than the skill directory. That is what makes
// a stale install self-excluding: versions before the reference split have no such
// directory, so the search can never silently bind to one.
const RESOLVE_SKILL_DIR = A.skill
  ? `The skill directory is \`${A.skill}\`. Confirm it contains \`references/\` and report it as skill_dir.`
  : `Locate this plugin's strategy references and report their parent as skill_dir. Run these
in order and stop at the first that prints a path:

  ls -d "$CLAUDE_PLUGIN_ROOT/skills/variant-analysis/references" 2>/dev/null
  ls -d ~/.claude/plugins/cache/*/variant-analysis/*/skills/variant-analysis/references 2>/dev/null | sort -V | tail -1
  find . -maxdepth 6 -type d -path '*variant-analysis/skills/variant-analysis/references' 2>/dev/null | head -1
  find "$HOME" -maxdepth 7 -type d -path '*variant-analysis/skills/variant-analysis/references' 2>/dev/null | head -1

The last one takes ~15s; it is the fallback for a plugin loaded with --plugin-dir from
outside the current tree, so run it only if the earlier three print nothing.

Report the PARENT of the matched path (the directory containing \`references/\`). If all
four print nothing, report skill_dir as an empty string rather than guessing.`

const ref = (skillDir, file) =>
  skillDir
    ? `Read \`${skillDir}/references/${file}\` before you start. It is the strategy for this stage; follow it.`
    : `(Strategy reference \`references/${file}\` could not be located on this machine — proceed on the instructions below alone.)`

const template = (skillDir) =>
  skillDir ? `${skillDir}/resources/variant-report-template.md` : 'the standard variant report template'

// Coverage bounds.
const MAX_AXES_PER_ROUND = 6
const TRIAGE_BATCH = 4
const MAX_ROUNDS = budget.total ? 4 : 2
const DRY_ROUNDS_TO_STOP = 2

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------
const ROOT_CAUSE_SCHEMA = {
  type: 'object',
  required: ['skill_dir', 'statement', 'origin', 'exact_pattern', 'axes'],
  properties: {
    skill_dir: {
      type: 'string',
      description: 'Absolute path to the variant-analysis skill directory (the parent of references/), or empty string if it could not be found.',
    },
    statement: {
      type: 'string',
      description: 'Root cause in the form: [UNTRUSTED DATA] reaches [DANGEROUS OPERATION] without [REQUIRED PROTECTION]. For logic bugs, state the invariant that is violated instead.',
    },
    origin: {
      type: 'object',
      required: ['file', 'line', 'snippet'],
      properties: {
        file: { type: 'string' },
        line: { type: 'integer' },
        snippet: { type: 'string' },
      },
    },
    exact_pattern: {
      type: 'string',
      description: 'A ripgrep ERE that matches the original vulnerable line and, ideally, nothing else. Level 0 of the abstraction ladder.',
    },
    axes: {
      type: 'array',
      minItems: 3,
      maxItems: 12,
      description:
        'Independent search axes. Cover all three kinds: semantically related identifiers, alternative manifestations of the same root cause, and data-type edge cases.',
      items: {
        type: 'object',
        required: ['id', 'kind', 'description', 'hints'],
        properties: {
          id: { type: 'string' },
          kind: { type: 'string', enum: ['identifier', 'manifestation', 'edge-case'] },
          description: { type: 'string' },
          hints: { type: 'array', items: { type: 'string' }, description: 'Concrete identifiers, call shapes, or code constructs to search for on this axis.' },
        },
      },
    },
  },
}

const BASELINE_SCHEMA = {
  type: 'object',
  required: ['match_count', 'locations', 'matches_origin', 'source_file_count'],
  properties: {
    match_count: { type: 'integer' },
    locations: { type: 'array', items: { type: 'string' } },
    matches_origin: { type: 'boolean', description: 'True if one of the matches is the known vulnerable line named in the root cause.' },
    source_file_count: {
      type: 'integer',
      description: 'Source files in the codebase, from the second command: the primary language\'s files, excluding vendored, generated, asset, and fixture directories. Sizes the sweep.',
    },
    notes: { type: 'string' },
  },
}

const CANDIDATES_SCHEMA = {
  type: 'object',
  required: ['candidates', 'patterns_tried'],
  properties: {
    candidates: {
      type: 'array',
      items: {
        type: 'object',
        required: ['file', 'line', 'snippet', 'why'],
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          snippet: { type: 'string' },
          why: { type: 'string', description: 'How this instance realizes the same root cause.' },
        },
      },
    },
    patterns_tried: {
      type: 'array',
      description: 'The abstraction ladder followed, for the report methodology table.',
      items: {
        type: 'object',
        required: ['pattern', 'level', 'tool', 'matches'],
        properties: {
          pattern: { type: 'string' },
          level: { type: 'integer' },
          tool: { type: 'string' },
          matches: { type: 'integer' },
          note: { type: 'string' },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['verdicts'],
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['file', 'line', 'is_variant', 'severity', 'confidence', 'reasoning'],
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          is_variant: { type: 'boolean' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'informational'] },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          reasoning: { type: 'string' },
          exploitability: { type: 'string', description: 'Reachability, input control, and what protection is missing.' },
          fp_reason: { type: 'string', description: 'If not a variant, why it is safe. This feeds the false-positive table.' },
        },
      },
    },
  },
}

// ---------------------------------------------------------------------------
// Phase 1 - Root cause and expansion axes
// ---------------------------------------------------------------------------
phase('Root cause')

const rc = await agent(
  `You are performing the first step of a variant analysis (i.e., searching the codebase looking for vulnerabilities that are similar to an originally discovered vulnerability) on the codebase at \`${ROOT}\` (language: ${LANG}).

FIRST, resolve the strategy reference so the rest of this run can use it:
${RESOLVE_SKILL_DIR}

Then read \`<skill_dir>/references/root-cause.md\` and follow it.

The known bug:
${A.bug}

Read the actual vulnerable code, then produce the root cause statement, an exact-match
ripgrep ERE (POSIX extended, not PCRE) for the original vulnerable line, and the expansion
axes.`,
  { schema: ROOT_CAUSE_SCHEMA, label: 'root-cause' },
)

if (!rc) throw new Error('Root cause analysis failed; nothing downstream is meaningful without it.')

const SKILL_DIR = rc.skill_dir || ''
if (SKILL_DIR) {
  log(`Strategy references: ${SKILL_DIR}/references/`)
} else {
  log('WARNING: could not locate the skill directory. Stages will run without their strategy references, which degrades sweep and triage quality. Pass args.skill to fix.')
}
log(`Root cause: ${rc.statement}`)
log(`${rc.axes.length} expansion axes: ${rc.axes.map((x) => x.id).join(', ')}`)

// ---------------------------------------------------------------------------
// Phase 2 - Baseline gate
// ---------------------------------------------------------------------------
// A sweep calibrated against a pattern that matches nothing is a sweep that finds
// nothing and reports success. Fail loudly here instead.
//
// This stage deliberately gets no strategy reference. It runs one command and reports
// what came back
phase('Baseline')

const baseline = await agent(
  `Run these two commands against the codebase at \`${ROOT}\` and report exactly what they return.

1. The calibration pattern:

    rg -n --no-heading ${sh(rc.exact_pattern)} ${sh(ROOT)}

2. The size of the tree, which decides how wide the sweep needs to be. Count SOURCE
files only - restrict to the primary language's extensions when you can tell what it
is, and exclude vendored, generated, asset, and test-fixture directories. A project of
25 source files behind 300 fixtures is a small project:

    rg --files ${sh(ROOT)} | wc -l        # then narrow it, e.g. -g '*.py'

The pattern is supposed to match this known vulnerable line:
  ${rc.origin.file}:${rc.origin.line}
  ${rc.origin.snippet}

Report the true match count and locations, and source_file_count from the second command.
Set matches_origin only if one of the matches really is that line. Do not adjust the
pattern to make it work, just report what it does.`,
  { schema: BASELINE_SCHEMA, label: 'baseline', effort: 'low' },
)

if (!baseline || baseline.match_count === 0) {
  throw new Error(
    `Baseline gate failed: exact pattern matched 0 locations. The root cause pattern is wrong or the codebase root is wrong. Pattern: ${rc.exact_pattern}`,
  )
}
if (!baseline.matches_origin) {
  throw new Error(
    `Baseline gate failed: pattern matched ${baseline.match_count} location(s) but none is the known bug at ${rc.origin.file}:${rc.origin.line}. Everything downstream would be calibrated against the wrong code.`,
  )
}
log(`Baseline OK: ${baseline.match_count} match(es), origin confirmed.`)

// Size floor. Fanning six sweep agents and a triage batch per axis across a handful of
// files spends 25 agents to re-read what one agent could hold at once — and the eval's
// own negative result says exactly that: five small synthetic codebases showed no
// difference between the workflow and the skill alone, because "the fan-out had nothing
// to buy". Below the floor, sweep narrow and once.
const SMALL_TREE = 40
const isSmall = (baseline.source_file_count || 0) > 0 && baseline.source_file_count <= SMALL_TREE
const axesPerRound = isSmall ? 2 : MAX_AXES_PER_ROUND
const maxRounds = isSmall ? 1 : MAX_ROUNDS
if (isSmall) {
  log(
    `Small tree (${baseline.source_file_count} files ≤ ${SMALL_TREE}): sweeping ${axesPerRound} axes in 1 round instead of ${MAX_AXES_PER_ROUND}×${MAX_ROUNDS}. Fan-out buys nothing at this size.`,
  )
}

// ---------------------------------------------------------------------------
// Phases 3+4 - Sweep and triage, pipelined per axis
// ---------------------------------------------------------------------------
// Each axis triages as soon as its own sweep lands; a slow axis does not hold up
// verification of a fast one. Rounds repeat until the sweep goes dry.
const seen = new Set()
const confirmed = []
const rejected = []
const ladder = []
const key = (c) => `${c.file}:${c.line}`

let dry = 0
let round = 0
let stoppedForBudget = false
// Which axes actually got swept. A single-round sweep on a small tree covers only the
// first slice, and "we never looked" has to reach the report rather than only the live
// progress log — an artifact that omits it is indistinguishable from an exhausted sweep.
const sweptAxes = new Set()

while (round < maxRounds && dry < DRY_ROUNDS_TO_STOP) {
  // Checked BEFORE the increment: a round that never ran is not a round that ran,
  // and counting it made the report say "swept N rounds" and "hit the round cap"
  // for a sweep that actually stopped early on budget.
  if (budget.total && budget.remaining() < 60_000) {
    stoppedForBudget = true
    log(`Stopping after round ${round}: ~${Math.round(budget.remaining() / 1000)}k tokens left, below the floor for another round.`)
    break
  }
  round++

  // Rotate through the axes across rounds rather than re-running the same slice, so
  // a long axis list gets swept rather than truncated.
  const offset = ((round - 1) * axesPerRound) % rc.axes.length
  const axes = [...rc.axes, ...rc.axes].slice(offset, offset + axesPerRound).slice(0, rc.axes.length)
  axes.forEach((a) => sweptAxes.add(a.id))
  if (rc.axes.length > axesPerRound) {
    log(`Round ${round} sweeps ${axes.length}/${rc.axes.length} axes: ${axes.map((x) => x.id).join(', ')}`)
  }

  const known = [...seen].join(', ') || '(none yet)'

  const results = await pipeline(
    axes,

    // Sweep: climb the abstraction ladder on this axis alone.
    (axis) =>
      agent(
        `Variant analysis sweep, round ${round}, axis "${axis.id}" (${axis.kind}).

${ref(SKILL_DIR, 'searching.md')}

Codebase root: \`${ROOT}\`

Root cause being hunted:
  ${rc.statement}

Original instance:
  ${rc.origin.file}:${rc.origin.line}
  ${rc.origin.snippet}

Level 0 calibration pattern: ${rc.exact_pattern}

Your axis, and only this axis:
  ${axis.description}
  Concrete leads: ${axis.hints.join(', ')}

Already-known locations, do not re-report these: ${known}

Return every candidate this axis surfaces with the reason it realizes the same root cause,
and the ladder you climbed. Whether a candidate is exploitable is the next stage's call.
Report what you find rather than filtering on it.`,
        { schema: CANDIDATES_SCHEMA, label: `sweep:${axis.id}`, phase: 'Sweep' },
      ),

    // Dedup against everything seen so far, then batch for triage.
    (found, axis) => {
      if (!found) return []
      ladder.push(...(found.patterns_tried || []).map((p) => ({ ...p, axis: axis.id })))
      const fresh = (found.candidates || []).filter((c) => !seen.has(key(c)))
      fresh.forEach((c) => seen.add(key(c)))
      if (!fresh.length) return []
      const batches = []
      for (let i = 0; i < fresh.length; i += TRIAGE_BATCH) batches.push(fresh.slice(i, i + TRIAGE_BATCH))
      return batches.map((b) => ({ axis, batch: b }))
    },

    // Triage: adversarial, severity attached to everything.
    (batches) =>
      parallel(
        batches.map(({ axis, batch }) => () =>
          agent(
            `Triage ${batch.length} candidate variant(s) found on axis "${axis.id}" of a variant hunt.

${ref(SKILL_DIR, 'triage.md')}

Root cause being hunted:
  ${rc.statement}

Confirmed instance for comparison:
  ${rc.origin.file}:${rc.origin.line}
  ${rc.origin.snippet}

Candidates:
${batch.map((c, i) => `${i + 1}. ${c.file}:${c.line}\n   ${c.snippet}\n   claimed: ${c.why}`).join('\n')}

Return a verdict for every candidate, including the ones you judge minor.`,
            { schema: VERDICT_SCHEMA, label: `triage:${axis.id}`, phase: 'Triage' },
          ),
        ),
      ),
  )

  const verdicts = results
    .filter(Boolean)
    .flat()
    .filter(Boolean)
    .flatMap((r) => r.verdicts || [])

  const hits = verdicts.filter((v) => v.is_variant)
  confirmed.push(...hits)
  rejected.push(...verdicts.filter((v) => !v.is_variant))

  if (hits.length === 0) {
    dry++
    log(`Round ${round}: no new confirmed variants (${dry}/${DRY_ROUNDS_TO_STOP} dry rounds).`)
  } else {
    dry = 0
    log(`Round ${round}: +${hits.length} confirmed, ${confirmed.length} total.`)
  }
}

// Four ways out of that loop, and the report has to be told which. Only the dry exit
// means the sweep is exhausted; the rest are coverage bounds a reader needs to see, not
// just a line in the live log. The small-tree bound is deliberate rather than a
// truncation, so it is named separately — reporting it as "cap hit while still finding
// variants" would read as a warning about a sweep that did what it was asked to.
const sweptToDry = dry >= DRY_ROUNDS_TO_STOP
if (stoppedForBudget) {
  log(`COVERAGE BOUND: stopped after ${round} round(s) with the token budget exhausted. The sweep is not exhausted.`)
} else if (isSmall && !sweptToDry) {
  log(`Single-round sweep on a ${baseline.source_file_count}-file tree, as sized at the baseline gate.`)
} else if (round >= maxRounds && !sweptToDry) {
  log(`COVERAGE BOUND: stopped at the ${maxRounds}-round cap while still finding new variants. The sweep is not exhausted.`)
}

const stopReason = sweptToDry
  ? ' (swept to dry - no new variants in the last rounds)'
  : stoppedForBudget
    ? ' (STOPPED EARLY: token budget exhausted, not swept to dry - say so in the report)'
    : isSmall
      ? ` (single round, sized to a ${baseline.source_file_count}-file tree)`
      : ` (hit the ${maxRounds}-round cap - sweep not exhausted, say so in the report)`

// Any axis the loop never reached is a generalization nobody attempted. That belongs in
// the artifact, not just in the log the operator watched go by.
const unsweptAxes = rc.axes.filter((a) => !sweptAxes.has(a.id))
if (unsweptAxes.length) {
  log(`COVERAGE BOUND: ${unsweptAxes.length}/${rc.axes.length} axes never swept: ${unsweptAxes.map((a) => a.id).join(', ')}`)
}
const axisCoverage =
  `Axes swept: ${sweptAxes.size}/${rc.axes.length}` +
  (unsweptAxes.length
    ? `. NEVER SWEPT, and the report must say so under its own heading: ${unsweptAxes
        .map((a) => `${a.id} (${a.kind}) - ${a.description}`)
        .join('; ')}`
    : ' (all of them).')

// ---------------------------------------------------------------------------
// Phase 5 - Report
// ---------------------------------------------------------------------------
phase('Report')

const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }
confirmed.sort((a, b) => order[a.severity] - order[b.severity])

if (confirmed.length === 0) {
  log('No variants confirmed. Writing a report documenting the search anyway. Negative coverage is a result.')
}

await agent(
  `Write the variant analysis report to \`${OUT}\`.

${ref(SKILL_DIR, 'reporting.md')}
Follow the template at \`${template(SKILL_DIR)}\` - read it first. Use \`date -I\` for the date.

Match the report's length to what the findings need: cover the substance, but do not pad
with filler sections, redundant summaries, or boilerplate.

REQUIRED, and not negotiable for formatting reasons: give every confirmed variant its own
\`### \` block under a \`## Findings\` heading, and inside that block put the location on
its own line, exactly:

    **Location:** \`path/to/file.ext:LINE\`

Do not put the location only in the \`### \` header, and do not merge several findings into
one block. Downstream tooling reads the \`**Location:**\` lines to tell a real finding from
a path mentioned in passing while tracing data flow; a report that omits them is scored by
a fallback that cannot make that distinction. Ruled-out sites go under a separate
\`## False Positive Patterns\` heading, grouped by the reason they were safe.

Codebase: ${ROOT}
Original bug: ${A.bug}
Root cause: ${rc.statement}
Origin: ${rc.origin.file}:${rc.origin.line}
Baseline: exact pattern \`${rc.exact_pattern}\` matched ${baseline.match_count} location(s)
Rounds run: ${round}${stopReason}
${axisCoverage}

Abstraction ladder climbed, for the Search Methodology table:
${JSON.stringify(ladder, null, 2)}

Confirmed variants (${confirmed.length}), severity-ordered:
${JSON.stringify(confirmed, null, 2)}

Ruled out (${rejected.length}). These populate the False Positive Patterns table; group
them by the reason they were safe rather than listing each one:
${JSON.stringify(rejected, null, 2)}

Read the code at each confirmed location so the report quotes it accurately.`,
  { label: 'report', phase: 'Report' },
)

return {
  root_cause: rc.statement,
  origin: `${rc.origin.file}:${rc.origin.line}`,
  rounds: round,
  axes_total: rc.axes.length,
  axes_swept: sweptAxes.size,
  axes_unswept: unsweptAxes.map((a) => a.id),
  swept_to_dry: sweptToDry,
  stopped_for_budget: stoppedForBudget,
  confirmed: confirmed.length,
  rejected: rejected.length,
  variants: confirmed.map((v) => ({ at: `${v.file}:${v.line}`, severity: v.severity, confidence: v.confidence })),
  report: OUT,
}
