import assert from 'node:assert/strict'
import { test } from 'node:test'
import path from 'node:path'
import fs from 'node:fs'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'

import { loadFunction } from './extract.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const workflow = path.join(here, '..', 'workflows', 'validate-patch.js')
const normalizeArgs = loadFunction(workflow, 'normalizeArgs')
const argProblems = loadFunction(workflow, 'argProblems')
const finalStatus = loadFunction(workflow, 'finalStatus')
const plain = value => JSON.parse(JSON.stringify(value))

test('structured input is normalized without widening patch scope', () => {
  assert.deepEqual(
    plain(
      normalizeArgs({
        finding: '  finding.md ',
        baseRef: ' vulnerable ',
        patchRef: ' fix ',
        workdir: ' evidence ',
      }),
    ),
    {
      finding: 'finding.md',
      baseRef: 'vulnerable',
      patchRef: 'fix',
      patchFile: '',
      workdir: 'evidence',
    },
  )
})

test('patch files suppress the default HEAD ref', () => {
  const input = normalizeArgs({ finding: 'bug', baseRef: 'base', patchFile: 'fix.patch' })
  assert.equal(input.patchFile, 'fix.patch')
  assert.equal(input.patchRef, '')
  assert.deepEqual(plain(argProblems(input)), [])
})

test('explicit patch refs and patch files are mutually exclusive', () => {
  const input = normalizeArgs({
    finding: 'bug',
    baseRef: 'base',
    patchRef: 'fix-commit',
    patchFile: 'fix.patch',
  })
  assert.equal(input.patchRef, 'fix-commit')
  assert.equal(input.patchFile, 'fix.patch')
  assert.ok(argProblems(input).includes('only one of patchRef or patchFile'))
})

test('missing baseline and unsafe workdirs fail before dispatch', () => {
  const input = normalizeArgs({ finding: 'bug', workdir: '../escape' })
  const problems = argProblems(input)
  assert.ok(problems.includes('baseRef'))
  assert.ok(problems.some(value => value.startsWith('workdir')))
})

const passed = { status: 'complete', findings: [], gaps: [], human_review_required: true }

test('only unanimous review can advance passing checks to human review', () => {
  const ok = approved => ({ approved, evidenceRead: ['results/result.json'] })
  const yes = [ok(true), ok(true)]
  assert.equal(finalStatus(passed, yes), 'READY_FOR_HUMAN_REVIEW')
  assert.equal(finalStatus(passed, [ok(true), ok(false)]), 'REVIEW_REQUIRED')
  assert.equal(finalStatus(passed, [yes[0]]), 'REVIEW_REQUIRED')
})

test('a reviewer that read nothing cannot approve', () => {
  const read = { approved: true, evidenceRead: ['results/result.json'] }
  for (const empty of [{ approved: true, evidenceRead: [] }, { approved: true }]) {
    assert.equal(finalStatus(passed, [read, empty]), 'REVIEW_REQUIRED')
  }
})

test('findings require repair even when unrelated checks are incomplete', () => {
  const finding = { check_id: 'variant', kind: 'variant', message: 'Assertion still fails.' }
  for (const gaps of [[], [{ check_id: 'suite', reason: 'Could not start.' }]]) {
    const assessment = { ...passed, status: gaps.length ? 'incomplete' : 'complete', findings: [finding], gaps }
    const before = JSON.stringify(assessment)
    assert.equal(finalStatus(assessment, []), 'NEEDS_REPAIR')
    assert.equal(JSON.stringify(assessment), before)
  }
})

test('missing evidence blocks a result without supported failures', () => {
  const gap = { check_id: 'suite', reason: 'Timed out.' }
  for (const assessment of [
    { ...passed, status: 'incomplete', gaps: [gap] },
    { ...passed, status: 'incomplete' },
    { ...passed, gaps: [gap] },
  ]) {
    assert.equal(finalStatus(assessment, []), 'BLOCKED')
  }
})

test('the full workflow handoff preserves every finding and gap beside reviewer concerns', async () => {
  const assessment = {
    status: 'incomplete',
    findings: [
      { check_id: 'cancel', kind: 'variant', message: 'Safety assertion still fails.' },
      { check_id: 'cleanup', kind: 'security', message: 'Security check fails after patch.' },
    ],
    gaps: [{ check_id: 'suite', reason: 'The command could not start.' }],
    human_review_required: true,
  }
  const execution = {
    hasResult: true, assessment, evidenceLevel: 'runtime',
    resultPath: 'results/result.json', reportPath: 'results/report.md',
  }
  const before = JSON.stringify(execution)
  const body = fs.readFileSync(workflow, 'utf8').replace(/^export const meta = \{[\s\S]*?^\}\n/m, '')
  const run = vm.runInNewContext(`(async function(args, log, phase, agent, parallel) { ${body} })`)
  let deliveredExecution = execution
  let reviewCalls = 0
  const agent = async (_prompt, options) => {
    if (options.label === 'inventory') return { planPath: 'plan.json' }
    if (options.label === 'plan') return { complete: true, planPath: 'plan.json' }
    if (options.label === 'execute') return deliveredExecution
    if (options.label.startsWith('review:')) {
      reviewCalls += 1
      return { lens: options.label, approved: false, concerns: ['A sibling path is untested.'],
        evidenceRead: ['results/result.json'] }
    }
    return { lens: options.label, observations: [], proposals: [] }
  }
  const result = await run(
    { finding: 'test finding', baseRef: 'base', patchRef: 'patched' },
    () => {}, () => {}, agent, tasks => Promise.all(tasks.map(task => task())),
  )
  assert.equal(result.status, 'NEEDS_REPAIR')
  assert.deepEqual(plain(result.assessment), assessment)
  assert.equal(JSON.stringify(execution), before)
  assert.equal(result.evidenceLevel, 'runtime')
  assert.equal(result.resultPath, execution.resultPath)
  assert.equal(result.reviews.length, 2)
  assert.deepEqual(plain(result.reviews[0].concerns), ['A sibling path is untested.'])
  deliveredExecution = { hasResult: false, blocker: 'The patch pin changed before execution.' }
  const blocked = await run(
    { finding: 'test finding', baseRef: 'base', patchRef: 'patched' },
    () => {}, () => {}, agent, tasks => Promise.all(tasks.map(task => task())),
  )
  assert.equal(blocked.status, 'BLOCKED')
  assert.equal(blocked.reason, deliveredExecution.blocker)
  assert.equal(blocked.assessment, undefined)
  assert.equal(reviewCalls, 2, 'Review must not run when there is no result artifact')
})
