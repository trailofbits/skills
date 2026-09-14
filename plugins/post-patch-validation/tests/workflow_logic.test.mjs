import assert from 'node:assert/strict'
import { test } from 'node:test'
import path from 'node:path'
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

test('only unanimous review can advance S1 to human review', () => {
  const ok = approved => ({ approved, evidenceRead: ['results/result.json'] })
  const yes = [ok(true), ok(true)]
  assert.equal(finalStatus('S1', yes), 'READY_FOR_HUMAN_REVIEW')
  assert.equal(finalStatus('S1', [ok(true), ok(false)]), 'REVIEW_REQUIRED')
  assert.equal(finalStatus('S1', [yes[0]]), 'REVIEW_REQUIRED')
  for (const verdict of ['S2', 'S3', 'S4', 'S5', 'INCONCLUSIVE']) {
    assert.equal(finalStatus(verdict, yes), 'REJECTED')
  }
})

test('a reviewer that read nothing cannot approve', () => {
  const read = { approved: true, evidenceRead: ['results/result.json'] }
  for (const empty of [{ approved: true, evidenceRead: [] }, { approved: true }]) {
    assert.equal(finalStatus('S1', [read, empty]), 'REVIEW_REQUIRED')
  }
})
