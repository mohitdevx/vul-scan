import test from 'node:test'
import assert from 'node:assert/strict'
import { extractCodeContext, inspectGroundTruthSafety } from '../../services/aiValidator.service.js'

test('AI Validator Logic & Context Extraction Suite', async (t) => {
  await t.test('1. Extracts top imports and target function context accurately', () => {
    const code = [
      'import Redis from "ioredis";',
      'import { config } from "./config";',
      '',
      'const redisClient = new Redis();',
      '',
      'export const getCache = async (key: string) => {',
      '  if (!redisClient) return null;',
      '  return await redisClient.get(key);',
      '};',
    ].join('\n')

    const context = extractCodeContext(code, 8, 5)
    assert.ok(context.includes('>>> L8 [CANDIDATE]:   return await redisClient.get(key);'))
    assert.ok(context.includes('import Redis from "ioredis"'))
  })

  await t.test('2. Accurately detects sanitizers and numeric casts', () => {
    const safeCode = 'const val = parseInt(input, 10); const clean = DOMPurify.sanitize(val);'
    const inspection = inspectGroundTruthSafety(safeCode)
    assert.equal(inspection.hasSanitizer, true)
    assert.equal(inspection.hasNumberCast, true)
    assert.equal(inspection.sanitizerMatched, 'dompurify')
    assert.equal(inspection.numberCastMatched, 'parseint')
  })

  await t.test('3. Accurately returns false when no sanitizers are present', () => {
    const rawCode = 'const query = "SELECT * FROM users WHERE id = " + req.query.id;'
    const inspection = inspectGroundTruthSafety(rawCode)
    assert.equal(inspection.hasSanitizer, false)
    assert.equal(inspection.hasNumberCast, false)
  })
})
