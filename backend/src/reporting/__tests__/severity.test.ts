import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  SEVERITY_METADATA,
  getSeverityMeta,
  compareSeverity,
  calculateDistribution,
  computeSummary,
} from '../severity.js'

describe('Severity System & Posture Calculation', () => {
  test('correctly retrieves metadata for all severity levels', () => {
    assert.equal(getSeverityMeta('CRITICAL').numericPriority, 5)
    assert.equal(getSeverityMeta('HIGH').numericPriority, 4)
    assert.equal(getSeverityMeta('MEDIUM').numericPriority, 3)
    assert.equal(getSeverityMeta('LOW').numericPriority, 2)
    assert.equal(getSeverityMeta('INFO').numericPriority, 1)

    // Case insensitivity
    assert.equal(getSeverityMeta('high').numericPriority, 4)
    assert.equal(getSeverityMeta('critical').numericPriority, 5)

    // Fallback for unknown
    assert.equal(getSeverityMeta('UNKNOWN' as any).numericPriority, 3)
  })

  test('compares and sorts severity levels correctly in descending order', () => {
    assert.ok(compareSeverity('CRITICAL', 'HIGH') < 0)
    assert.ok(compareSeverity('HIGH', 'MEDIUM') < 0)
    assert.ok(compareSeverity('MEDIUM', 'LOW') < 0)
    assert.ok(compareSeverity('LOW', 'INFO') < 0)
    assert.equal(compareSeverity('HIGH', 'HIGH'), 0)
  })

  test('calculates accurate severity distribution from findings', () => {
    const findings = [
      { severity: 'CRITICAL' },
      { severity: 'HIGH' },
      { severity: 'HIGH' },
      { severity: 'MEDIUM' },
      { severity: 'LOW' },
      { severity: 'INFO' },
    ]

    const dist = calculateDistribution(findings)
    assert.equal(dist.critical, 1)
    assert.equal(dist.high, 2)
    assert.equal(dist.medium, 1)
    assert.equal(dist.low, 1)
    assert.equal(dist.info, 1)
    assert.equal(dist.total, 6)
  })

  test('computes posture correctly for clean, high, critical, and medium scans', () => {
    // 1. Clean scan
    const cleanSummary = computeSummary([])
    assert.equal(cleanSummary.posture, 'CLEAN')
    assert.equal(cleanSummary.statusVerdict, 'PASSED')
    assert.equal(cleanSummary.distribution.total, 0)

    // 2. High severity scan
    const highSummary = computeSummary([
      {
        id: 'XSS-1',
        rule: { id: 'xss', name: 'XSS', category: 'Injection', cwe: 'CWE-79' },
        severity: 'HIGH',
        confidence: 95,
        status: 'confirmed',
        location: { file: 'app.js', line: 10 },
        taintFlow: {
          source: { type: 'source', label: 'src', expression: 'req.query' },
          transformations: [],
          sink: { type: 'sink', label: 'sink', expression: 'innerHTML' },
        },
        evidence: { code: 'x', language: 'js', startLine: 1, endLine: 1 },
        impact: { description: 'desc', consequences: [] },
        remediation: { summary: 'fix', explanation: 'fix' },
        rawMessage: 'msg',
      },
    ])
    assert.equal(highSummary.posture, 'HIGH_RISK')
    assert.equal(highSummary.statusVerdict, 'ACTION_REQUIRED')
    assert.equal(highSummary.confirmedCount, 1)

    // 3. Critical severity scan
    const criticalSummary = computeSummary([
      {
        id: 'CMD-1',
        rule: { id: 'cmdi', name: 'CMDi', category: 'Injection', cwe: 'CWE-78' },
        severity: 'CRITICAL',
        confidence: 98,
        status: 'confirmed',
        location: { file: 'shell.js', line: 5 },
        taintFlow: {
          source: { type: 'source', label: 'src', expression: 'req.body' },
          transformations: [],
          sink: { type: 'sink', label: 'sink', expression: 'exec' },
        },
        evidence: { code: 'x', language: 'js', startLine: 1, endLine: 1 },
        impact: { description: 'desc', consequences: [] },
        remediation: { summary: 'fix', explanation: 'fix' },
        rawMessage: 'msg',
      },
    ])
    assert.equal(criticalSummary.posture, 'CRITICAL_RISK')
    assert.equal(criticalSummary.statusVerdict, 'ACTION_REQUIRED')
  })
})
