import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { FindingNormalizer } from '../normalizer.js'

describe('Finding Normalizer & Deterministic Grounding', () => {
  const sampleScan = {
    id: 'scan-test-123',
    repoName: 'test-repo',
    repoUrl: 'https://github.com/org/test-repo',
    branch: 'main',
    createdAt: '2026-09-20T10:00:00Z',
    durationMs: 42,
    filesAnalyzed: 18,
    findings: [
      {
        id: 'XSS-001',
        ruleId: 'ast/xss-innerhtml',
        ruleName: 'Cross-Site Scripting (DOM innerHTML)',
        cwe: 'CWE-79',
        severity: 'HIGH',
        filePath: 'src/interceptor/proxyDOM.js',
        line: 13,
        column: 3,
        snippet: "const decodedHtml = Buffer.from(req.query.rawB64 || '', 'base64').toString('utf8');\nproxy.innerHTML = decodedHtml;",
        sink: 'proxy.innerHTML',
        source: 'req.query.rawB64',
        message: 'Untrusted HTTP query input reaches DOM innerHTML sink without sanitization.',
        aiAnalysis: {
          model: 'qwen2.5-coder:3b',
          verdict: 'CONFIRMED_VULNERABILITY',
          confidence: 95,
          isFalsePositive: false,
          reason: 'Input from req.query flows directly to innerHTML sink. Base64 is not a sanitizer.',
          sanitizerDetected: false,
          safeCastDetected: false,
        },
      },
    ],
  }

  test('preserves deterministic scanner fields without modification', () => {
    const report = FindingNormalizer.normalizeScan(sampleScan)

    assert.equal(report.schemaVersion, '1.0')
    assert.equal(report.metadata.target.repositoryName, 'test-repo')
    assert.equal(report.metadata.target.branch, 'main')
    assert.equal(report.findings.length, 1)

    const f = report.findings[0]
    // Deterministic fields must match exactly
    assert.equal(f.location.file, 'src/interceptor/proxyDOM.js')
    assert.equal(f.location.line, 13)
    assert.equal(f.location.column, 3)
    assert.equal(f.rule.id, 'ast/xss-innerhtml')
    assert.equal(f.rule.cwe, 'CWE-79')
    assert.equal(f.severity, 'HIGH')
    assert.equal(f.taintFlow.sink.expression, 'proxy.innerHTML')
    assert.equal(f.taintFlow.source.expression, 'req.query.rawB64')
  })

  test('correctly normalizes AI analysis into separated structured block', () => {
    const report = FindingNormalizer.normalizeScan(sampleScan)
    const f = report.findings[0]

    assert.ok(f.analysis)
    assert.equal(f.analysis?.model, 'qwen2.5-coder:3b')
    assert.equal(f.analysis?.verdict, 'CONFIRMED')
    assert.equal(f.analysis?.confidence, 95)
    assert.equal(f.status, 'confirmed')
    assert.equal(f.analysis?.sanitizerDetected, false)
  })

  test('derives accurate vulnerability impact and remediation tailored to CWE-79', () => {
    const report = FindingNormalizer.normalizeScan(sampleScan)
    const f = report.findings[0]

    assert.ok(f.impact.description.includes('executable HTML/JavaScript'))
    assert.ok(f.impact.consequences.length >= 3)
    assert.ok(f.remediation.summary.includes('safe text assignment') || f.remediation.summary.includes('sanitization'))
    assert.ok(f.remediation.code?.includes('textContent'))
  })

  test('handles zero findings clean scan properly', () => {
    const cleanScan = {
      id: 'scan-clean-999',
      repoName: 'clean-app',
      repoUrl: 'https://github.com/org/clean-app',
      branch: 'main',
      filesAnalyzed: 120,
      findings: [],
    }

    const report = FindingNormalizer.normalizeScan(cleanScan)
    assert.equal(report.summary.posture, 'CLEAN')
    assert.equal(report.summary.statusVerdict, 'PASSED')
    assert.equal(report.findings.length, 0)
    assert.equal(report.summary.distribution.total, 0)
  })
})
