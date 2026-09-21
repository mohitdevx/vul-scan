import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { generateSecurityReport } from '../index.js'

describe('Reporting Engine Fixture Tests', () => {
  // Primary test fixture from Section 31
  const xssPrimaryFixture = {
    id: 'scan-sec31-fixture',
    repoName: 'vulnsites',
    repoUrl: 'https://github.com/mohitdevx/vulnsites',
    branch: 'insane',
    createdAt: '2026-09-20T12:00:00.000Z',
    durationMs: 28,
    filesAnalyzed: 14,
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
        source: 'req.query.rawB64',
        sink: 'proxy.innerHTML',
        snippet: "const decodedHtml =\n  Buffer.from(req.query.rawB64 || '', 'base64')\n    .toString('utf8');\n\nproxy['innerHTML'] = decodedHtml;",
        message: 'Untrusted HTTP input reaches a DOM HTML execution sink without an identifiable sanitization step.',
        aiAnalysis: {
          model: 'qwen2.5-coder:3b',
          verdict: 'CONFIRMED',
          confidence: 95,
          isFalsePositive: false,
          reason: 'The value originates from an HTTP query parameter and reaches innerHTML without an identified sanitization boundary. Base64 encoding does not provide security sanitization.',
          sanitizerDetected: false,
          safeCastDetected: false,
        },
      },
    ],
  }

  test('Primary XSS-001 Fixture generates valid IR, JSON, Markdown, and HTML', () => {
    const { ir, json, markdown, html } = generateSecurityReport(xssPrimaryFixture)

    // 1. Report IR
    assert.equal(ir.schemaVersion, '1.0')
    assert.equal(ir.metadata.target.repositoryName, 'vulnsites')
    assert.equal(ir.metadata.target.branch, 'insane')
    assert.equal(ir.summary.posture, 'HIGH_RISK')
    assert.equal(ir.summary.statusVerdict, 'ACTION_REQUIRED')
    assert.equal(ir.findings.length, 1)

    const f = ir.findings[0]
    assert.equal(f.id, 'XSS-001')
    assert.equal(f.rule.id, 'ast/xss-innerhtml')
    assert.equal(f.rule.cwe, 'CWE-79')
    assert.equal(f.severity, 'HIGH')
    assert.equal(f.location.file, 'src/interceptor/proxyDOM.js')
    assert.equal(f.location.line, 13)
    assert.equal(f.taintFlow.source.expression, 'req.query.rawB64')
    assert.equal(f.taintFlow.sink.expression, 'proxy.innerHTML')
    assert.equal(f.analysis?.verdict, 'CONFIRMED')
    assert.equal(f.analysis?.confidence, 95)

    // 2. JSON
    const parsedJson = JSON.parse(json)
    assert.equal(parsedJson.findings[0].id, 'XSS-001')

    // 3. Markdown
    assert.ok(markdown.includes('### [HIGH] XSS-001 — Cross-Site Scripting (DOM innerHTML)'))
    assert.ok(markdown.includes('SOURCE: req.query.rawB64'))
    assert.ok(markdown.includes('SINK:   proxy.innerHTML'))
    assert.ok(markdown.includes('src/interceptor/proxyDOM.js:13:3'))
    assert.ok(markdown.includes('proxy.textContent = decodedHtml;'))

    // 4. HTML
    assert.ok(html.includes('id="XSS-001"'))
    assert.ok(html.includes('Cross-Site Scripting (DOM innerHTML)'))
    assert.ok(html.includes('req.query.rawB64'))
    assert.ok(html.includes('proxy.innerHTML'))
    assert.ok(html.includes('src/interceptor/proxyDOM.js:13:3'))
  })

  test('Multi-Vulnerability Report (XSS, SQLi, CMDi) generates cohesive report with priority sorting', () => {
    const multiScan = {
      id: 'scan-multi-findings',
      repoName: 'enterprise-app',
      repoUrl: 'https://github.com/org/enterprise-app',
      branch: 'main',
      filesAnalyzed: 80,
      findings: [
        {
          id: 'XSS-001',
          ruleId: 'ast/xss-innerhtml',
          ruleName: 'DOM Cross-Site Scripting (XSS)',
          cwe: 'CWE-79',
          severity: 'HIGH',
          filePath: 'src/views/render.js',
          line: 22,
          snippet: 'document.getElementById("output").innerHTML = req.query.msg;',
          sink: 'output.innerHTML',
          source: 'req.query.msg',
        },
        {
          id: 'SQL-002',
          ruleId: 'ast/sqli-unparameterized',
          ruleName: 'SQL Injection (SQLi)',
          cwe: 'CWE-89',
          severity: 'CRITICAL',
          filePath: 'src/db/users.js',
          line: 45,
          snippet: 'const query = "SELECT * FROM users WHERE id = " + req.params.id;\ndb.query(query);',
          sink: 'db.query',
          source: 'req.params.id',
        },
        {
          id: 'CMD-003',
          ruleId: 'ast/cmdi-exec',
          ruleName: 'OS Command Injection (CMDi)',
          cwe: 'CWE-78',
          severity: 'CRITICAL',
          filePath: 'src/utils/system.js',
          line: 12,
          snippet: 'child_process.exec("ping -c 1 " + req.body.host);',
          sink: 'child_process.exec',
          source: 'req.body.host',
        },
      ],
    }

    const { ir, markdown, html } = generateSecurityReport(multiScan)

    assert.equal(ir.findings.length, 3)
    assert.equal(ir.summary.distribution.critical, 2)
    assert.equal(ir.summary.distribution.high, 1)
    assert.equal(ir.summary.posture, 'CRITICAL_RISK')

    assert.ok(markdown.includes('2 CRITICAL-SEVERITY VULNERABILITIES FLAGGED'))
    assert.ok(markdown.includes('SQL-002'))
    assert.ok(markdown.includes('CMD-003'))
    assert.ok(markdown.includes('XSS-001'))

    assert.ok(html.includes('id="SQL-002"'))
    assert.ok(html.includes('id="CMD-003"'))
    assert.ok(html.includes('id="XSS-001"'))
  })
})
