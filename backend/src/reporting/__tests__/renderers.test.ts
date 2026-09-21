import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { FindingNormalizer } from '../normalizer.js'
import { JsonReporter } from '../renderers/jsonReporter.js'
import { MarkdownReporter } from '../renderers/markdownReporter.js'
import { HtmlReporter } from '../renderers/htmlReporter.js'

describe('Report Renderers (JSON, Markdown, HTML)', () => {
  const sampleScan = {
    id: 'scan-xss-001',
    repoName: 'vulnsites',
    repoUrl: 'https://github.com/mohitdevx/vulnsites',
    branch: 'insane',
    durationMs: 38,
    filesAnalyzed: 45,
    findings: [
      {
        id: 'XSS-001',
        ruleId: 'ast/xss-innerhtml',
        ruleName: 'DOM Cross-Site Scripting (XSS)',
        cwe: 'CWE-79',
        severity: 'HIGH',
        filePath: 'src/interceptor/proxyDOM.js',
        line: 13,
        column: 3,
        snippet: "const decodedHtml = Buffer.from(req.query.rawB64 || '', 'base64').toString('utf8');\nproxy.innerHTML = decodedHtml;",
        sink: 'proxy.innerHTML',
        source: 'req.query.rawB64',
        message: 'Untrusted HTTP input reaches a DOM HTML execution sink without an identifiable sanitization step.',
        aiAnalysis: {
          model: 'qwen2.5-coder:3b',
          verdict: 'CONFIRMED_VULNERABILITY',
          confidence: 95,
          isFalsePositive: false,
          reason: 'The value originates from an HTTP query parameter and reaches innerHTML without an identified sanitization boundary. Base64 encoding does not provide security sanitization.',
          sanitizerDetected: false,
          safeCastDetected: false,
        },
      },
    ],
  }

  const report = FindingNormalizer.normalizeScan(sampleScan)

  test('JsonReporter outputs canonical valid JSON matching schemaVersion 1.0', () => {
    const jsonReporter = new JsonReporter()
    const jsonString = jsonReporter.render(report)

    assert.equal(jsonReporter.format, 'json')
    assert.equal(jsonReporter.contentType, 'application/json')

    const parsed = JSON.parse(jsonString)
    assert.equal(parsed.schemaVersion, '1.0')
    assert.equal(parsed.metadata.target.repositoryName, 'vulnsites')
    assert.equal(parsed.summary.distribution.high, 1)
    assert.equal(parsed.findings.length, 1)
    assert.equal(parsed.findings[0].id, 'XSS-001')
  })

  test('MarkdownReporter outputs GitHub-flavored markdown with structured tables and alert blocks', () => {
    const mdReporter = new MarkdownReporter()
    const md = mdReporter.render(report)

    assert.equal(mdReporter.format, 'markdown')

    // Document header & repository
    assert.ok(md.includes('# VulScan Security Assessment Report: vulnsites'))
    assert.ok(md.includes('`https://github.com/mohitdevx/vulnsites`'))

    // Posture caution block
    assert.ok(md.includes('> [!CAUTION]'))
    assert.ok(md.includes('1 HIGH-SEVERITY VULNERABILITY DETECTED'))

    // Tables
    assert.ok(md.includes('| Severity | Findings Count | Priority |'))
    assert.ok(md.includes('| [XSS-001](#xss-001) | DOM Cross-Site Scripting (XSS) | **HIGH** | `CWE-79` |'))

    // Detailed finding
    assert.ok(md.includes('### [HIGH] XSS-001 — DOM Cross-Site Scripting (XSS)'))
    assert.ok(md.includes('src/interceptor/proxyDOM.js:13:3'))
    assert.ok(md.includes('`proxy.innerHTML`'))

    // Taint Flow ASCII diagram
    assert.ok(md.includes('SOURCE: req.query.rawB64'))
    assert.ok(md.includes('TRANSFORMATION: Base64 Decode'))
    assert.ok(md.includes('SINK:   proxy.innerHTML'))

    // Flagged code with line numbers
    assert.ok(md.includes('>>>   13 │ proxy.innerHTML = decodedHtml;'))

    // Security Advisory & Verification
    assert.ok(md.includes('#### Security Advisory & Taint Analysis'))
    assert.ok(md.includes('`qwen2.5-coder:3b`'))
    assert.ok(md.includes('CONFIRMED VULNERABILITY'))
    assert.ok(md.includes('95%'))

    // Impact & Remediation
    assert.ok(md.includes('#### Security Impact & Consequences'))
    assert.ok(md.includes('#### Recommended Remediation'))
    assert.ok(md.includes('proxy.textContent = decodedHtml;'))
  })

  test('HtmlReporter outputs standalone production HTML dashboard with syntax highlighting and CSS variables', () => {
    const htmlReporter = new HtmlReporter()
    const html = htmlReporter.render(report)

    assert.equal(htmlReporter.format, 'html')

    // HTML5 Document
    assert.ok(html.startsWith('<!DOCTYPE html>'))
    assert.ok(html.includes('<title>VulScan Security Assessment - vulnsites (insane)</title>'))

    // CSS variables & styles
    assert.ok(html.includes('--severity-critical: #ef4444;'))
    assert.ok(html.includes('--severity-high: #f97316;'))

    // Posture & Metrics
    assert.ok(html.includes('VulScan'))
    assert.ok(html.includes('Critical'))
    assert.ok(html.includes('High'))

    // Finding card
    assert.ok(html.includes('id="XSS-001"'))
    assert.ok(html.includes('DOM Cross-Site Scripting (XSS)'))
    assert.ok(html.includes('src/interceptor/proxyDOM.js:13:3'))

    // Taint Flow Visual Component
    assert.ok(html.includes('<div class="taint-flow-container">'))
    assert.ok(html.includes('SOURCE'))
    assert.ok(html.includes('req.query.rawB64'))
    assert.ok(html.includes('TRANSFORMATION'))
    assert.ok(html.includes('Base64 Decode'))
    assert.ok(html.includes('SINK'))
    assert.ok(html.includes('proxy.innerHTML'))

    // Code Evidence with Line highlight
    assert.ok(html.includes('code-evidence-box'))
    assert.ok(html.includes('code-row flagged'))

    // Security Advisory & Remediation
    assert.ok(html.includes('Security Advisory & Verification (qwen2.5-coder:3b)'))
    assert.ok(html.includes('remediation-code'))

    // Interactive Script
    assert.ok(html.includes('finding-search-input'))
    assert.ok(html.includes('filter-pill'))
  })
})
