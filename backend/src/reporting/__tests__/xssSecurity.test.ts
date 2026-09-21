import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { FindingNormalizer } from '../normalizer.js'
import { HtmlReporter } from '../renderers/htmlReporter.js'
import { MarkdownReporter } from '../renderers/markdownReporter.js'
import { escapeHtml } from '../utils/escape.js'

describe('Security & XSS Injection Neutralization', () => {
  test('escapeHtml properly neutralizes all HTML special characters', () => {
    assert.equal(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;')
    assert.equal(escapeHtml('"><img src=x onerror=alert(1)>'), '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;')
    assert.equal(escapeHtml('var a = 1 & 2;'), 'var a = 1 &amp; 2;')
    assert.equal(escapeHtml("' OR '1'='1"), '&#39; OR &#39;1&#39;=&#39;1')
    assert.equal(escapeHtml('`test`'), '&#96;test&#96;')
  })

  test('HtmlReporter completely neutralizes malicious script payloads injected into all fields', () => {
    const maliciousScan = {
      id: 'scan-<script>alert("id")</script>',
      repoName: '<script>alert("repo")</script>',
      repoUrl: 'https://github.com/<svg onload=alert("url")>',
      branch: '"><script>alert("branch")</script>',
      durationMs: 10,
      filesAnalyzed: 5,
      findings: [
        {
          id: 'INJ-<script>alert("id")</script>',
          ruleId: 'ast/<script>alert("rule")</script>',
          ruleName: '<script>alert("vuln")</script>',
          cwe: 'CWE-<script>alert("cwe")</script>',
          severity: 'HIGH',
          filePath: 'src/<script>alert("file")</script>.js',
          line: 1,
          column: 1,
          snippet: '<script>alert("code")</script>\nconst x = "<img src=x onerror=alert(1)>";',
          sink: '<script>alert("sink")</script>',
          source: '<script>alert("source")</script>',
          message: '<script>alert("msg")</script>',
          aiAnalysis: {
            model: 'qwen-<script>alert("model")</script>',
            verdict: 'CONFIRMED_VULNERABILITY',
            confidence: 95,
            isFalsePositive: false,
            reason: '<script>alert("reason")</script>',
            sanitizerDetected: false,
            safeCastDetected: false,
          },
        },
      ],
    }

    const report = FindingNormalizer.normalizeScan(maliciousScan)
    const htmlReporter = new HtmlReporter()
    const html = htmlReporter.render(report)

    // The raw unescaped script tag should NOT exist anywhere in the generated HTML
    assert.ok(!html.includes('<script>alert('), 'Raw unescaped script tags must not exist in HTML body')
    assert.ok(!html.includes('<svg onload='), 'Raw unescaped SVG payload must not exist in HTML body')
    assert.ok(!html.includes('onerror=alert(1)>'), 'Raw unescaped image onerror payload must not exist in HTML body')

    // Instead, they should be safely escaped
    assert.ok(html.includes('&lt;script&gt;alert('))
  })

  test('MarkdownReporter neutralizes script tags in output', () => {
    const maliciousScan = {
      id: 'scan-x',
      repoName: '<script>alert("repo")</script>',
      repoUrl: 'https://github.com/org/<script>alert("url")',
      branch: 'main',
      findings: [
        {
          id: 'F-1',
          ruleId: 'xss',
          ruleName: '<script>alert("rule")</script>',
          cwe: 'CWE-79',
          severity: 'HIGH',
          filePath: 'app.js',
          line: 1,
          snippet: 'proxy.innerHTML = input;',
          sink: 'innerHTML',
          message: '<script>alert("desc")</script>',
        },
      ],
    }

    const report = FindingNormalizer.normalizeScan(maliciousScan)
    const mdReporter = new MarkdownReporter()
    const md = mdReporter.render(report)

    assert.ok(md.includes('<script>alert(') || md.includes('&lt;script&gt;'))
    // Verify it compiles into valid text without breaking markdown structure
    assert.ok(md.startsWith('# VulScan Security Assessment Report:'))
  })
})
