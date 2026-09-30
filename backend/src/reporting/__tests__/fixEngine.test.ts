import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateDeterministicHardenedFix,
  applySnippetReplacement,
} from '../../services/prFix.service.js'
import type { Finding } from '../../engine/types.js'

describe('Automated Security Fix Engine & Remediation Hardening', () => {
  it('1. Generates hardened fix for Command Injection (execSync)', () => {
    const finding: Finding = {
      id: 'CMDI-1',
      ruleId: 'CMDI-EXEC-01',
      ruleName: 'Command Injection in child_process.execSync',
      cwe: 'CWE-78',
      severity: 'CRITICAL',
      filePath: 'src/cli.js',
      line: 3,
      column: 15,
      message: 'Command injection vulnerability',
      sink: 'execSync(cmd)',
      snippet: 'const out = execSync(`ping -c 4 ${target}`);',
      remediation: 'Use spawn with argument array without shell',
    }
    const fileContent = `const { execSync } = require('child_process');\nfunction test(target) {\n  const out = execSync(\`ping -c 4 \${target}\`);\n  return out;\n}`

    const fix = generateDeterministicHardenedFix(finding, fileContent)
    assert.ok(fix.searchSnippet.includes('execSync'))
    assert.ok(fix.replacementSnippet.includes('shell: false') || fix.replacementSnippet.includes('execFileSync'))
    assert.ok(fix.explanation.length > 0)
  })

  it('2. Generates hardened fix for Command Injection (spawn with shell: true)', () => {
    const finding: Finding = {
      id: 'CMDI-2',
      ruleId: 'CMDI-SPAWN-SHELL',
      ruleName: 'Unsafe Subshell Spawning',
      cwe: 'CWE-78',
      severity: 'HIGH',
      filePath: 'src/runner.js',
      line: 2,
      column: 17,
      message: 'Unsafe subshell spawning',
      sink: 'spawn(bin, args, { shell: true })',
      snippet: 'spawn("sh", ["-c", userCmd], { shell: true })',
      remediation: 'Disable subshell execution',
    }
    const fileContent = `const { spawn } = require('child_process');\nconst child = spawn("sh", ["-c", userCmd], { shell: true });\nchild.on('close', done);`

    const fix = generateDeterministicHardenedFix(finding, fileContent)
    assert.ok(fix.searchSnippet.includes('shell: true'))
    assert.ok(fix.replacementSnippet.includes('shell: false'))
  })

  it('3. Generates hardened fix for SQL Injection ($queryRawUnsafe)', () => {
    const finding: Finding = {
      id: 'SQLI-1',
      ruleId: 'SQLI-PRISMA-RAW',
      ruleName: 'Prisma Unsafe Raw Query',
      cwe: 'CWE-89',
      severity: 'CRITICAL',
      filePath: 'src/db.js',
      line: 2,
      column: 25,
      message: 'Prisma raw query injection',
      sink: '$queryRawUnsafe(sql)',
      snippet: 'const users = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);',
      remediation: 'Use $queryRaw with template literal',
    }
    const fileContent = `async function getUser(id) {\n  const users = await prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE id = \${id}\`);\n  return users[0];\n}`

    const fix = generateDeterministicHardenedFix(finding, fileContent)
    assert.ok(fix.searchSnippet.includes('$queryRawUnsafe'))
    assert.ok(fix.replacementSnippet.includes('$queryRaw'))
    assert.ok(!fix.replacementSnippet.includes('$queryRawUnsafe'))
  })

  it('4. Generates hardened fix for Cross-Site Scripting (innerHTML)', () => {
    const finding: Finding = {
      id: 'XSS-1',
      ruleId: 'XSS-DOM-INNERHTML',
      ruleName: 'Direct innerHTML assignment',
      cwe: 'CWE-79',
      severity: 'HIGH',
      filePath: 'src/render.js',
      line: 2,
      column: 11,
      message: 'Direct innerHTML assignment',
      sink: 'element.innerHTML = html',
      snippet: 'element.innerHTML = userInput;',
      remediation: 'Sanitize with DOMPurify before assigning to innerHTML',
    }
    const fileContent = `function render(userInput) {\n  element.innerHTML = userInput;\n}`

    const fix = generateDeterministicHardenedFix(finding, fileContent)
    assert.ok(fix.searchSnippet.includes('innerHTML'))
    assert.ok(fix.replacementSnippet.includes('DOMPurify.sanitize'))
  })

  it('5. 4-Tier Snippet Matcher applies exact, normalized, and trimmed multi-line replacements', () => {
    const sourceCode = `function run() {\r\n    const a = 1;\r\n    const b = 2;\r\n    return a + b;\r\n}`

    // Exact / Line-ending normalized match
    const patch1 = applySnippetReplacement(sourceCode, 'const a = 1;', 'const a = 10;')
    assert.strictEqual(patch1.applied, true)
    assert.ok(patch1.updatedContent.includes('const a = 10;'))

    // Multi-line trimmed match
    const patch2 = applySnippetReplacement(
      sourceCode,
      'const a = 1;\nconst b = 2;',
      'const a = 10;\nconst b = 20;'
    )
    assert.strictEqual(patch2.applied, true)
    assert.ok(patch2.updatedContent.includes('const a = 10;'))
    assert.ok(patch2.updatedContent.includes('const b = 20;'))
  })
})
