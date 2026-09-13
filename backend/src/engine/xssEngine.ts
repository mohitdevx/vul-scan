import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'

const traverse = (traverseModule as any).default || traverseModule

const SANITIZER_NAMES = new Set([
  'sanitize',
  'dompurify',
  'escapehtml',
  'escape',
  'encodeuricomponent',
  'encodeuri',
  'clean',
])

function isSanitizedExpression(node: any): boolean {
  if (!node) return false
  if (node.type === 'CallExpression') {
    const callee = node.callee
    if (callee.type === 'Identifier') {
      const name = callee.name.toLowerCase()
      if (Array.from(SANITIZER_NAMES).some(s => name.includes(s))) return true
    }
    if (callee.type === 'MemberExpression') {
      const prop = callee.property
      if (prop && prop.name) {
        const name = prop.name.toLowerCase()
        if (Array.from(SANITIZER_NAMES).some(s => name.includes(s))) return true
      }
      const obj = callee.object
      if (obj && obj.name && obj.name.toLowerCase().includes('dompurify')) return true
    }
  }
  return false
}

function isDynamicValue(node: any): boolean {
  if (!node) return false
  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral' || node.type === 'BooleanLiteral') {
    return false
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions && node.expressions.length > 0
  }
  if (node.type === 'BinaryExpression') {
    return true
  }
  if (node.type === 'Identifier' || node.type === 'MemberExpression' || node.type === 'CallExpression') {
    return !isSanitizedExpression(node)
  }
  return false
}

export const xssEngine: SecurityEngine = {
  name: 'Cross-Site Scripting (XSS) Engine',
  ruleId: 'engine/ast-xss',
  cwe: 'CWE-79',

  analyze(ast: any, ctx: EngineContext): Finding[] {
    const findings: Finding[] = []
    let counter = 1

    traverse(ast, {
      // 1. innerHTML / outerHTML assignment
      AssignmentExpression(path: any) {
        const { left, right } = path.node
        if (left && left.type === 'MemberExpression' && left.property) {
          const propName = left.property.name || left.property.value
          if (propName === 'innerHTML' || propName === 'outerHTML') {
            if (isDynamicValue(right) && !isSanitizedExpression(right)) {
              const line = left.loc?.start.line || 1
              const col = left.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-innerhtml',
                ruleName: 'Cross-Site Scripting (DOM innerHTML/outerHTML)',
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `element.${propName}`,
                message: `Unsanitized dynamic value assigned directly to DOM sink 'element.${propName}'. This allows script execution if the source contains attacker-controlled markup.`,
                remediation: `Use 'element.textContent' for plain text, or sanitize untrusted HTML using 'DOMPurify.sanitize()' before assigning to innerHTML.`,
              })
            }
          }
        }
      },

      // 2. document.write / document.writeln
      CallExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (
          callee &&
          callee.type === 'MemberExpression' &&
          callee.object?.name === 'document' &&
          (callee.property?.name === 'write' || callee.property?.name === 'writeln')
        ) {
          const firstArg = args[0]
          if (firstArg && isDynamicValue(firstArg) && !isSanitizedExpression(firstArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-document-write',
              ruleName: 'Cross-Site Scripting (document.write)',
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `document.${callee.property.name}`,
              message: `Call to dangerous DOM sink 'document.${callee.property.name}' with unsanitized dynamic markup.`,
              remediation: `Avoid document.write entirely. Use modern DOM APIs like document.createElement() and set element.textContent or element.setAttribute().`,
            })
          }
        }

        // 3. Server-side reflected HTML via res.send/res.write with HTML concatenation
        if (
          callee &&
          callee.type === 'MemberExpression' &&
          (callee.object?.name === 'res' || callee.object?.name === 'response') &&
          (callee.property?.name === 'send' || callee.property?.name === 'write')
        ) {
          const firstArg = args[0]
          if (firstArg && (firstArg.type === 'BinaryExpression' || firstArg.type === 'TemplateLiteral')) {
            const rawText = ctx.lines[callee.loc?.start.line - 1] || ''
            if (rawText.includes('<') && rawText.includes('>') && !isSanitizedExpression(firstArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-reflected-response',
                ruleName: 'Reflected Cross-Site Scripting (Server Response)',
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `res.${callee.property.name}`,
                message: `HTTP response payload contains raw HTML string concatenation with unescaped expressions.`,
                remediation: `Render views using a template engine with auto-escaping enabled (e.g. EJS, Pug) or set Content-Type: application/json.`,
              })
            }
          }
        }
      },

      // 4. React JSX dangerouslySetInnerHTML
      JSXAttribute(path: any) {
        if (path.node.name?.name === 'dangerouslySetInnerHTML') {
          const value = path.node.value
          if (value?.type === 'JSXExpressionContainer') {
            const expr = value.expression
            if (expr?.type === 'ObjectExpression') {
              const htmlProp = expr.properties?.find(
                (p: any) => p.key?.name === '__html' || p.key?.value === '__html'
              )
              if (htmlProp && isDynamicValue(htmlProp.value) && !isSanitizedExpression(htmlProp.value)) {
                const line = path.node.loc?.start.line || 1
                const col = path.node.loc?.start.column || 1
                findings.push({
                  id: `XSS-${counter++}`,
                  ruleId: 'ast/xss-dangerouslysetinnerhtml',
                  ruleName: 'Cross-Site Scripting (React dangerouslySetInnerHTML)',
                  cwe: 'CWE-79',
                  severity: 'HIGH',
                  filePath: ctx.filePath,
                  line,
                  column: col,
                  snippet: extractSnippet(ctx.lines, line),
                  sink: 'dangerouslySetInnerHTML',
                  message: `React component uses 'dangerouslySetInnerHTML' with dynamic content that does not pass through a sanitizer.`,
                  remediation: `Render text as standard JSX child strings or wrap dynamic HTML with 'DOMPurify.sanitize()'.`,
                })
              }
            }
          }
        }
      },
    })

    return findings
  },
}
