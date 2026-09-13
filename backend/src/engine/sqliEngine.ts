import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'

const traverse = (traverseModule as any).default || traverseModule

const SQL_KEYWORDS = [
  'SELECT',
  'INSERT INTO',
  'UPDATE',
  'DELETE FROM',
  'WHERE',
  'FROM',
  'DROP TABLE',
  'UNION SELECT',
  'ORDER BY',
  'GROUP BY',
]

const SQL_SINK_METHODS = new Set([
  '$queryRawUnsafe',
  '$executeRawUnsafe',
  'raw',
  'whereRaw',
  'havingRaw',
  'query',
  'execute',
  'exec',
  'all',
  'get',
  'run',
])

function containsSqlKeywords(text: string): boolean {
  const upper = text.toUpperCase()
  return SQL_KEYWORDS.some(keyword => upper.includes(keyword))
}

function hasSqlConcatenation(node: any): boolean {
  if (!node) return false
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const leftText = node.left.value || node.left.raw || ''
    const rightText = node.right.value || node.right.raw || ''
    if (containsSqlKeywords(String(leftText)) || containsSqlKeywords(String(rightText))) {
      return true
    }
    return hasSqlConcatenation(node.left) || hasSqlConcatenation(node.right)
  }
  return false
}

function isUnsafeTemplateLiteral(node: any): boolean {
  if (!node || node.type !== 'TemplateLiteral') return false
  if (!node.expressions || node.expressions.length === 0) return false

  const rawString = node.quasis.map((q: any) => q.value?.raw || '').join(' ')
  return containsSqlKeywords(rawString)
}

export const sqliEngine: SecurityEngine = {
  name: 'SQL Injection (SQLi) Engine',
  ruleId: 'engine/ast-sqli',
  cwe: 'CWE-89',

  analyze(ast: any, ctx: EngineContext): Finding[] {
    const findings: Finding[] = []
    let counter = 1

    traverse(ast, {
      CallExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (!callee) return

        let methodName = ''
        let objectName = ''

        if (callee.type === 'MemberExpression') {
          methodName = callee.property?.name || callee.property?.value || ''
          objectName = callee.object?.name || callee.object?.property?.name || ''
        } else if (callee.type === 'Identifier') {
          methodName = callee.name
        }

        if (SQL_SINK_METHODS.has(methodName)) {
          const firstArg = args[0]
          if (!firstArg) return

          let isVulnerable = false
          let vulnType = ''

          if (hasSqlConcatenation(firstArg)) {
            isVulnerable = true
            vulnType = 'String concatenation with binary operator (+)'
          } else if (isUnsafeTemplateLiteral(firstArg)) {
            isVulnerable = true
            vulnType = 'Template literal interpolation (${...})'
          } else if (firstArg.type === 'Identifier') {
            const binding = path.scope.getBinding(firstArg.name)
            if (binding && binding.path.isVariableDeclarator()) {
              const init = (binding.path.node as any).init
              if (hasSqlConcatenation(init)) {
                isVulnerable = true
                vulnType = `Variable '${firstArg.name}' declared with SQL string concatenation (+)`
              } else if (isUnsafeTemplateLiteral(init)) {
                isVulnerable = true
                vulnType = `Variable '${firstArg.name}' declared with SQL template literal interpolation (\${...})`
              }
            }
          } else if (
            methodName === '$queryRawUnsafe' ||
            methodName === '$executeRawUnsafe'
          ) {
            if (firstArg.type !== 'StringLiteral') {
              isVulnerable = true
              vulnType = `Explicit unsafe call '${methodName}' with dynamic query parameter`
            }
          }

          if (isVulnerable) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            const sinkName = objectName ? `${objectName}.${methodName}` : methodName

            findings.push({
              id: `SQLI-${counter++}`,
              ruleId: 'ast/sqli-raw-concat',
              ruleName: 'SQL Injection (Raw Query Interpolation)',
              cwe: 'CWE-89',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: sinkName,
              message: `Unsanitized user-controlled query passed to '${sinkName}' via ${vulnType}. Attackers can alter SQL execution logic or extract database records.`,
              remediation: `Use parameterized queries with bind placeholders ($1, $2 or ?) or ORM typed query methods (e.g. prisma.$queryRaw\`...\`, knex query builder).`,
            })
          }
        }
      },
    })

    return findings
  },
}
