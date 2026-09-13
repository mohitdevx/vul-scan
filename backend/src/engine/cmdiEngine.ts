import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'

const traverse = (traverseModule as any).default || traverseModule

const EXEC_METHODS = new Set(['exec', 'execSync'])
const SPAWN_METHODS = new Set(['spawn', 'spawnSync'])

function isDynamicCommandArgument(node: any): boolean {
  if (!node) return false
  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral' || node.type === 'BooleanLiteral') return false
  if (node.type === 'BinaryExpression' && node.operator === '+') return true
  if (node.type === 'TemplateLiteral' && node.expressions && node.expressions.length > 0) return true
  if (node.type === 'Identifier' || node.type === 'MemberExpression' || node.type === 'CallExpression') return true
  return false
}

function hasShellTrueOption(optionsNode: any): boolean {
  if (!optionsNode || optionsNode.type !== 'ObjectExpression') return false
  const shellProp = optionsNode.properties?.find(
    (p: any) =>
      (p.key?.name === 'shell' || p.key?.value === 'shell') &&
      p.value?.type === 'BooleanLiteral' &&
      p.value?.value === true
  )
  return Boolean(shellProp)
}

export const cmdiEngine: SecurityEngine = {
  name: 'Command Injection (CMDi) Engine',
  ruleId: 'engine/ast-cmdi',
  cwe: 'CWE-78',

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

        const isChildProcess =
          objectName === 'child_process' ||
          objectName === 'cp' ||
          objectName === 'shelljs' ||
          objectName === ''

        // 1. exec / execSync
        if (EXEC_METHODS.has(methodName) && isChildProcess) {
          const firstArg = args[0]
          if (firstArg && isDynamicCommandArgument(firstArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            const sinkName = objectName ? `${objectName}.${methodName}` : methodName

            findings.push({
              id: `CMDI-${counter++}`,
              ruleId: 'ast/cmd-injection',
              ruleName: 'Operating System Command Injection',
              cwe: 'CWE-78',
              severity: 'CRITICAL',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: sinkName,
              message: `Dynamic command passed to shell execution sink '${sinkName}'. An attacker can chain shell metacharacters (; | & \` $) to execute arbitrary commands.`,
              remediation: `Use 'child_process.execFile' or 'child_process.spawn' with an explicit array of arguments without invoking a system shell.`,
            })
          }
        }

        // 2. spawn / spawnSync with { shell: true }
        if (SPAWN_METHODS.has(methodName) && isChildProcess) {
          const optionsArg = args.find((a: any) => a?.type === 'ObjectExpression')
          if (hasShellTrueOption(optionsArg)) {
            const firstArg = args[0]
            const secondArg = args[1]
            const hasDynamicArgsArray =
              secondArg?.type === 'ArrayExpression' &&
              secondArg.elements.some((el: any) => isDynamicCommandArgument(el))

            if (isDynamicCommandArgument(firstArg) || hasDynamicArgsArray || secondArg?.type === 'Identifier') {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              const sinkName = objectName ? `${objectName}.${methodName}` : methodName

              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmd-injection-spawn-shell',
                ruleName: 'OS Command Injection via spawn with shell: true',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${sinkName} ({ shell: true })`,
                message: `spawn was invoked with '{ shell: true }' and dynamic arguments, rendering it vulnerable to shell metacharacter injection.`,
                remediation: `Set 'shell: false' (the default) and pass arguments as an array in the second parameter to spawn.`,
              })
            }
          }
        }
      },
    })

    return findings
  },
}
