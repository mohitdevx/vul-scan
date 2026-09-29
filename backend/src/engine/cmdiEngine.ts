import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'
import {
  evaluateStaticString,
  isCmdiSanitizedExpression,
  isSafeNumericOrBooleanCast,
  isCmdiTainted,
  isShellOptionEnabled,
  isInternalBuildOrDevScript,
  isNodeGuardedAgainstCmdi,
} from './astUtils.js'

const traverse = (traverseModule as any).default || traverseModule

// Shell-executing method names that invoke a system shell directly
const SHELL_EXEC_METHODS = new Set([
  'exec',
  'execsync',
  'command',
  'commandsync',
  'run',
  'runsync',
  'get',
  'system',
  'shellexec',
  'runcommand',
  'executecommand',
  'execcommand',
])

// Process spawning methods that execute a binary directly unless shell option is enabled
const SPAWN_METHODS = new Set([
  'spawn',
  'spawnsync',
  'execfile',
  'execfilesync',
  'fork',
  'crossspawn',
  'node',
])

// Known child_process and shell object module identifiers
const PROCESS_MODULE_OBJECTS = new Set([
  'child_process',
  'childprocess',
  'cp',
  'shell',
  'shelljs',
  'execa',
  'crossspawn',
  'cmd',
  'zx',
])

// Known shell binaries that execute shell commands via -c or /c flags
const SHELL_BINARIES = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  '/bin/sh',
  '/bin/bash',
  '/bin/zsh',
  '/usr/bin/env',
])

interface SinkCheckResult {
  isSink: boolean
  sinkName: string
  isDirectShell: boolean
  isSpawn: boolean
  isTaggedTemplate: boolean
}

/**
 * Checks whether a Callee (Identifier, MemberExpression, or TaggedTemplateExpression)
 * represents a Command Execution Sink.
 */
function isCommandExecutionSink(callee: any): SinkCheckResult {
  if (!callee) {
    return { isSink: false, sinkName: '', isDirectShell: false, isSpawn: false, isTaggedTemplate: false }
  }

  // 1. Direct function call: exec(...), execSync(...), spawn(...), runCommand(...)
  if (callee.type === 'Identifier') {
    const name = callee.name.toLowerCase()
    if (SHELL_EXEC_METHODS.has(name)) {
      return { isSink: true, sinkName: callee.name, isDirectShell: true, isSpawn: false, isTaggedTemplate: false }
    }
    if (SPAWN_METHODS.has(name)) {
      return { isSink: true, sinkName: callee.name, isDirectShell: false, isSpawn: true, isTaggedTemplate: false }
    }
    if (name === '$') {
      return { isSink: true, sinkName: '$', isDirectShell: true, isSpawn: false, isTaggedTemplate: true }
    }
  }

  // 2. Member expression: cp.exec, child_process.spawn, shell.exec, execa.command, etc.
  if (callee.type === 'MemberExpression') {
    const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()
    const objName = (callee.object?.name || callee.object?.property?.name || '').toLowerCase()

    const isProcessObj =
      PROCESS_MODULE_OBJECTS.has(objName) ||
      objName.includes('child_process') ||
      objName.includes('process') ||
      objName.includes('shell') ||
      objName.includes('exec')

    // child_process.exec, shell.exec, execa.command, etc.
    if ((isProcessObj || objName === 'cp' || objName === 'child_process' || objName === 'shell') && SHELL_EXEC_METHODS.has(propName)) {
      return { isSink: true, sinkName: `${objName}.${callee.property?.name || propName}`, isDirectShell: true, isSpawn: false, isTaggedTemplate: false }
    }

    // child_process.spawn, cp.execFile, execa.sync, etc.
    if ((isProcessObj || objName === 'cp' || objName === 'child_process' || objName === 'execa') && (SPAWN_METHODS.has(propName) || propName === 'sync')) {
      return { isSink: true, sinkName: `${objName}.${callee.property?.name || propName}`, isDirectShell: false, isSpawn: true, isTaggedTemplate: false }
    }

    // execa(...) direct call or execa.sync(...)
    if (objName === 'execa') {
      return { isSink: true, sinkName: `execa.${callee.property?.name || propName}`, isDirectShell: false, isSpawn: true, isTaggedTemplate: false }
    }
  }

  return { isSink: false, sinkName: '', isDirectShell: false, isSpawn: false, isTaggedTemplate: false }
}

export const cmdiEngine: SecurityEngine = {
  id: 'cmdi',
  name: 'Command Injection (CMDi) Engine',
  ruleId: 'engine/ast-cmdi-advanced',
  cwe: 'CWE-78',
  version: '2.0.0',

  analyze(ast: any, ctx: EngineContext): Finding[] {
    const findings: Finding[] = []
    let counter = 1

    // Determine if file is an internal build tool / maintainer script / test file
    const isBuildScript = isInternalBuildOrDevScript(ctx.filePath)

    // Map of helper wrapper functions for inter-procedural command executions:
    // e.g. function runPing(host) { return exec('ping -c 1 ' + host); }
    const helperFunctionSinks = new Map<string, { paramIndex: number; sinkName: string; line: number }>()

    // Track dynamic command variables mutated via concatenation:
    // e.g. let cmd = "ping "; cmd += req.query.host;
    const taintedVariables = new Map<string, { sourceDesc: string; line: number; column: number }>()

    // Pre-pass 1: Discover inter-procedural helper wrapper functions
    traverse(ast, {
      FunctionDeclaration(path: any) {
        const fnName = path.node.id?.name
        if (!fnName) return

        const params = path.node.params.map((p: any) => p.name)

        path.traverse({
          CallExpression(subPath: any) {
            const callee = subPath.node.callee
            const sinkCheck = isCommandExecutionSink(callee)

            if (sinkCheck.isSink && subPath.node.arguments && subPath.node.arguments.length > 0) {
              const firstArg = subPath.node.arguments[0]
              if (firstArg && firstArg.type === 'Identifier') {
                const paramIdx = params.indexOf(firstArg.name)
                if (paramIdx !== -1) {
                  helperFunctionSinks.set(fnName, {
                    paramIndex: paramIdx,
                    sinkName: sinkCheck.sinkName,
                    line: subPath.node.loc?.start.line || 1,
                  })
                }
              }
            }
          },
        })
      },

      // Pre-pass 2: Track variable concatenation mutations (e.g. cmd += req.query.arg)
      AssignmentExpression(path: any) {
        const { left, right, operator } = path.node
        if (left && left.type === 'Identifier') {
          const varName = left.name
          const isCmdNamed = /cmd|command|script|shell|exec|arg/i.test(varName)

          if (operator === '+=' || operator === '=') {
            const taint = isCmdiTainted(right, path.scope, isBuildScript)
            if (taint.tainted) {
              if (isCmdNamed) {
                taintedVariables.set(varName, {
                  sourceDesc: taint.sourceDesc || 'Dynamic string concatenation',
                  line: left.loc?.start.line || 1,
                  column: left.loc?.start.column || 1,
                })
              }
            }
          }
        }
      },
    })

    // Main Traversal: Detect Command Injection across child_process, execa, shelljs, and custom wrappers
    traverse(ast, {
      // =========================================================================
      // CATEGORY 1: Direct CallExpressions (exec, execSync, spawn, execFile, helper calls)
      // =========================================================================
      CallExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (!callee) return
        const scope = path.scope

        // 1. Inter-procedural helper call: runPing(req.body.host)
        if (callee.type === 'Identifier' && helperFunctionSinks.has(callee.name)) {
          const helperInfo = helperFunctionSinks.get(callee.name)!
          const targetArg = args[helperInfo.paramIndex]

          if (targetArg) {
            const taint = isCmdiTainted(targetArg, scope, isBuildScript)
            if (taint.tainted) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-interprocedural-helper',
                ruleName: 'Command Injection via Tainted Helper Function Delegation',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${callee.name} -> ${helperInfo.sinkName}`,
                message: `Untrusted user input passed to command execution helper '${callee.name}' which triggers system shell sink '${helperInfo.sinkName}' on line ${helperInfo.line}${
                  taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                }.`,
                remediation: `Avoid passing dynamic arguments into shell execution wrappers. Use child_process.spawn() or child_process.execFile() with strict argument arrays and { shell: false }.`,
              })
              return
            }
          }
        }

        // 2. Direct Command Execution Sinks
        const sinkCheck = isCommandExecutionSink(callee)
        if (!sinkCheck.isSink || !args || args.length === 0) {
          return
        }

        const firstArg = args[0]
        if (!firstArg) return

        // If this call is inside a registered helper function forwarding its parameter, skip direct flag to avoid duplicate counting
        if (firstArg.type === 'Identifier') {
          const enclosingFn = path.findParent((p: any) => p.isFunctionDeclaration())
          const fnName = enclosingFn?.node?.id?.name
          if (fnName && helperFunctionSinks.has(fnName)) {
            const helperInfo = helperFunctionSinks.get(fnName)!
            const params = enclosingFn.node.params.map((p: any) => p.name)
            if (params.indexOf(firstArg.name) === helperInfo.paramIndex) {
              return
            }
          }
        }

        const line = callee.loc?.start.line || 1
        const col = callee.loc?.start.column || 1

        // Check if first argument is a tracked variable that was assembled dangerously
        if (firstArg.type === 'Identifier' && taintedVariables.has(firstArg.name)) {
          const varInfo = taintedVariables.get(firstArg.name)!
          findings.push({
            id: `CMDI-${counter++}`,
            ruleId: 'ast/cmdi-stored-variable',
            ruleName: 'Command Injection via Dynamically Assembled Command Variable',
            cwe: 'CWE-78',
            severity: 'CRITICAL',
            filePath: ctx.filePath,
            line,
            column: col,
            snippet: extractSnippet(ctx.lines, line),
            sink: sinkCheck.sinkName,
            message: `Command execution sink '${sinkCheck.sinkName}' invoked with dynamically assembled command variable '${firstArg.name}' constructed via ${varInfo.sourceDesc} on line ${varInfo.line}.`,
            remediation: `Do not concatenate untrusted strings into system commands. Use child_process.spawn() or child_process.execFile() passing command arguments as separate array elements with { shell: false }.`,
          })
          return
        }

        // =====================================================================
        // CASE A: Direct Shell Execution Sinks (exec, execSync, shell.exec, etc.)
        // =====================================================================
        if (sinkCheck.isDirectShell) {
          // Template literal check: exec(`ping ${req.query.host}`)
          if (firstArg.type === 'TemplateLiteral') {
            const hasTaintedExpr = firstArg.expressions.some((expr: any) => {
              if (
                isSafeNumericOrBooleanCast(expr, scope) ||
                isCmdiSanitizedExpression(expr, scope) ||
                isNodeGuardedAgainstCmdi(expr, path)
              ) {
                return false
              }
              return isCmdiTainted(expr, scope, isBuildScript).tainted
            })

            if (hasTaintedExpr) {
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-template-literal',
                ruleName: 'Command Injection via Template Literal Interpolation',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: sinkCheck.sinkName,
                message: `Unsanitized user-controlled value interpolated into command string passed to '${sinkCheck.sinkName}'.`,
                remediation: `Replace shell execution '${sinkCheck.sinkName}' with child_process.execFile() or child_process.spawn() using an argument array, or sanitize dynamic parameters using 'shell-quote'.`,
              })
            }
            return
          }

          // String concatenation or tainted identifier: exec('ping ' + req.body.host)
          if (!isNodeGuardedAgainstCmdi(firstArg, path) && !isCmdiSanitizedExpression(firstArg, scope)) {
            const taint = isCmdiTainted(firstArg, scope, isBuildScript)
            if (taint.tainted) {
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-shell-execution',
                ruleName: 'Command Injection in System Shell Execution',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: sinkCheck.sinkName,
                message: `Dynamic, untrusted input passed to '${sinkCheck.sinkName}' without shell escaping or argument separation${
                  taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                }.`,
                remediation: `Use child_process.spawn() or child_process.execFile() with an argument array and { shell: false }, ensuring input cannot break out of argument boundaries.`,
              })
              return
            }
          }
        }

        // =====================================================================
        // CASE B: Process Spawning Sinks (spawn, spawnSync, execFile, execa)
        // =====================================================================
        if (sinkCheck.isSpawn) {
          const secondArg = args.length > 1 ? args[1] : null
          const thirdArg = args.length > 2 ? args[2] : null

          // Determine which argument is the options object
          let optionsArg: any = null
          if (secondArg && secondArg.type === 'ObjectExpression') {
            optionsArg = secondArg
          } else if (thirdArg && thirdArg.type === 'ObjectExpression') {
            optionsArg = thirdArg
          } else if (args.length > 1 && args[args.length - 1]?.type === 'Identifier') {
            optionsArg = args[args.length - 1]
          }

          const hasShellOption = isShellOptionEnabled(optionsArg, scope)

          // Subcase B1: The executable binary itself is dynamic / tainted
          if (!isNodeGuardedAgainstCmdi(firstArg, path)) {
            const binaryTaint = isCmdiTainted(firstArg, scope, isBuildScript)
            if (binaryTaint.tainted) {
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-dynamic-executable',
                ruleName: 'Command Hijacking via Dynamic Executable Path',
                cwe: 'CWE-78',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: sinkCheck.sinkName,
                message: `The executable binary path passed to '${sinkCheck.sinkName}' is controlled by dynamic user input${
                  binaryTaint.sourceDesc ? ` (${binaryTaint.sourceDesc})` : ''
                }.`,
                remediation: `Hardcode the executable binary path or validate against a strict whitelist of allowed executables before invoking '${sinkCheck.sinkName}'.`,
              })
              return
            }
          }

          // Subcase B2: If { shell: true } is enabled, ANY tainted argument in the args array is vulnerable
          if (hasShellOption && secondArg) {
            let hasTaintedShellArg = false
            let taintedArgDesc = ''

            if (secondArg.type === 'ArrayExpression') {
              for (const elem of secondArg.elements) {
                if (elem) {
                  if (
                    isNodeGuardedAgainstCmdi(elem, path) ||
                    isCmdiSanitizedExpression(elem, scope) ||
                    isSafeNumericOrBooleanCast(elem, scope)
                  ) {
                    continue
                  }
                  const taint = isCmdiTainted(elem, scope, isBuildScript)
                  if (taint.tainted) {
                    hasTaintedShellArg = true
                    taintedArgDesc = taint.sourceDesc || 'Dynamic argument'
                    break
                  }
                }
              }
            } else {
              if (
                !isNodeGuardedAgainstCmdi(secondArg, path) &&
                !isCmdiSanitizedExpression(secondArg, scope) &&
                !isSafeNumericOrBooleanCast(secondArg, scope)
              ) {
                const taint = isCmdiTainted(secondArg, scope, isBuildScript)
                if (taint.tainted) {
                  hasTaintedShellArg = true
                  taintedArgDesc = taint.sourceDesc || 'Dynamic argument'
                }
              }
            }

            if (hasTaintedShellArg) {
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-spawn-shell-option',
                ruleName: 'Command Injection via spawn/execFile with shell: true',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: sinkCheck.sinkName,
                message: `'${sinkCheck.sinkName}' was invoked with { shell: true } and untrusted arguments (${taintedArgDesc}), enabling shell metacharacter injection.`,
                remediation: `Disable the { shell: true } option in '${sinkCheck.sinkName}' and pass arguments directly to the binary as an array.`,
              })
              return
            }
          }

          // Subcase B3: Spawning shell binary (sh, bash, cmd.exe) with -c / /c and tainted command string
          const staticBinary = evaluateStaticString(firstArg, scope)
          if (staticBinary && SHELL_BINARIES.has(staticBinary.toLowerCase()) && secondArg && secondArg.type === 'ArrayExpression') {
            const elements = secondArg.elements
            // Look for -c, /c, or /C flag followed by tainted argument
            for (let i = 0; i < elements.length; i++) {
              const el = elements[i]
              const staticFlag = evaluateStaticString(el, scope)
              if (staticFlag === '-c' || staticFlag === '/c' || staticFlag === '/C') {
                const nextEl = elements[i + 1]
                if (nextEl) {
                  const taint = isCmdiTainted(nextEl, scope, isBuildScript)
                  if (taint.tainted) {
                    findings.push({
                      id: `CMDI-${counter++}`,
                      ruleId: 'ast/cmdi-shell-execution',
                      ruleName: 'Command Injection via Shell Invocation with -c Flag',
                      cwe: 'CWE-78',
                      severity: 'CRITICAL',
                      filePath: ctx.filePath,
                      line,
                      column: col,
                      snippet: extractSnippet(ctx.lines, line),
                      sink: `${sinkCheck.sinkName} (${staticBinary} -c)`,
                      message: `Untrusted command string passed to '${staticBinary} -c' via '${sinkCheck.sinkName}'${
                        taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                      }.`,
                      remediation: `Directly invoke the target binary instead of spawning a subshell with '${staticBinary} -c'. Pass arguments via array.`,
                    })
                    return
                  }
                }
              }
            }
          }
        }
      },

      // =========================================================================
      // CATEGORY 2: TaggedTemplateExpression (e.g. $`ping ${req.query.host}`)
      // =========================================================================
      TaggedTemplateExpression(path: any) {
        const { tag, quasi } = path.node
        if (!tag || !quasi) return
        const scope = path.scope

        const tagName = tag.type === 'Identifier' ? tag.name : tag.property?.name || ''
        if (tagName === '$' || tagName === 'exec' || tagName === 'sh') {
          // Check if any expression in quasi is tainted
          for (const expr of quasi.expressions || []) {
            if (isSafeNumericOrBooleanCast(expr, scope) || isCmdiSanitizedExpression(expr, scope)) {
              continue
            }
            const taint = isCmdiTainted(expr, scope, isBuildScript)
            if (taint.tainted) {
              const line = tag.loc?.start.line || 1
              const col = tag.loc?.start.column || 1
              findings.push({
                id: `CMDI-${counter++}`,
                ruleId: 'ast/cmdi-template-tag',
                ruleName: 'Command Injection in Shell Tagged Template Expression',
                cwe: 'CWE-78',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${tagName}\`...\``,
                message: `Unsanitized user-controlled value interpolated into shell template tag '${tagName}\`...\`'${
                  taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                }.`,
                remediation: `Ensure all arguments passed into the template tag are properly quoted or validated with a strict allowlist.`,
              })
              return
            }
          }
        }
      },
    })

    return findings
  },
}
