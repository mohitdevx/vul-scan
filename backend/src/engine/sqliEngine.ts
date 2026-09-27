import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'
import {
  evaluateStaticString,
  isSqlSanitizedExpression,
  isSafeNumericOrBooleanCast,
  isSqlTainted,
  isHttpSource,
  isDatabaseSource,
} from './astUtils.js'

const traverse = (traverseModule as any).default || traverseModule

// Core database execution method names across major Node.js SQL libraries
const DB_QUERY_METHODS = new Set([
  'query',
  'execute',
  'exec',
  'run',
  'all',
  'get',
  'each',
  'prepare',
  'any',
  'one',
  'oneornone',
  'many',
  'none',
  'multi',
  'queryrawunsafe',
  'executerawunsafe',
  '$queryrawunsafe',
  '$executerawunsafe',
])

// ORM Raw expression constructors and query builder raw methods
const ORM_RAW_METHODS = new Set([
  'raw',
  'whereraw',
  'havingraw',
  'joinraw',
  'groupbyraw',
  'orderbyraw',
  'literal',
  'unsafe',
])

// Known database client / pool / ORM object identifiers
const DB_OBJECT_NAMES = new Set([
  'db',
  'database',
  'pool',
  'client',
  'conn',
  'connection',
  'sql',
  'mysql',
  'mysql2',
  'postgres',
  'pg',
  'sqlite',
  'sqlite3',
  'prisma',
  'knex',
  'sequelize',
  'qb',
  'builder',
  'querybuilder',
  'datasource',
  'manager',
  'entitymanager',
  'repository',
  'repo',
  'em',
  'session',
])

// TypeORM query builder clause methods that accept raw SQL conditions
const TYPEORM_CLAUSE_METHODS = new Set([
  'where',
  'andwhere',
  'orwhere',
  'having',
  'andhaving',
  'orhaving',
  'orderby',
  'addorderby',
])

// SQL keywords to confirm SQL context when generic identifiers are used
const SQL_KEYWORDS_REGEX = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|TABLE|JOIN|UNION|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|EXEC|EXECUTE|TRUNCATE|CALL|PRAGMA|SHOW|DESCRIBE)\b/i

/**
 * Checks if a string contains SQL statement keywords
 */
function containsSqlKeywords(text: string): boolean {
  return SQL_KEYWORDS_REGEX.test(text)
}

/**
 * Checks if a MemberExpression represents a database method invocation
 */
function isDatabaseMemberExpression(callee: any): { isDb: boolean; sinkName: string; isOrmRaw: boolean; isTypeOrmClause: boolean } {
  if (!callee || callee.type !== 'MemberExpression') {
    return { isDb: false, sinkName: '', isOrmRaw: false, isTypeOrmClause: false }
  }

  const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()
  const objName = (callee.object?.name || callee.object?.property?.name || '').toLowerCase()

  const isDbObject = DB_OBJECT_NAMES.has(objName) || objName.includes('db') || objName.includes('sql') || objName.includes('pool') || objName.includes('client') || objName.includes('conn')
  const isQueryMethod = DB_QUERY_METHODS.has(propName)
  const isOrmRaw = ORM_RAW_METHODS.has(propName)
  const isTypeOrmClause = TYPEORM_CLAUSE_METHODS.has(propName)

  // Direct database sink: db.query, pool.execute, prisma.$queryRawUnsafe, etc.
  if (isDbObject && (isQueryMethod || isOrmRaw)) {
    return { isDb: true, sinkName: `${objName}.${callee.property?.name || propName}`, isOrmRaw, isTypeOrmClause: false }
  }

  // Explicit unsafe ORM methods regardless of object name: $queryRawUnsafe, $executeRawUnsafe, whereRaw, etc.
  if (propName.startsWith('$queryrawunsafe') || propName.startsWith('$executerawunsafe') || propName.endsWith('raw') || propName === 'literal') {
    return { isDb: true, sinkName: `${objName || 'orm'}.${callee.property?.name || propName}`, isOrmRaw: true, isTypeOrmClause: false }
  }

  // Generic query method: client.query, connection.query, etc.
  if (isQueryMethod && (isDbObject || objName === 'client' || objName === 'conn' || objName === 'connection' || objName === 'pool')) {
    return { isDb: true, sinkName: `${objName}.${callee.property?.name || propName}`, isOrmRaw: false, isTypeOrmClause: false }
  }

  // TypeORM query builder clauses: qb.where, repository.createQueryBuilder().where(...)
  if (isTypeOrmClause && (isDbObject || objName.includes('qb') || objName.includes('builder') || objName.includes('query'))) {
    return { isDb: true, sinkName: `${objName}.${callee.property?.name || propName}`, isOrmRaw: false, isTypeOrmClause: true }
  }

  return { isDb: false, sinkName: '', isOrmRaw: false, isTypeOrmClause: false }
}

export const sqliEngine: SecurityEngine = {
  id: 'sqli',
  name: 'SQL Injection (SQLi) Engine',
  ruleId: 'engine/ast-sqli-advanced',
  cwe: 'CWE-89',
  version: '2.0.0',

  analyze(ast: any, ctx: EngineContext): Finding[] {
    const findings: Finding[] = []
    let counter = 1

    // Map of helper wrapper functions for inter-procedural SQL queries:
    // e.g. function executeQuery(sql) { return db.query(sql); }
    const helperFunctionSinks = new Map<string, { paramIndex: number; sinkName: string; line: number }>()

    // Track dynamic SQL query variables mutated via concatenation:
    // e.g. let sql = "SELECT * FROM users"; sql += " WHERE id = " + req.query.id;
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
            const dbCheck = isDatabaseMemberExpression(callee)

            if (dbCheck.isDb && subPath.node.arguments && subPath.node.arguments.length > 0) {
              const firstArg = subPath.node.arguments[0]
              if (firstArg && firstArg.type === 'Identifier') {
                const paramIdx = params.indexOf(firstArg.name)
                if (paramIdx !== -1) {
                  helperFunctionSinks.set(fnName, {
                    paramIndex: paramIdx,
                    sinkName: dbCheck.sinkName,
                    line: subPath.node.loc?.start.line || 1,
                  })
                }
              }
            }
          },
        })
      },

      // Pre-pass 2: Track variable concatenation mutations (e.g. sql += " WHERE id = " + input)
      AssignmentExpression(path: any) {
        const { left, right, operator } = path.node
        if (left && left.type === 'Identifier') {
          const varName = left.name
          const isSqlNamed = /sql|query|stmt|command/i.test(varName)

          if (operator === '+=' || operator === '=') {
            const taint = isSqlTainted(right, path.scope)
            if (taint.tainted) {
              // Check if right side looks like SQL syntax or variable is explicitly SQL-named
              const staticPortion = ctx.lines[left.loc?.start.line - 1] || ''
              if (isSqlNamed || containsSqlKeywords(staticPortion)) {
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

    // Main Traversal: Detect SQL Injection across Database Drivers, ORMs, and Query Builders
    traverse(ast, {
      // =========================================================================
      // CATEGORY 1: Database Method Calls (db.query, pool.execute, prisma.$queryRawUnsafe, knex.raw, etc.)
      // =========================================================================
      CallExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (!callee) return
        const scope = path.scope

        // 1. Inter-procedural helper call: executeQuery("SELECT * FROM users WHERE name = '" + req.query.name + "'")
        if (callee.type === 'Identifier' && helperFunctionSinks.has(callee.name)) {
          const helperInfo = helperFunctionSinks.get(callee.name)!
          const targetArg = args[helperInfo.paramIndex]

          if (targetArg) {
            const taint = isSqlTainted(targetArg, scope)
            if (taint.tainted) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `SQLI-${counter++}`,
                ruleId: 'ast/sqli-interprocedural-helper',
                ruleName: 'SQL Injection via Tainted Query Helper Delegation',
                cwe: 'CWE-89',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${callee.name} -> ${helperInfo.sinkName}`,
                message: `Unescaped dynamic query passed to helper function '${callee.name}' which executes database sink '${helperInfo.sinkName}' on line ${helperInfo.line}${
                  taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                }.`,
                remediation: `Refactor '${callee.name}' to accept parameterized query placeholders and an array of bound values instead of raw concatenated SQL strings.`,
              })
              return
            }
          }
        }

        // 2. Direct Database & ORM Sink Calls
        const dbCheck = isDatabaseMemberExpression(callee)
        if (dbCheck.isDb && args && args.length > 0) {
          const firstArg = args[0]
          if (!firstArg) return

          // If this call is inside a registered helper function forwarding its parameter, skip direct flag to avoid double counting
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


          // For TypeORM .where(sql, params), if 2nd argument is provided (parameter bindings object), it is safe!
          if (dbCheck.isTypeOrmClause && args.length >= 2) {
            const secondArg = args[1]
            if (secondArg && (secondArg.type === 'ObjectExpression' || secondArg.type === 'ArrayExpression')) {
              return
            }
          }

          // Check if first argument is a tracked variable that was assembled dangerously
          if (firstArg.type === 'Identifier' && taintedVariables.has(firstArg.name)) {
            const varInfo = taintedVariables.get(firstArg.name)!
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `SQLI-${counter++}`,
              ruleId: 'ast/sqli-stored-variable',
              ruleName: 'SQL Injection via Dynamically Assembled Query Variable',
              cwe: 'CWE-89',
              severity: 'CRITICAL',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: dbCheck.sinkName,
              message: `Database sink '${dbCheck.sinkName}' executed with dynamically assembled query variable '${firstArg.name}' constructed via ${varInfo.sourceDesc} on line ${varInfo.line}.`,
              remediation: `Use parameterized queries with prepared statement placeholders ($1, ?, or :param) and pass parameters via the query execution options array.`,
            })
            return
          }

          // Check if first argument is tainted
          const taint = isSqlTainted(firstArg, scope)
          if (taint.tainted) {
            const line = firstArg.loc?.start.line || callee.loc?.start.line || 1
            const col = firstArg.loc?.start.column || callee.loc?.start.column || 1

            let ruleId = 'ast/sqli-raw-concatenation'
            let ruleName = `SQL Injection (${dbCheck.sinkName})`

            if (firstArg.type === 'TemplateLiteral') {
              ruleId = 'ast/sqli-template-literal'
              ruleName = `SQL Injection via Template Literal (${dbCheck.sinkName})`
            } else if (dbCheck.isOrmRaw) {
              ruleId = 'ast/sqli-orm-unsafe-call'
              ruleName = `SQL Injection via Unsafe ORM Method (${dbCheck.sinkName})`
            } else if (dbCheck.isTypeOrmClause) {
              ruleId = 'ast/sqli-typeorm-where'
              ruleName = `SQL Injection via Unparameterized QueryBuilder Clause (${dbCheck.sinkName})`
            }

            findings.push({
              id: `SQLI-${counter++}`,
              ruleId,
              ruleName,
              cwe: 'CWE-89',
              severity: 'CRITICAL',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: dbCheck.sinkName,
              message: `Unparameterized dynamic SQL query executed in '${dbCheck.sinkName}'${
                taint.sourceDesc ? ` via ${taint.sourceDesc}` : ''
              }. Allows arbitrary SQL command manipulation, data exfiltration, or authentication bypass.`,
              remediation: `Replace dynamic string concatenation with parameterized placeholders (e.g. $1, ?, or :value) and supply parameters in a separate bindings array/object.`,
            })
            return
          }
        }

        // 3. Nested Raw Call inside query: e.g. prisma.$queryRaw(Prisma.raw(`SELECT * FROM users WHERE id = '${id}'`))
        if (
          callee.type === 'MemberExpression' &&
          (callee.property?.name === '$queryRaw' || callee.property?.name === '$executeRaw' || callee.property?.name === 'query')
        ) {
          if (args.length > 0 && args[0]?.type === 'CallExpression') {
            const innerCall = args[0]
            const innerCallee = innerCall.callee
            const innerName = innerCallee?.property?.name || innerCallee?.name
            if (innerName === 'raw' && innerCall.arguments && innerCall.arguments.length > 0) {
              const rawArg = innerCall.arguments[0]
              const taint = isSqlTainted(rawArg, scope)
              if (taint.tainted) {
                const line = rawArg.loc?.start.line || callee.loc?.start.line || 1
                const col = rawArg.loc?.start.column || callee.loc?.start.column || 1
                findings.push({
                  id: `SQLI-${counter++}`,
                  ruleId: 'ast/sqli-orm-unsafe-call',
                  ruleName: 'SQL Injection via Prisma.raw() Dynamic Construction',
                  cwe: 'CWE-89',
                  severity: 'CRITICAL',
                  filePath: ctx.filePath,
                  line,
                  column: col,
                  snippet: extractSnippet(ctx.lines, line),
                  sink: `${callee.object?.name || 'prisma'}.${callee.property.name}(Prisma.raw(...))`,
                  message: `Dynamic untrusted value wrapped in 'Prisma.raw()' and passed to '${callee.property.name}' disables Prisma's built-in query parameterization.`,
                  remediation: `Use tagged template literals directly: prisma.$queryRaw\`SELECT * FROM table WHERE col = \${value}\` without Prisma.raw().`,
                })
              }
            }
          }
        }
      },

      // =========================================================================
      // CATEGORY 2: Tagged Template Literal Sinks (e.g. postgres.unsafe`...`, sql.unsafe`...`, Prisma.raw`...`)
      // =========================================================================
      TaggedTemplateExpression(path: any) {
        const { tag, quasi } = path.node
        if (!tag || !quasi) return

        const tagName = tag.type === 'Identifier' ? tag.name : tag.property?.name || ''
        const tagObjName = (tag.object?.name || '').toLowerCase()

        // Note: Standard tagged template literals like prisma.$queryRaw`...` or postgres`...` are SAFE parameterized!
        // Only explicit unsafe tags like postgres.unsafe`...`, sql.unsafe`...`, or Prisma.raw`...` are vulnerable!
        const isUnsafeTag =
          tagName === 'unsafe' ||
          (tagName === 'raw' && (tagObjName === 'prisma' || tagObjName === 'knex')) ||
          tagName === '$queryRawUnsafe' ||
          tagName === '$executeRawUnsafe'

        if (isUnsafeTag && quasi.expressions && quasi.expressions.length > 0) {
          for (const expr of quasi.expressions) {
            // If safe numeric cast, skip
            if (isSafeNumericOrBooleanCast(expr, path.scope) || isSqlSanitizedExpression(expr)) {
              continue
            }

            const taint = isSqlTainted(expr, path.scope)
            if (taint.tainted) {
              const line = tag.loc?.start.line || 1
              const col = tag.loc?.start.column || 1
              findings.push({
                id: `SQLI-${counter++}`,
                ruleId: 'ast/sqli-unsafe-tagged-template',
                ruleName: `SQL Injection via Unsafe Tagged Template (${tagObjName ? `${tagObjName}.` : ''}${tagName})`,
                cwe: 'CWE-89',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${tagObjName ? `${tagObjName}.` : ''}${tagName}\`...\``,
                message: `Dynamic untrusted interpolation in unsafe tagged template '${tagName}\`...\`' bypasses database driver parameterization.`,
                remediation: `Use standard parameterized tagged template queries without the '.unsafe' modifier.`,
              })
              break
            }
          }
        }
      },
    })

    return findings
  },
}
