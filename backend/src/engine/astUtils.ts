/**
 * AST Utilities for Security Analysis
 * Provides constant folding, scope binding resolution, source identification,
 * sanitizer detection, and taint flow tracing.
 */

// Known sanitizer method names and packages
export const KNOWN_SANITIZERS = new Set([
  'sanitize',
  'dompurify',
  'sanitizehtml',
  'escapehtml',
  'escape',
  'encodeuricomponent',
  'encodeuri',
  'clean',
  'he.encode',
  'validator.escape',
  'lodash.escape',
  'striptags',
  'xss',
  'filterxss',
  'purify',
])

// Known SQL sanitizers and escape methods
export const KNOWN_SQL_SANITIZERS = new Set([
  'escape',
  'escapeliteral',
  'escapeidentifier',
  'sqlescape',
  'clean',
  'sanitize',
  'sqlstring',
  'mysql.escape',
  'pool.escape',
  'connection.escape',
  'db.escape',
  'validator.escape',
])

// Known Command Injection sanitizers, quoting, and shell escaping methods
export const KNOWN_CMDI_SANITIZERS = new Set([
  'quote',
  'shellquote',
  'shellescape',
  'escapeshell',
  'escapeshellarg',
  'escapeshellcmd',
  'clean',
  'sanitize',
  'sanitizecommand',
  'sanitizearg',
  'sanitizefilename',
  'shell-quote.quote',
  'shell-escape',
])


// HTTP Source indicators (Express, Fastify, Koa, Next.js, Node http)
export const HTTP_SOURCE_PROPERTIES = new Set([
  'query',
  'params',
  'param',
  'body',
  'headers',
  'header',
  'cookies',
  'cookie',
  'url',
  'originalurl',
  'searchparams',
  'rawbody',
])

// Browser DOM Source indicators
export const DOM_SOURCE_PROPERTIES = new Set([
  'search',
  'hash',
  'href',
  'pathname',
  'referrer',
  'name',
  'cookie',
  'data', // e.data in postMessage
  'hashchange',
  'popstate',
])

// Persistent / Database Source identifiers
export const DB_SOURCE_IDENTIFIERS = new Set([
  'db',
  'prisma',
  'knex',
  'sequelize',
  'mongoose',
  'user',
  'post',
  'comment',
  'order',
  'account',
  'record',
  'result',
  'rows',
  'row',
  'doc',
  'document',
  'item',
  'items',
])

/**
 * Constant Folding: Evaluates an AST expression to a static string if possible.
 * Resolves:
 * - String literals: 'foo'
 * - Binary concatenations: 'inner' + 'HTML'
 * - Array joins: ['inner', 'HTML'].join('')
 * - Identifiers bound to constants in scope: const parts = ['inner', 'HTML']; parts.join('')
 */
export function evaluateStaticString(node: any, scope?: any, depth = 0): string | null {
  if (!node || depth > 10) return null

  if (node.type === 'StringLiteral') {
    return node.value
  }

  if (node.type === 'NumericLiteral' || node.type === 'BooleanLiteral') {
    return String(node.value)
  }

  // Template literal with static quasis and no dynamic expressions
  if (node.type === 'TemplateLiteral') {
    if (!node.expressions || node.expressions.length === 0) {
      return node.quasis.map((q: any) => q.value.raw).join('')
    }
    // If all expressions can be evaluated statically
    let combined = ''
    for (let i = 0; i < node.quasis.length; i++) {
      combined += node.quasis[i].value.raw
      if (i < node.expressions.length) {
        const exprVal = evaluateStaticString(node.expressions[i], scope, depth + 1)
        if (exprVal === null) return null
        combined += exprVal
      }
    }
    return combined
  }

  // Binary expression: "inner" + "HTML"
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = evaluateStaticString(node.left, scope, depth + 1)
    const right = evaluateStaticString(node.right, scope, depth + 1)
    if (left !== null && right !== null) {
      return left + right
    }
    return null
  }

  // Method call: .join('')
  if (node.type === 'CallExpression') {
    const callee = node.callee
    if (callee && callee.type === 'MemberExpression') {
      const methodName = callee.property?.name || callee.property?.value
      if (methodName === 'join') {
        const sep = node.arguments[0]?.type === 'StringLiteral' ? node.arguments[0].value : ','
        // Evaluate the array object
        const arrElements = resolveArrayElements(callee.object, scope, depth + 1)
        if (arrElements) {
          const stringElements: string[] = []
          for (const el of arrElements) {
            const str = evaluateStaticString(el, scope, depth + 1)
            if (str === null) return null
            stringElements.push(str)
          }
          return stringElements.join(sep)
        }
      }
    }
    return null
  }

  // Identifier lookup in scope
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return evaluateStaticString(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return null
}

/**
 * Resolves an AST node to an array of element nodes if it is an ArrayExpression
 * or an identifier bound to an ArrayExpression in scope.
 */
export function resolveArrayElements(node: any, scope?: any, depth = 0): any[] | null {
  if (!node || depth > 10) return null

  if (node.type === 'ArrayExpression') {
    return node.elements
  }

  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init && init.type === 'ArrayExpression') {
        return init.elements
      }
    }
  }

  return null
}

/**
 * Checks if an expression is wrapped in a known sanitizer call
 */
export function isSanitizedExpression(node: any): boolean {
  if (!node) return false

  if (node.type === 'CallExpression') {
    const callee = node.callee

    // e.g. DOMPurify.sanitize(input), validator.escape(input)
    if (callee.type === 'MemberExpression') {
      const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()
      const objName = (callee.object?.name || '').toLowerCase()

      if (
        Array.from(KNOWN_SANITIZERS).some(s => propName.includes(s) || objName.includes(s)) ||
        propName.includes('sanitize') ||
        propName.includes('escape') ||
        propName.includes('purify') ||
        propName.includes('clean') ||
        propName.includes('filter') ||
        propName.includes('safe') ||
        (propName.includes('process') && propName.includes('html')) ||
        (propName.includes('render') && propName.includes('html'))
      ) {
        return true
      }
    }

    // e.g. sanitize(input), escapeHtml(input), getProcessedHtml(input)
    if (callee.type === 'Identifier') {
      const name = callee.name.toLowerCase()
      if (
        Array.from(KNOWN_SANITIZERS).some(s => name.includes(s)) ||
        name.includes('sanitize') ||
        name.includes('escape') ||
        name.includes('purify') ||
        name.includes('clean') ||
        name.includes('filter') ||
        name.includes('safe') ||
        (name.includes('process') && name.includes('html')) ||
        (name.includes('render') && name.includes('html'))
      ) {
        return true
      }
    }
  }

  return false
}

/**
 * Checks if an expression is explicitly a string value.
 * Used to avoid false positives on timer functions (setTimeout/setInterval) when
 * a function callback reference (e.g. resolve, res, onDismiss, cb) is passed instead of code string.
 */
export function isExplicitStringExpression(node: any, scope?: any, depth = 0): boolean {
  if (!node || depth > 8) return false

  if (node.type === 'StringLiteral' || node.type === 'TemplateLiteral') {
    return true
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isExplicitStringExpression(node.left, scope, depth + 1) || isExplicitStringExpression(node.right, scope, depth + 1)
  }

  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      // If it's a function parameter (e.g. resolve, onDismiss, cb, res), it is NOT a string!
      if (binding.kind === 'param') {
        return false
      }
      const init = binding.path.node.init
      if (init) {
        return isExplicitStringExpression(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return false
}

/**
 * Determines if a node represents an untrusted HTTP request source
 * e.g. req.query, req.params, req.body, req.headers, req.cookies, etc.
 */
export function isHttpSource(node: any, scope?: any, depth = 0): { isSource: boolean; detail?: string } {
  if (!node || depth > 8) return { isSource: false }

  if (node.type === 'MemberExpression') {
    const propName = (node.property?.name || node.property?.value || '').toLowerCase()
    const obj = node.object

    // Direct match: req.query.foo or req.query
    if (HTTP_SOURCE_PROPERTIES.has(propName)) {
      return { isSource: true, detail: `HTTP input source 'req.${propName}'` }
    }

    // Nested match: req.query.username -> obj is req.query
    const parentCheck = isHttpSource(obj, scope, depth + 1)
    if (parentCheck.isSource) {
      return { isSource: true, detail: `${parentCheck.detail}.${propName}` }
    }
  }

  if (node.type === 'LogicalExpression') {
    const left = isHttpSource(node.left, scope, depth + 1)
    if (left.isSource) return left
    const right = isHttpSource(node.right, scope, depth + 1)
    if (right.isSource) return right
  }

  if (node.type === 'ConditionalExpression') {
    const c = isHttpSource(node.consequent, scope, depth + 1)
    if (c.isSource) return c
    const a = isHttpSource(node.alternate, scope, depth + 1)
    if (a.isSource) return a
  }

  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isHttpSource(node.expression, scope, depth + 1)
  }

  // Identifier lookup backwards in scope
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isHttpSource(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return { isSource: false }
}

/**
 * Determines if a node represents a browser DOM Source
 * e.g. location.search, location.hash, document.referrer, window.name, document.cookie, etc.
 */
export function isDomSource(node: any, scope?: any, depth = 0): { isSource: boolean; detail?: string } {
  if (!node || depth > 8) return { isSource: false }

  if (node.type === 'MemberExpression') {
    const propName = (node.property?.name || node.property?.value || '').toLowerCase()
    const obj = node.object

    if (DOM_SOURCE_PROPERTIES.has(propName)) {
      const objName = (obj?.name || '').toLowerCase()
      if (objName === 'location' || objName === 'document' || objName === 'window' || objName === 'e' || objName === 'event') {
        return { isSource: true, detail: `Browser DOM source '${objName}.${propName}'` }
      }
      return { isSource: true, detail: `DOM source property '${propName}'` }
    }

    const parentCheck = isDomSource(obj, scope, depth + 1)
    if (parentCheck.isSource) {
      return { isSource: true, detail: parentCheck.detail }
    }
  }

  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isDomSource(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return { isSource: false }
}

/**
 * Determines if a node represents a Database or Persistent source
 * e.g. user.bio, post.content, result.rows, record.description
 */
export function isDatabaseSource(node: any, scope?: any, depth = 0): { isSource: boolean; detail?: string } {
  if (!node || depth > 8) return { isSource: false }

  if (node.type === 'MemberExpression') {
    const objName = (node.object?.name || '').toLowerCase()
    if (DB_SOURCE_IDENTIFIERS.has(objName)) {
      const propName = node.property?.name || node.property?.value || 'field'
      return { isSource: true, detail: `Persistent database property '${objName}.${propName}'` }
    }
  }

  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isDatabaseSource(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return { isSource: false }
}

/**
 * Deep inspection: Checks whether a node contains dynamic, untrusted or unescaped variables.
 * Traverses BinaryExpressions (+), TemplateLiterals, Array joins, Identifiers, etc.
 */
export function isDynamicOrTainted(
  node: any,
  scope?: any,
  depth = 0
): { tainted: boolean; sourceDesc?: string } {
  if (!node || depth > 10) return { tainted: false }

  if (isSanitizedExpression(node)) {
    return { tainted: false }
  }

  // Static constants are safe
  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral' || node.type === 'BooleanLiteral' || node.type === 'NullLiteral') {
    return { tainted: false }
  }

  // Template literal: check expressions
  if (node.type === 'TemplateLiteral') {
    if (node.expressions && node.expressions.length > 0) {
      for (const expr of node.expressions) {
        const check = isDynamicOrTainted(expr, scope, depth + 1)
        if (check.tainted) return check
      }
      return { tainted: true, sourceDesc: 'Template literal interpolation' }
    }
    return { tainted: false }
  }

  // Binary expression (+ string concatenation)
  if (node.type === 'BinaryExpression') {
    const left = isDynamicOrTainted(node.left, scope, depth + 1)
    if (left.tainted) return left
    const right = isDynamicOrTainted(node.right, scope, depth + 1)
    if (right.tainted) return right
    return { tainted: true, sourceDesc: 'String concatenation (+)' }
  }

  // Logical expression (||, &&, ??)
  if (node.type === 'LogicalExpression') {
    const left = isDynamicOrTainted(node.left, scope, depth + 1)
    if (left.tainted) return left
    const right = isDynamicOrTainted(node.right, scope, depth + 1)
    if (right.tainted) return right
  }

  // Ternary expression (? :)
  if (node.type === 'ConditionalExpression') {
    const c = isDynamicOrTainted(node.consequent, scope, depth + 1)
    if (c.tainted) return c
    const a = isDynamicOrTainted(node.alternate, scope, depth + 1)
    if (a.tainted) return a
  }

  // Type casts and parentheses
  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isDynamicOrTainted(node.expression, scope, depth + 1)
  }

  // Array join
  if (node.type === 'CallExpression') {
    const callee = node.callee
    if (callee && callee.type === 'MemberExpression') {
      const methodName = callee.property?.name || callee.property?.value
      if (methodName === 'join') {
        const elements = resolveArrayElements(callee.object, scope, depth + 1)
        if (elements) {
          for (const el of elements) {
            const elCheck = isDynamicOrTainted(el, scope, depth + 1)
            if (elCheck.tainted) return elCheck
          }
        }
      }
      // Buffer / decode calls (e.g. Buffer.from(x, 'base64').toString('utf8'))
      if (methodName === 'toString') {
        const baseCheck = isDynamicOrTainted(callee.object, scope, depth + 1)
        if (baseCheck.tainted) return baseCheck
      }
    }

    if (node.arguments) {
      for (const arg of node.arguments) {
        const argCheck = isDynamicOrTainted(arg, scope, depth + 1)
        if (argCheck.tainted) return argCheck
      }
    }
  }

  // Check HTTP Source
  const httpCheck = isHttpSource(node, scope, depth + 1)
  if (httpCheck.isSource) {
    return { tainted: true, sourceDesc: httpCheck.detail }
  }

  // Check DOM Source
  const domCheck = isDomSource(node, scope, depth + 1)
  if (domCheck.isSource) {
    return { tainted: true, sourceDesc: domCheck.detail }
  }

  // Check DB Source
  const dbCheck = isDatabaseSource(node, scope, depth + 1)
  if (dbCheck.isSource) {
    return { tainted: true, sourceDesc: dbCheck.detail }
  }

  // Identifier: trace back to definition in scope
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isDynamicOrTainted(init, binding.scope || scope, depth + 1)
      }
      // If parameter of a function
      if (binding.kind === 'param') {
        return { tainted: true, sourceDesc: `Parameter '${node.name}'` }
      }
    }
    return { tainted: true, sourceDesc: `Dynamic variable '${node.name}'` }
  }

  return { tainted: false }
}

/**
 * Checks if an expression represents a safe numeric, integer, or boolean cast
 * (e.g. parseInt, parseFloat, Number(x), +x, Math.floor, Boolean(x))
 * which is mathematically impossible to inject SQL syntax into.
 */
export function isSafeNumericOrBooleanCast(node: any, scope?: any, depth = 0): boolean {
  if (!node || depth > 8) return false

  // Numeric and Boolean literals are safe
  if (node.type === 'NumericLiteral' || node.type === 'BooleanLiteral' || node.type === 'NullLiteral') {
    return true
  }

  // Unary expressions: +x, -x, !x, typeof x
  if (node.type === 'UnaryExpression') {
    if (node.operator === '+' || node.operator === '-' || node.operator === '!' || node.operator === '~') {
      return true
    }
  }

  // Binary arithmetic: a * b, a / b, a - b, a % b (non-string binary)
  if (node.type === 'BinaryExpression') {
    if (['-', '*', '/', '%', '**', '&', '|', '^', '>>', '<<', '>>>'].includes(node.operator)) {
      return true
    }
  }

  // Call Expressions: parseInt(x), parseFloat(x), Number(x), Math.floor(x), Boolean(x), BigInt(x), Date.now()
  if (node.type === 'CallExpression') {
    const callee = node.callee
    if (callee.type === 'Identifier') {
      const name = callee.name
      if (['parseInt', 'parseFloat', 'Number', 'Boolean', 'BigInt', 'isFinite', 'isNaN'].includes(name)) {
        return true
      }
    }

    if (callee.type === 'MemberExpression') {
      const objName = (callee.object?.name || '').toLowerCase()
      const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()

      if (objName === 'math' && ['floor', 'ceil', 'round', 'abs', 'min', 'max', 'trunc', 'sqrt', 'pow'].includes(propName)) {
        return true
      }
      if (objName === 'number' && ['parseint', 'parsefloat', 'isinteger', 'issafeinteger', 'isnan'].includes(propName)) {
        return true
      }
      if (objName === 'date' && propName === 'now') {
        return true
      }
    }
  }

  // Type assertions / Parentheses: (x as number)
  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isSafeNumericOrBooleanCast(node.expression, scope, depth + 1)
  }

  // Identifier lookup in scope
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isSafeNumericOrBooleanCast(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return false
}

/**
 * Checks if an expression is passed through a known SQL escaping/sanitizing function.
 * (e.g. mysql.escape(val), pool.escape(val), sqlstring.escape(val), escapeLiteral(val))
 */
export function isSqlSanitizedExpression(node: any, scope?: any, depth = 0): boolean {
  if (!node || depth > 8) return false

  if (node.type === 'CallExpression') {
    const callee = node.callee

    if (callee.type === 'MemberExpression') {
      const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()
      const objName = (callee.object?.name || '').toLowerCase()

      if (
        propName === 'escape' ||
        propName === 'escapeliteral' ||
        propName === 'escapeidentifier' ||
        propName === 'sqlescape' ||
        objName === 'sqlstring' ||
        objName === 'mysql' ||
        propName.includes('escape') ||
        propName.includes('sanitize')
      ) {
        return true
      }
    }

    if (callee.type === 'Identifier') {
      const name = callee.name.toLowerCase()
      if (
        name === 'escape' ||
        name === 'escapeliteral' ||
        name === 'escapeidentifier' ||
        name === 'sqlescape' ||
        name.includes('escape') ||
        name.includes('sanitize')
      ) {
        return true
      }
    }
  }

  // Type assertions / Parentheses
  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isSqlSanitizedExpression(node.expression, scope, depth + 1)
  }

  // Identifier lookup in scope
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isSqlSanitizedExpression(init, binding.scope || scope, depth + 1)
      }
    }
  }

  return false
}

/**
 * Deep inspection for SQL Injection taint flow.
 * Evaluates whether an expression contains unparameterized, dynamic, untrusted values,
 * while accurately respecting safe numeric casts, constant folding, and SQL escaping.
 */
export function isSqlTainted(
  node: any,
  scope?: any,
  depth = 0
): { tainted: boolean; sourceDesc?: string; isSafeCast?: boolean } {
  if (!node || depth > 10) return { tainted: false }

  // 1. Safe numeric / boolean conversions are immune to SQL injection
  if (isSafeNumericOrBooleanCast(node, scope)) {
    return { tainted: false, isSafeCast: true }
  }

  // 2. Safe SQL escaping functions
  if (isSqlSanitizedExpression(node, scope)) {
    return { tainted: false }
  }

  // 3. Static primitives are safe
  if (
    node.type === 'StringLiteral' ||
    node.type === 'NumericLiteral' ||
    node.type === 'BooleanLiteral' ||
    node.type === 'NullLiteral'
  ) {
    return { tainted: false }
  }

  // 4. Static string evaluation via constant folding
  const staticVal = evaluateStaticString(node, scope)
  if (staticVal !== null) {
    return { tainted: false }
  }

  // 5. Template literal: inspect dynamic expressions
  if (node.type === 'TemplateLiteral') {
    if (node.expressions && node.expressions.length > 0) {
      for (const expr of node.expressions) {
        // If the expression is a safe number/boolean cast or sanitized, it's safe
        if (isSafeNumericOrBooleanCast(expr, scope) || isSqlSanitizedExpression(expr, scope)) {
          continue
        }
        const exprCheck = isSqlTainted(expr, scope, depth + 1)
        if (exprCheck.tainted) {
          return exprCheck
        }
      }
      return { tainted: false }
    }
    return { tainted: false }
  }

  // 6. Binary expression (+ concatenation)
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const leftStatic = evaluateStaticString(node.left, scope)
    const rightStatic = evaluateStaticString(node.right, scope)

    if (leftStatic !== null && rightStatic !== null) {
      return { tainted: false }
    }

    // Check left operand
    if (leftStatic === null && !isSafeNumericOrBooleanCast(node.left, scope) && !isSqlSanitizedExpression(node.left, scope)) {
      const leftCheck = isSqlTainted(node.left, scope, depth + 1)
      if (leftCheck.tainted) return leftCheck
    }

    // Check right operand
    if (rightStatic === null && !isSafeNumericOrBooleanCast(node.right, scope) && !isSqlSanitizedExpression(node.right, scope)) {
      const rightCheck = isSqlTainted(node.right, scope, depth + 1)
      if (rightCheck.tainted) return rightCheck
    }

    return { tainted: false }
  }

  // 7. Logical and conditional expressions
  if (node.type === 'LogicalExpression') {
    const left = isSqlTainted(node.left, scope, depth + 1)
    if (left.tainted) return left
    const right = isSqlTainted(node.right, scope, depth + 1)
    if (right.tainted) return right
  }

  if (node.type === 'ConditionalExpression') {
    const c = isSqlTainted(node.consequent, scope, depth + 1)
    if (c.tainted) return c
    const a = isSqlTainted(node.alternate, scope, depth + 1)
    if (a.tainted) return a
  }

  // 8. Type Casts
  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isSqlTainted(node.expression, scope, depth + 1)
  }

  // 9. HTTP Source check
  const httpCheck = isHttpSource(node, scope, depth + 1)
  if (httpCheck.isSource) {
    return { tainted: true, sourceDesc: httpCheck.detail }
  }

  // 10. DOM Source check
  const domCheck = isDomSource(node, scope, depth + 1)
  if (domCheck.isSource) {
    return { tainted: true, sourceDesc: domCheck.detail }
  }

  // 11. Database Source check
  const dbCheck = isDatabaseSource(node, scope, depth + 1)
  if (dbCheck.isSource) {
    return { tainted: true, sourceDesc: dbCheck.detail }
  }

  // 12. Identifier scope tracing
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init) {
        return isSqlTainted(init, binding.scope || scope, depth + 1)
      }
      if (binding.kind === 'param') {
        return { tainted: true, sourceDesc: `Parameter '${node.name}'` }
      }
    }
    return { tainted: true, sourceDesc: `Dynamic variable '${node.name}'` }
  }

  return { tainted: false }
}

/**
 * Checks whether a file is an internal build tool, maintainer script, test file, or config file
 * (e.g. bin/, scripts/, tools/, build/, tests/, webpack.config.js, etc.)
 */
export function isInternalBuildOrDevScript(filePath: string): boolean {
  if (!filePath) return false
  const normalized = filePath.replace(/\\/g, '/').toLowerCase()
  const pathParts = normalized.split('/')
  const fileName = pathParts[pathParts.length - 1] || ''

  // Build / Dev / Tooling directories and harnesses
  if (
    normalized.includes('/bin/') ||
    normalized.startsWith('bin/') ||
    normalized.includes('/scripts/') ||
    normalized.startsWith('scripts/') ||
    normalized.includes('/tools/') ||
    normalized.startsWith('tools/') ||
    normalized.includes('/build/') ||
    normalized.startsWith('build/') ||
    normalized.includes('/tasks/') ||
    normalized.startsWith('tasks/') ||
    normalized.includes('/benchmark/') ||
    normalized.startsWith('benchmark/') ||
    normalized.includes('/benchmarks/') ||
    normalized.startsWith('benchmarks/') ||
    normalized.includes('/harness/') ||
    normalized.startsWith('harness/') ||
    normalized.includes('/harness-') ||
    normalized.includes('harness-') ||
    normalized.includes('/e2e/') ||
    normalized.startsWith('e2e/') ||
    normalized.includes('/fixtures/') ||
    normalized.startsWith('fixtures/') ||
    normalized.includes('/mocks/') ||
    normalized.startsWith('mocks/') ||
    normalized.includes('/examples/') ||
    normalized.startsWith('examples/') ||
    normalized.includes('/docs/') ||
    normalized.startsWith('docs/') ||
    normalized.includes('/test/') ||
    normalized.startsWith('test/') ||
    normalized.includes('/tests/') ||
    normalized.startsWith('tests/') ||
    normalized.includes('/__tests__/') ||
    normalized.startsWith('__tests__/')
  ) {
    return true
  }

  // Config files and test files
  if (
    fileName.endsWith('.config.js') ||
    fileName.endsWith('.config.ts') ||
    fileName.endsWith('.config.mjs') ||
    fileName.endsWith('.config.cjs') ||
    fileName.endsWith('.test.js') ||
    fileName.endsWith('.test.ts') ||
    fileName.endsWith('.spec.js') ||
    fileName.endsWith('.spec.ts') ||
    fileName === 'gulpfile.js' ||
    fileName === 'gruntfile.js' ||
    fileName === 'webpack.js' ||
    fileName === 'rollup.js'
  ) {
    return true
  }

  return false
}

/**
 * Checks if an expression has been sanitized against Command Injection
 * (e.g. quote(x), shellEscape(x), validator.isAlphanumeric check, escapeShellArg(x))
 */
export function isCmdiSanitizedExpression(node: any, scope?: any): boolean {
  if (!node) return false

  // Direct Call to sanitizer function: quote(cmd), escapeShellArg(arg), etc.
  if (node.type === 'CallExpression') {
    const callee = node.callee

    // Simple identifier: quote(x), escapeShell(x), sanitize(x)
    if (callee.type === 'Identifier') {
      const name = callee.name.toLowerCase()
      if (
        KNOWN_CMDI_SANITIZERS.has(name) ||
        KNOWN_SANITIZERS.has(name) ||
        name.includes('escapeshell') ||
        name.includes('sanitize') ||
        name.includes('quote') ||
        name === 'isalphanumeric' ||
        name === 'isnumeric' ||
        name === 'isip'
      ) {
        return true
      }
    }

    // MemberExpression: shellQuote.quote(x), validator.escape(x), shlex.quote(x)
    if (callee.type === 'MemberExpression') {
      const propName = (callee.property?.name || callee.property?.value || '').toLowerCase()
      const objName = (callee.object?.name || '').toLowerCase()
      const fullName = `${objName}.${propName}`

      if (
        KNOWN_CMDI_SANITIZERS.has(propName) ||
        KNOWN_CMDI_SANITIZERS.has(fullName) ||
        KNOWN_SANITIZERS.has(propName) ||
        propName.includes('escapeshell') ||
        propName.includes('quote') ||
        propName.includes('sanitize') ||
        propName === 'isalphanumeric' ||
        propName === 'isnumeric' ||
        propName === 'isip'
      ) {
        return true
      }
    }
  }

  // Identifier holding sanitized result
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init
      if (init && isCmdiSanitizedExpression(init, binding.scope || scope)) {
        return true
      }
    }
  }

  return false
}

/**
 * Evaluates whether an options object passed to spawn/spawnSync/execFile has shell enabled
 * (e.g. { shell: true } or { shell: '/bin/bash' } or { shell: 'sh' })
 */
export function isShellOptionEnabled(optionsNode: any, scope?: any): boolean {
  if (!optionsNode) return false

  let resolvedNode = optionsNode

  // If options is an Identifier, resolve binding
  if (optionsNode.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(optionsNode.name) : null
    if (binding?.path?.node?.init) {
      resolvedNode = binding.path.node.init
    }
  }

  if (resolvedNode && resolvedNode.type === 'ObjectExpression') {
    for (const prop of resolvedNode.properties || []) {
      if (prop.type === 'ObjectProperty' || prop.type === 'Property') {
        const keyName = (prop.key?.name || prop.key?.value || '').toLowerCase()
        if (keyName === 'shell') {
          // Check value of shell property
          if (prop.value?.type === 'BooleanLiteral') {
            return prop.value.value === true
          }
          if (prop.value?.type === 'StringLiteral') {
            return prop.value.value.trim().length > 0
          }
          // If dynamic expression or identifier for shell
          if (prop.value?.type === 'Identifier') {
            if (prop.value.name === 'true') return true
            if (prop.value.name === 'false') return false
          }
          return true
        }
      }
    }
  }

  return false
}

/**
 * Checks if an expression passed into a command execution sink contains tainted / dynamic user input.
 * When isBuildScript is true, dynamic variables without traceable external HTTP sources are treated as safe.
 */
export function isCmdiTainted(
  node: any,
  scope?: any,
  isBuildScript = false,
  depth = 0
): { tainted: boolean; sourceDesc?: string; isDirectSource?: boolean } {
  if (!node || depth > 10) {
    return { tainted: false }
  }

  // 1. If wrapped in sanitizer or shell-quote, it is safe
  if (isCmdiSanitizedExpression(node, scope)) {
    return { tainted: false }
  }

  // 2. Safe numeric/boolean casts: Number(x), parseInt(x), Boolean(x)
  if (isSafeNumericOrBooleanCast(node, scope)) {
    return { tainted: false }
  }

  // 3. Constant folding: static string literal or concatenated literals
  const staticVal = evaluateStaticString(node, scope)
  if (staticVal !== null) {
    return { tainted: false }
  }

  // 4. Template literal: inspect dynamic expressions
  if (node.type === 'TemplateLiteral') {
    if (node.expressions && node.expressions.length > 0) {
      for (const expr of node.expressions) {
        if (isSafeNumericOrBooleanCast(expr, scope) || isCmdiSanitizedExpression(expr, scope)) {
          continue
        }
        const exprCheck = isCmdiTainted(expr, scope, isBuildScript, depth + 1)
        if (exprCheck.tainted) {
          return exprCheck
        }
      }
      return { tainted: false }
    }
    return { tainted: false }
  }

  // 5. Binary expression (+ concatenation)
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const leftStatic = evaluateStaticString(node.left, scope)
    const rightStatic = evaluateStaticString(node.right, scope)

    if (leftStatic !== null && rightStatic !== null) {
      return { tainted: false }
    }

    if (leftStatic === null && !isSafeNumericOrBooleanCast(node.left, scope) && !isCmdiSanitizedExpression(node.left, scope)) {
      const leftCheck = isCmdiTainted(node.left, scope, isBuildScript, depth + 1)
      if (leftCheck.tainted) return leftCheck
    }

    if (rightStatic === null && !isSafeNumericOrBooleanCast(node.right, scope) && !isCmdiSanitizedExpression(node.right, scope)) {
      const rightCheck = isCmdiTainted(node.right, scope, isBuildScript, depth + 1)
      if (rightCheck.tainted) return rightCheck
    }

    return { tainted: false }
  }

  // 6. Logical and conditional expressions
  if (node.type === 'LogicalExpression') {
    const left = isCmdiTainted(node.left, scope, isBuildScript, depth + 1)
    if (left.tainted) return left
    const right = isCmdiTainted(node.right, scope, isBuildScript, depth + 1)
    if (right.tainted) return right
  }

  if (node.type === 'ConditionalExpression') {
    const c = isCmdiTainted(node.consequent, scope, isBuildScript, depth + 1)
    if (c.tainted) return c
    const a = isCmdiTainted(node.alternate, scope, isBuildScript, depth + 1)
    if (a.tainted) return a
  }

  // 7. Type Casts / Parenthesized
  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'ParenthesizedExpression') {
    return isCmdiTainted(node.expression, scope, isBuildScript, depth + 1)
  }

  // 8. HTTP Source check
  const httpCheck = isHttpSource(node, scope, depth + 1)
  if (httpCheck.isSource) {
    return { tainted: true, isDirectSource: true, sourceDesc: httpCheck.detail }
  }

  // 9. DOM Source check
  const domCheck = isDomSource(node, scope, depth + 1)
  if (domCheck.isSource) {
    return { tainted: true, isDirectSource: true, sourceDesc: domCheck.detail }
  }

  // 10. Database / Persistent Source check
  const dbCheck = isDatabaseSource(node, scope, depth + 1)
  if (dbCheck.isSource) {
    return { tainted: true, isDirectSource: true, sourceDesc: dbCheck.detail }
  }

  // 11. Identifier scope tracing
  if (node.type === 'Identifier' && scope) {
    const binding = scope.getBinding ? scope.getBinding(node.name) : null
    if (binding && binding.path && binding.path.node) {
      const init = binding.path.node.init

      // Check if init is an allowlist object lookup: const cmd = CMD_MAP[req.query.action]
      if (init && init.type === 'MemberExpression') {
        const obj = init.object
        if (obj && obj.type === 'Identifier') {
          const objBinding = scope.getBinding ? scope.getBinding(obj.name) : null
          const objInit = objBinding?.path?.node?.init
          if (objInit && objInit.type === 'ObjectExpression') {
            const allPropsStatic = objInit.properties.every((p: any) => {
              return p.value && (p.value.type === 'StringLiteral' || evaluateStaticString(p.value, scope) !== null)
            })
            if (allPropsStatic && objInit.properties.length > 0) {
              return { tainted: false }
            }
          }
        }
      }

      if (init) {
        return isCmdiTainted(init, binding.scope || scope, isBuildScript, depth + 1)
      }
      if (binding.kind === 'param') {
        if (isBuildScript) {
          // Inside build/maintainer scripts, parameters are internal and not exposed to network input
          return { tainted: false }
        }
        return { tainted: true, sourceDesc: `Parameter '${node.name}'` }
      }
    }
    if (isBuildScript) {
      // In internal build scripts, unbound variables/options are local CLI options or constants
      return { tainted: false }
    }
    return { tainted: true, sourceDesc: `Dynamic variable '${node.name}'` }
  }

  // Member expressions like options.since or config.branch in build scripts
  if (node.type === 'MemberExpression' && isBuildScript) {
    return { tainted: false }
  }

  return { tainted: false }
}

/**
 * Checks if an identifier or expression in the given AST path was guarded against command injection
 * by preceding validation checks in the enclosing function or block (e.g. regex tests, allowlist lookups).
 */
export function isNodeGuardedAgainstCmdi(node: any, path: any): boolean {
  if (!node || !path) return false

  const varName = node.type === 'Identifier' ? node.name : null
  if (!varName) return false

  // Find enclosing function or program body
  const enclosingFunction = path.getFunctionParent ? path.getFunctionParent() : null
  const bodyNode = enclosingFunction?.node?.body || path.scope?.block?.body || path.scope?.block

  if (!bodyNode) return false

  const statements = Array.isArray(bodyNode.body) ? bodyNode.body : [bodyNode]
  const targetLine = path.node?.loc?.start?.line || 999999

  for (const stmt of statements) {
    if (stmt.loc && stmt.loc.start.line >= targetLine) {
      break
    }

    if (stmt.type === 'IfStatement') {
      const test = stmt.test
      if (!test) continue

      let foundGuard = false

      const checkExpr = (expr: any) => {
        if (!expr) return
        if (expr.type === 'UnaryExpression') {
          checkExpr(expr.argument)
          return
        }
        if (expr.type === 'LogicalExpression' || expr.type === 'BinaryExpression') {
          checkExpr(expr.left)
          checkExpr(expr.right)
          return
        }
        if (expr.type === 'CallExpression') {
          const callee = expr.callee
          const args = expr.arguments || []
          const matchesVar = args.some((a: any) => a.type === 'Identifier' && a.name === varName)

          if (matchesVar) {
            if (callee.type === 'MemberExpression') {
              const prop = (callee.property?.name || callee.property?.value || '').toLowerCase()
              if (['test', 'includes', 'has', 'isalphanumeric', 'isnumeric', 'isip', 'isuuid'].includes(prop)) {
                foundGuard = true
              }
            }
            if (callee.type === 'Identifier') {
              const fn = callee.name.toLowerCase()
              if (['isalphanumeric', 'isnumeric', 'isip', 'isuuid', 'test'].includes(fn)) {
                foundGuard = true
              }
            }
          }
        }
      }

      checkExpr(test)
      if (foundGuard) {
        return true
      }
    }
  }

  return false
}




