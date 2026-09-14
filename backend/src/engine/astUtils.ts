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
