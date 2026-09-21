/**
 * Security & Escaping Utilities for Report Generation
 * Guarantees that untrusted source code, user inputs, and AI outputs
 * cannot execute script payloads or break document layouts.
 */

const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
}

/**
 * Strictly escapes special HTML characters to prevent XSS injection
 */
export function escapeHtml(str: unknown): string {
  if (str === null || str === undefined) return ''
  const stringVal = String(str)
  return stringVal.replace(/[&<>"'`]/g, ch => HTML_ESCAPE_MAP[ch] || ch)
}

/**
 * Sanitizes an attribute value for safe inclusion in HTML attributes
 */
export function escapeAttribute(str: unknown): string {
  return escapeHtml(str).replace(/\n/g, ' ')
}

/**
 * Sanitizes an ID string for safe usage in HTML element IDs and URL fragments
 */
export function sanitizeElementId(id: string): string {
  return String(id)
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/^_+|_+$/g, '')
}

const JS_KEYWORDS = new Set([
  'const',
  'let',
  'var',
  'function',
  'return',
  'if',
  'else',
  'for',
  'while',
  'async',
  'await',
  'import',
  'export',
  'from',
  'default',
  'class',
  'extends',
  'new',
  'this',
  'try',
  'catch',
  'finally',
  'throw',
  'typeof',
  'instanceof',
  'type',
  'interface',
  'require',
])

const JS_LITERALS = new Set(['true', 'false', 'null', 'undefined'])

/**
 * Escapes and tokenizes a code line into syntax-highlighted HTML spans
 * All token text is strictly HTML-escaped.
 */
export function highlightCodeLineHtml(line: string, highlightToken?: string): string {
  // Check for line comments
  const commentIdx = line.indexOf('//')
  let mainCode = line
  let commentPart = ''

  if (commentIdx !== -1) {
    const before = line.slice(0, commentIdx)
    const singleQuotes = (before.match(/'/g) || []).length
    const doubleQuotes = (before.match(/"/g) || []).length
    const backticks = (before.match(/`/g) || []).length
    if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0 && backticks % 2 === 0) {
      mainCode = line.slice(0, commentIdx)
      commentPart = line.slice(commentIdx)
    }
  }

  const regex = /(`(?:\\`|[^`])*`|"(?:\\"|[^"])*"|'(?:\\'|[^'])*'|\b\w+\b|[<>&=+\-*/:;,.(){}[\]])/g
  let lastIndex = 0
  let match: RegExpExecArray | null
  let htmlResult = ''

  while ((match = regex.exec(mainCode)) !== null) {
    if (match.index > lastIndex) {
      htmlResult += escapeHtml(mainCode.slice(lastIndex, match.index))
    }

    const val = match[0]
    const escapedVal = escapeHtml(val)

    if (highlightToken && (val === highlightToken || val.includes(highlightToken))) {
      htmlResult += `<span class="token-sink-highlight">${escapedVal}</span>`
    } else if (val.startsWith('"') || val.startsWith("'") || val.startsWith('`')) {
      htmlResult += `<span class="token-string">${escapedVal}</span>`
    } else if (JS_KEYWORDS.has(val)) {
      htmlResult += `<span class="token-keyword">${escapedVal}</span>`
    } else if (JS_LITERALS.has(val) || /^\d+$/.test(val)) {
      htmlResult += `<span class="token-number">${escapedVal}</span>`
    } else if (
      val === 'innerHTML' ||
      val === 'outerHTML' ||
      val === 'eval' ||
      val === 'dangerouslySetInnerHTML' ||
      val === 'exec' ||
      val === 'execSync' ||
      val === '$queryRawUnsafe' ||
      val === 'document'
    ) {
      htmlResult += `<span class="token-sink">${escapedVal}</span>`
    } else {
      htmlResult += escapedVal
    }

    lastIndex = regex.lastIndex
  }

  if (lastIndex < mainCode.length) {
    htmlResult += escapeHtml(mainCode.slice(lastIndex))
  }

  if (commentPart) {
    htmlResult += `<span class="token-comment">${escapeHtml(commentPart)}</span>`
  }

  return htmlResult
}
