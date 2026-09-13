import { type FC } from 'react'

interface CodeBlockProps {
  code: string
  highlightToken?: string
  highlightType?: 'unsafe' | 'safe'
  showLineNumbers?: boolean
  startLine?: number
  className?: string
}

// Token types for syntax highlighting
type TokenType =
  | 'comment'
  | 'string'
  | 'keyword'
  | 'boolean'
  | 'number'
  | 'function'
  | 'property'
  | 'punctuation'
  | 'text'

interface Token {
  type: TokenType
  content: string
}

const KEYWORDS = new Set([
  'const',
  'let',
  'var',
  'function',
  'return',
  'import',
  'from',
  'export',
  'default',
  'class',
  'new',
  'async',
  'await',
  'if',
  'else',
])

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = []
  let i = 0

  while (i < line.length) {
    // Single line comments
    if (line[i] === '/' && line[i + 1] === '/') {
      tokens.push({ type: 'comment', content: line.slice(i) })
      break
    }

    // Strings: single, double, backtick
    if (line[i] === '"' || line[i] === "'" || line[i] === '`') {
      const quote = line[i]
      let str = quote
      i++
      while (i < line.length) {
        str += line[i]
        if (line[i] === quote && line[i - 1] !== '\\') {
          i++
          break
        }
        i++
      }
      tokens.push({ type: 'string', content: str })
      continue
    }

    // Word tokens: keywords, booleans, functions, properties, identifiers
    if (/[a-zA-Z_$]/.test(line[i])) {
      let word = ''
      while (i < line.length && /[a-zA-Z0-9_$]/.test(line[i])) {
        word += line[i]
        i++
      }

      if (KEYWORDS.has(word)) {
        tokens.push({ type: 'keyword', content: word })
      } else if (word === 'true' || word === 'false' || word === 'null' || word === 'undefined') {
        tokens.push({ type: 'boolean', content: word })
      } else if (i < line.length && line[i] === '(') {
        tokens.push({ type: 'function', content: word })
      } else if (tokens.length > 0 && tokens[tokens.length - 1].content === '.') {
        tokens.push({ type: 'property', content: word })
      } else {
        tokens.push({ type: 'text', content: word })
      }
      continue
    }

    // Numbers
    if (/[0-9]/.test(line[i])) {
      let num = ''
      while (i < line.length && /[0-9]/.test(line[i])) {
        num += line[i]
        i++
      }
      tokens.push({ type: 'number', content: num })
      continue
    }

    // Operators and punctuation
    if (/[{}()[\].,;:+=*&|^!<>?-]/.test(line[i])) {
      tokens.push({ type: 'punctuation', content: line[i] })
      i++
      continue
    }

    // Whitespace / other
    let space = ''
    while (i < line.length && /\s/.test(line[i])) {
      space += line[i]
      i++
    }
    if (space) {
      tokens.push({ type: 'text', content: space })
    } else {
      tokens.push({ type: 'text', content: line[i] })
      i++
    }
  }

  return tokens
}

export const CodeBlock: FC<CodeBlockProps> = ({
  code,
  highlightToken,
  highlightType = 'unsafe',
  showLineNumbers = true,
  startLine = 1,
  className = '',
}) => {
  const lines = code.trim().split('\n')

  const renderToken = (token: Token, idx: number) => {
    switch (token.type) {
      case 'comment':
        return (
          <span key={idx} className="text-zinc-500 italic">
            {token.content}
          </span>
        )
      case 'string':
        return (
          <span key={idx} className="text-emerald-300">
            {token.content}
          </span>
        )
      case 'keyword':
        return (
          <span key={idx} className="text-purple-400 font-semibold">
            {token.content}
          </span>
        )
      case 'boolean':
      case 'number':
        return (
          <span key={idx} className="text-amber-300">
            {token.content}
          </span>
        )
      case 'function':
        return (
          <span key={idx} className="text-sky-300">
            {token.content}
          </span>
        )
      case 'property':
        return (
          <span key={idx} className="text-cyan-200">
            {token.content}
          </span>
        )
      case 'punctuation':
        return (
          <span key={idx} className="text-zinc-400">
            {token.content}
          </span>
        )
      default:
        return (
          <span key={idx} className="text-zinc-200">
            {token.content}
          </span>
        )
    }
  }

  return (
    <div
      className={`rounded-lg bg-[#070709] border border-zinc-850 py-2.5 px-3.5 font-mono text-[12px] leading-relaxed overflow-hidden no-scrollbar select-text ${className}`}
    >
      <div className="space-y-1">
        {lines.map((lineText, lineIdx) => {
          const lineNum = startLine + lineIdx
          const hasHighlight = highlightToken && lineText.includes(highlightToken)

          if (hasHighlight && highlightToken) {
            const parts = lineText.split(highlightToken)
            return (
              <div key={lineIdx} className="flex items-start gap-3">
                {showLineNumbers && (
                  <span className="text-zinc-600 text-[11px] select-none shrink-0 w-5 text-right font-mono">
                    {lineNum}
                  </span>
                )}
                <div className="flex-1 whitespace-pre">
                  {tokenizeLine(parts[0]).map((tok, i) => renderToken(tok, i))}
                  <span
                    className={
                      highlightType === 'unsafe'
                        ? 'bg-rose-500/20 text-rose-300 px-1 py-0.5 rounded border border-rose-500/40 font-semibold'
                        : 'bg-emerald-500/20 text-emerald-300 px-1 py-0.5 rounded border border-emerald-500/40 font-semibold'
                    }
                  >
                    {highlightToken}
                  </span>
                  {parts[1] &&
                    tokenizeLine(parts[1]).map((tok, i) =>
                      renderToken(tok, i + 100)
                    )}
                </div>
              </div>
            )
          }

          const tokens = tokenizeLine(lineText)
          return (
            <div key={lineIdx} className="flex items-start gap-3">
              {showLineNumbers && (
                <span className="text-zinc-600 text-[11px] select-none shrink-0 w-5 text-right font-mono">
                  {lineNum}
                </span>
              )}
              <div className="flex-1 whitespace-pre">
                {tokens.map((tok, i) => renderToken(tok, i))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
