import { useState, useCallback } from 'react'
import { RiFileCopyLine, RiCheckLine, RiCodeLine } from '@remixicon/react'

interface CodeBlockProps {
  code: string
  language?: string
  highlightLine?: number
  startLineNumber?: number
  startLine?: number
  highlightToken?: string
  highlightType?: 'unsafe' | 'safe' | string
  filePath?: string
  className?: string
  variant?: 'minimal' | 'bordered'
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
])

const JS_LITERALS = new Set(['true', 'false', 'null', 'undefined'])

/**
 * Deterministic syntax tokenizer for JS/TS/JSX
 */
function highlightJsLine(line: string, highlightToken?: string, highlightType?: string) {
  // Check for line comment first
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

  const tokens: { text: string; type: 'keyword' | 'literal' | 'string' | 'token-highlight' | 'sink' | 'normal' }[] = []
  let lastIndex = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(mainCode)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ text: mainCode.slice(lastIndex, match.index), type: 'normal' })
    }

    const val = match[0]

    if (highlightToken && (val === highlightToken || val.includes(highlightToken))) {
      tokens.push({ text: val, type: 'token-highlight' })
    } else if (val.startsWith('"') || val.startsWith("'") || val.startsWith('`')) {
      tokens.push({ text: val, type: 'string' })
    } else if (JS_KEYWORDS.has(val)) {
      tokens.push({ text: val, type: 'keyword' })
    } else if (JS_LITERALS.has(val) || /^\d+$/.test(val)) {
      tokens.push({ text: val, type: 'literal' })
    } else if (
      val === 'innerHTML' ||
      val === 'outerHTML' ||
      val === 'eval' ||
      val === 'dangerouslySetInnerHTML' ||
      val === 'document' ||
      val === 'write' ||
      val === 'writeln'
    ) {
      tokens.push({ text: val, type: 'sink' })
    } else {
      tokens.push({ text: val, type: 'normal' })
    }

    lastIndex = regex.lastIndex
  }

  if (lastIndex < mainCode.length) {
    tokens.push({ text: mainCode.slice(lastIndex), type: 'normal' })
  }

  return (
    <>
      {tokens.map((tok, i) => {
        switch (tok.type) {
          case 'token-highlight':
            return (
              <span
                key={i}
                className={`font-semibold px-1 py-0.5 rounded ${
                  highlightType === 'safe'
                    ? 'text-emerald-300 bg-emerald-500/20'
                    : 'text-rose-300 bg-rose-500/20'
                }`}
              >
                {tok.text}
              </span>
            )
          case 'keyword':
            return <span key={i} className="text-[#c792ea]">{tok.text}</span>
          case 'string':
            return <span key={i} className="text-[#c3e88d]">{tok.text}</span>
          case 'literal':
            return <span key={i} className="text-[#f78c6c]">{tok.text}</span>
          case 'sink':
            return <span key={i} className="text-[#ff5370] font-semibold underline decoration-[#ff5370]/50">{tok.text}</span>
          default:
            return <span key={i} className="text-zinc-300">{tok.text}</span>
        }
      })}
      {commentPart && <span className="text-zinc-600 italic">{commentPart}</span>}
    </>
  )
}

export function CodeBlock({
  code,
  language = 'javascript',
  highlightLine,
  startLineNumber,
  startLine = 1,
  highlightToken,
  highlightType,
  filePath,
  className = '',
  variant = 'minimal',
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(() => {
    if (!code) return
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [code])

  const effectiveStart = startLineNumber !== undefined ? startLineNumber : startLine
  const rawLines = code.split('\n')

  const containerStyles =
    variant === 'minimal'
      ? 'bg-[#0d0e12] rounded-lg'
      : 'rounded-xl border border-zinc-800 bg-[#09090c]'

  return (
    <div className={`relative overflow-hidden text-xs font-mono ${containerStyles} ${className}`}>
      {/* Top Header Bar */}
      <div className="flex items-center justify-between px-4 py-2 text-zinc-400">
        <div className="flex items-center gap-2">
          <RiCodeLine className="w-3.5 h-3.5 text-zinc-600" />
          <span className="text-[11px] text-zinc-400 font-mono tracking-tight truncate max-w-sm">
            {filePath || language}
          </span>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-200 transition-colors cursor-pointer"
          title="Copy snippet"
        >
          {copied ? (
            <>
              <RiCheckLine className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <RiFileCopyLine className="w-3 h-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code Lines with line numbers */}
      <div className="overflow-x-auto px-4 pb-3 pt-1 leading-relaxed selection:bg-red-500/20">
        <table className="w-full border-collapse">
          <tbody>
            {rawLines.map((lineText, idx) => {
              const currentLineNum = effectiveStart + idx
              const isFlagged = highlightLine !== undefined && currentLineNum === highlightLine

              return (
                <tr
                  key={idx}
                  className={`transition-colors ${
                    isFlagged
                      ? 'bg-rose-500/[0.08] border-l-2 border-rose-500'
                      : 'hover:bg-white/[0.02]'
                  }`}
                >
                  {/* Line Number Gutter */}
                  <td className="pr-4 pl-1 select-none text-right align-top w-10 text-[11px]">
                    <span
                      className={`font-mono ${
                        isFlagged ? 'text-rose-400 font-semibold' : 'text-zinc-600'
                      }`}
                    >
                      {currentLineNum}
                    </span>
                  </td>

                  {/* Code Line Content */}
                  <td className="whitespace-pre align-top text-zinc-300">
                    {highlightJsLine(lineText, highlightToken, highlightType)}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
