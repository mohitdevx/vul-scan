import { parse, type ParserPlugin } from '@babel/parser'
import { logger } from '../utils/logger.js'

export function parseSourceCode(content: string, filePath: string): any | null {
  const isTs = filePath.endsWith('.ts') || filePath.endsWith('.tsx')
  const isJsx = filePath.endsWith('.jsx') || filePath.endsWith('.tsx')

  const plugins: ParserPlugin[] = [
    'exportDefaultFrom',
    'decorators-legacy',
  ]

  if (isTs) plugins.push('typescript')
  if (isJsx) plugins.push('jsx')

  try {
    return parse(content, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      plugins,
      errorRecovery: true,
    })
  } catch (err: any) {
    logger.debug(`Parser error on file ${filePath}: ${err.message}`)
    return null
  }
}

export function extractSnippet(lines: string[], startLine: number, radius = 1): string {
  if (!lines || lines.length === 0) return ''
  const index = Math.max(0, startLine - 1)
  const from = Math.max(0, index - radius)
  const to = Math.min(lines.length - 1, index + radius)
  return lines.slice(from, to + 1).join('\n')
}
