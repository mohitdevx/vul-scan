/**
 * VulScan Professional Security Reporting Engine
 * Entry point & API facade for generating multi-format security reports from AST scans.
 */

import { FindingNormalizer, type RawScanInput } from './normalizer.js'
import { JsonReporter } from './renderers/jsonReporter.js'
import { MarkdownReporter } from './renderers/markdownReporter.js'
import { HtmlReporter } from './renderers/htmlReporter.js'
import type { SecurityReport } from './types.js'

export * from './types.js'
export * from './severity.js'
export * from './renderer.js'
export * from './normalizer.js'
export * from './renderers/jsonReporter.js'
export * from './renderers/markdownReporter.js'
export * from './renderers/htmlReporter.js'
export * from './utils/escape.js'

export interface GeneratedReports {
  ir: SecurityReport
  json: string
  markdown: string
  html: string
}

/**
 * Transforms raw AST scan results into the normalized Report IR
 * and compiles it into canonical JSON, Markdown, and HTML reports.
 */
export function generateSecurityReport(scanInput: RawScanInput): GeneratedReports {
  const ir = FindingNormalizer.normalizeScan(scanInput)

  const jsonReporter = new JsonReporter()
  const markdownReporter = new MarkdownReporter()
  const htmlReporter = new HtmlReporter()

  return {
    ir,
    json: jsonReporter.render(ir),
    markdown: markdownReporter.render(ir),
    html: htmlReporter.render(ir),
  }
}
