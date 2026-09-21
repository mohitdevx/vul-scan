import type { SecurityReport } from './types.js'

/**
 * Generic Report Renderer Interface
 * Allows independent renderers (JSON, Markdown, HTML, SARIF, PDF)
 * to consume the same canonical SecurityReport IR without duplicating business logic.
 */
export interface ReportRenderer<T = string> {
  name: string
  format: 'json' | 'markdown' | 'html' | string
  contentType: string
  render(report: SecurityReport): T
}
