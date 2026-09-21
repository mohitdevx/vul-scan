import type { ReportRenderer } from '../renderer.js'
import type { SecurityReport } from '../types.js'

export class JsonReporter implements ReportRenderer<string> {
  public readonly name = 'JsonReporter'
  public readonly format = 'json'
  public readonly contentType = 'application/json'

  public render(report: SecurityReport): string {
    return JSON.stringify(report, null, 2)
  }
}
