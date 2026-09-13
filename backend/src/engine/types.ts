export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export interface Finding {
  id: string
  ruleId: string
  ruleName: string
  cwe: string
  severity: Severity
  filePath: string
  line: number
  column: number
  snippet: string
  sink: string
  message: string
  remediation: string
}

export interface EngineContext {
  filePath: string
  fileContent: string
  lines: string[]
}

export interface SecurityEngine {
  name: string
  ruleId: string
  cwe: string
  analyze: (ast: any, ctx: EngineContext) => Finding[]
}

export interface ScanResult {
  findings: Finding[]
  scannedFilesCount: number
  durationMs: number
}
