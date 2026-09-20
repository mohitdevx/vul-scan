export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type AiVerdict = 'CONFIRMED_VULNERABILITY' | 'FALSE_POSITIVE' | 'SUSPICIOUS'

export interface AiTriageResult {
  verdict: AiVerdict
  confidence: number
  isFalsePositive: boolean
  reason: string
  remediation: string
  model: string
  sanitizerDetected?: boolean
  safeCastDetected?: boolean
  evaluatedAt: string
  analysis?: string
  dataFlow?: string
  securityImpact?: string
  untrustedSource?: string
}

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
  aiAnalysis?: AiTriageResult
}

export interface EngineContext {
  filePath: string
  fileContent: string
  lines: string[]
}

export interface SecurityEngine {
  id: string
  name: string
  ruleId: string
  cwe: string
  version?: string
  enabled?: boolean
  analyze: (ast: any, ctx: EngineContext) => Finding[]
}

export interface ScanResult {
  findings: Finding[]
  scannedFilesCount: number
  durationMs: number
  aiValidated?: boolean
  aiConfirmedCount?: number
  aiFalsePositiveCount?: number
}
