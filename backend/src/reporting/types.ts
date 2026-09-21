/**
 * Security Report Intermediate Representation (Report IR)
 * Strongly typed internal representation for SAST security reports.
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface SeverityMeta {
  level: SeverityLevel
  label: string
  numericPriority: number
  color: string
  badgeBg: string
  badgeBorder: string
  badgeText: string
  emoji: string
  description: string
}

export type FindingStatus =
  | 'confirmed'
  | 'likely'
  | 'potential'
  | 'false-positive'
  | 'needs-review'

export interface FindingLocation {
  file: string
  line: number
  column?: number
  endLine?: number
  endColumn?: number
}

export interface TaintNode {
  type: 'source' | 'transformation' | 'variable' | 'sink' | 'sanitizer'
  label: string
  expression: string
  description?: string
  file?: string
  line?: number
}

export interface TaintFlow {
  source: TaintNode
  transformations: TaintNode[]
  sink: TaintNode
}

export interface FindingEvidence {
  code: string
  language: string
  startLine: number
  endLine: number
  highlightLine?: number
  highlightToken?: string
}

export interface FindingAiAnalysis {
  model: string
  verdict: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_REVIEW'
  confidence: number
  reasoning: string
  isFalsePositive?: boolean
  exploitability?: string
  sanitizerDetected?: boolean
  safeCastDetected?: boolean
  evaluatedAt?: string
}

export interface FindingImpact {
  description: string
  consequences: string[]
  prerequisites?: string[]
  cvssVector?: string
}

export interface FindingRemediation {
  summary: string
  explanation: string
  code?: string
  language?: string
  diff?: string
  documentationUrl?: string
}

export interface SecurityFinding {
  id: string
  rule: {
    id: string
    name: string
    category: string
    cwe: string
    owasp?: string
  }
  severity: SeverityLevel
  confidence: number
  status: FindingStatus
  location: FindingLocation
  taintFlow: TaintFlow
  evidence: FindingEvidence
  analysis?: FindingAiAnalysis
  impact: FindingImpact
  remediation: FindingRemediation
  rawMessage: string
  branch?: string
  scanId?: string
}

export interface ReportMetadata {
  scanner: {
    name: string
    version: string
    engine: string
  }
  target: {
    repositoryName: string
    repositoryUrl: string
    branch: string
    commitSha?: string
  }
  scan: {
    id: string
    timestamp: string
    durationMs: number
    filesAnalyzed: number
    linesAnalyzed?: number
    rulesExecuted: number
  }
}

export interface SeverityDistribution {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  total: number
}

export interface SecuritySummary {
  posture: 'CLEAN' | 'LOW_RISK' | 'MEDIUM_RISK' | 'HIGH_RISK' | 'CRITICAL_RISK'
  postureLabel: string
  statusVerdict: 'PASSED' | 'REVIEW_REQUIRED' | 'ACTION_REQUIRED'
  distribution: SeverityDistribution
  confirmedCount: number
  falsePositiveCount: number
  needsReviewCount: number
  executiveBrief: string
}

export interface RuleMethodology {
  id: string
  name: string
  cwe: string
  category: string
  description: string
  sources: string[]
  sinks: string[]
  detectionStrategy: string
}

export interface Methodology {
  framework: string
  analysisType: 'Deterministic AST Taint Analysis' | 'Deterministic Multi-Branch AST Taint Analysis' | string
  description: string
  rules: RuleMethodology[]
}

export interface SecurityReport {
  schemaVersion: '1.0'
  metadata: ReportMetadata
  summary: SecuritySummary
  findings: SecurityFinding[]
  methodology: Methodology
  generatedAt: string
}
