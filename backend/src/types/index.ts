export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type VulnerabilityCategory =
  | 'xss'
  | 'command_injection'
  | 'sql_injection'
  | 'auth_bypass'
  | 'session_management'
  | 'insecure_dependency'
  | 'secret_leak'

export interface VulnerabilityResult {
  id: string
  category: VulnerabilityCategory
  title: string
  description: string
  severity: Severity
  filePath: string
  lineNumber: number
  codeSnippet?: string
  remediation?: string
}

export interface ScanRequest {
  repoUrl: string
  branch?: string
  depth?: number
}

export interface ScanReport {
  scanId: string
  repoUrl: string
  status: 'pending' | 'scanning' | 'completed' | 'failed'
  createdAt: string
  completedAt?: string
  totalVulnerabilities: number
  summary: Record<Severity, number>
  findings: VulnerabilityResult[]
}
