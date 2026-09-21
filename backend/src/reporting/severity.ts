import type { SeverityLevel, SeverityMeta, SeverityDistribution, SecuritySummary, SecurityFinding } from './types.js'

export const SEVERITY_METADATA: Record<SeverityLevel, SeverityMeta> = {
  CRITICAL: {
    level: 'CRITICAL',
    label: 'Critical',
    numericPriority: 5,
    color: '#ef4444',
    badgeBg: 'rgba(239, 68, 68, 0.12)',
    badgeBorder: 'rgba(239, 68, 68, 0.35)',
    badgeText: '#f87171',
    emoji: '',
    description: 'Directly exploitable vulnerability that can result in immediate, full compromise of the system or data integrity without prior privileges.',
  },
  HIGH: {
    level: 'HIGH',
    label: 'High',
    numericPriority: 4,
    color: '#f97316',
    badgeBg: 'rgba(249, 115, 22, 0.12)',
    badgeBorder: 'rgba(249, 115, 22, 0.35)',
    badgeText: '#fb923c',
    emoji: '',
    description: 'Vulnerability that can allow an attacker to bypass critical security controls, execute arbitrary code, or exfiltrate sensitive data.',
  },
  MEDIUM: {
    level: 'MEDIUM',
    label: 'Medium',
    numericPriority: 3,
    color: '#eab308',
    badgeBg: 'rgba(234, 179, 8, 0.12)',
    badgeBorder: 'rgba(234, 179, 8, 0.35)',
    badgeText: '#facc15',
    emoji: '',
    description: 'Condition that provides partial control, information disclosure under specific conditions, or serves as a component in an attack chain.',
  },
  LOW: {
    level: 'LOW',
    label: 'Low',
    numericPriority: 2,
    color: '#3b82f6',
    badgeBg: 'rgba(59, 130, 246, 0.12)',
    badgeBorder: 'rgba(59, 130, 246, 0.35)',
    badgeText: '#60a5fa',
    emoji: '',
    description: 'Minor divergence from security best practices with limited direct exploitability, such as verbose error exposure.',
  },
  INFO: {
    level: 'INFO',
    label: 'Info',
    numericPriority: 1,
    color: '#71717a',
    badgeBg: 'rgba(113, 113, 122, 0.12)',
    badgeBorder: 'rgba(113, 113, 122, 0.35)',
    badgeText: '#a1a1aa',
    emoji: '',
    description: 'Informational finding, architectural insight, or compliance observation with no direct security vulnerability impact.',
  },
}

export function getSeverityMeta(level: string | SeverityLevel): SeverityMeta {
  const normalized = (level || 'MEDIUM').toUpperCase() as SeverityLevel
  return SEVERITY_METADATA[normalized] || SEVERITY_METADATA.MEDIUM
}

export function compareSeverity(a: SeverityLevel, b: SeverityLevel): number {
  const priorityA = getSeverityMeta(a).numericPriority
  const priorityB = getSeverityMeta(b).numericPriority
  return priorityB - priorityA // descending priority (Critical first)
}

export function calculateDistribution(findings: Array<{ severity: string }>): SeverityDistribution {
  const dist: SeverityDistribution = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  }

  for (const f of findings) {
    const level = (f.severity || 'MEDIUM').toUpperCase() as SeverityLevel
    switch (level) {
      case 'CRITICAL':
        dist.critical++
        break
      case 'HIGH':
        dist.high++
        break
      case 'MEDIUM':
        dist.medium++
        break
      case 'LOW':
        dist.low++
        break
      case 'INFO':
      default:
        dist.info++
        break
    }
  }

  return dist
}

export function computeSummary(findings: SecurityFinding[]): SecuritySummary {
  const distribution = calculateDistribution(findings)
  const confirmedCount = findings.filter(f => f.status === 'confirmed').length
  const falsePositiveCount = findings.filter(f => f.status === 'false-positive').length
  const needsReviewCount = findings.filter(f => f.status === 'needs-review' || f.status === 'likely' || f.status === 'potential').length

  let posture: SecuritySummary['posture'] = 'CLEAN'
  let postureLabel = 'Clean Security Posture'
  let statusVerdict: SecuritySummary['statusVerdict'] = 'PASSED'
  let executiveBrief = 'Static security analysis identified zero vulnerabilities across all evaluated files.'

  if (distribution.critical > 0) {
    posture = 'CRITICAL_RISK'
    postureLabel = `${distribution.critical} Critical Vulnerability Detected`
    statusVerdict = 'ACTION_REQUIRED'
    executiveBrief = `Immediate remediation required. Identified ${distribution.critical} critical and ${distribution.high} high severity flaw(s) with unhindered source-to-sink data flow.`
  } else if (distribution.high > 0) {
    posture = 'HIGH_RISK'
    postureLabel = `${distribution.high} High-Severity Vulnerabilit${distribution.high === 1 ? 'y' : 'ies'} Detected`
    statusVerdict = 'ACTION_REQUIRED'
    executiveBrief = `Remediation required prior to production release. Flagged ${distribution.high} high severity finding(s) with direct user-controlled input reaching dangerous execution sinks.`
  } else if (distribution.medium > 0) {
    posture = 'MEDIUM_RISK'
    postureLabel = `${distribution.medium} Medium-Severity Finding${distribution.medium === 1 ? '' : 's'} Identified`
    statusVerdict = 'REVIEW_REQUIRED'
    executiveBrief = `Security review recommended. Found ${distribution.medium} medium-severity issue(s) that should be hardened according to defensive coding guidelines.`
  } else if (distribution.low > 0 || distribution.info > 0) {
    posture = 'LOW_RISK'
    postureLabel = `${distribution.low + distribution.info} Low/Informational Finding(s)`
    statusVerdict = 'REVIEW_REQUIRED'
    executiveBrief = `Minor compliance and hygiene findings observed with low direct exploitability.`
  }

  return {
    posture,
    postureLabel,
    statusVerdict,
    distribution,
    confirmedCount,
    falsePositiveCount,
    needsReviewCount,
    executiveBrief,
  }
}
