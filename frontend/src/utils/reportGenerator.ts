/**
 * VulScan Report Generation & Download Utilities
 * Bridges the UI to the unified Security Reporting Engine.
 */

import type { ScanItem } from '../services/api'
import {
  FindingNormalizer,
  MarkdownReporter,
  HtmlReporter,
  JsonReporter,
  type RawScanInput,
  type SecurityReport,
} from '../reporting/index'

/**
 * Triggers a browser download of text data as a named file
 */
export function downloadFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8;` })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', filename)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Download as .md file
 */
export function downloadMarkdownFile(filename: string, content: string) {
  downloadFile(filename, content, 'text/markdown')
}

/**
 * Download as standalone .html file
 */
export function downloadHtmlFile(filename: string, content: string) {
  downloadFile(filename, content, 'text/html')
}

/**
 * Download as .json file
 */
export function downloadJsonFile(filename: string, content: string) {
  downloadFile(filename, content, 'application/json')
}

/**
 * Convert frontend ScanItem to canonical RawScanInput
 */
export function scanItemToRawScanInput(scan: ScanItem): RawScanInput {
  const scanAny = scan as Record<string, any>
  return {
    id: scan.id,
    repoName: scan.repoName || scan.repoUrl,
    repoUrl: scan.repoUrl,
    branch: scan.branch,
    commitSha: scanAny.commitSha,
    durationMs: scan.durationMs,
    createdAt: scan.createdAt,
    filesAnalyzed: scanAny.filesAnalyzed || (scan.findings ? Math.max(1, new Set(scan.findings.map(f => f.filePath)).size) : 1),
    rulesExecuted: scanAny.rulesExecuted || 3,
    findings: scan.findings || [],
  }
}

/**
 * Generates structured IR for a single branch scan
 */
export function generateBranchSecurityReport(scan: ScanItem): SecurityReport {
  return FindingNormalizer.normalizeScan(scanItemToRawScanInput(scan))
}

/**
 * Generates GitHub-flavored Markdown report for a branch scan
 */
export function generateBranchMarkdownReport(scan: ScanItem): string {
  const ir = generateBranchSecurityReport(scan)
  const reporter = new MarkdownReporter()
  return reporter.render(ir)
}

/**
 * Generates standalone HTML report for a branch scan
 */
export function generateBranchHtmlReport(scan: ScanItem): string {
  const ir = generateBranchSecurityReport(scan)
  const reporter = new HtmlReporter()
  return reporter.render(ir)
}

/**
 * Generates JSON schema 1.0 report for a branch scan
 */
export function generateBranchJsonReport(scan: ScanItem): string {
  const ir = generateBranchSecurityReport(scan)
  const reporter = new JsonReporter()
  return reporter.render(ir)
}

/**
 * Generates consolidated IR for an entire repository across all branches
 */
export function generateFullRepoSecurityReport(
  repoName: string,
  repoUrl: string,
  scans: ScanItem[]
): SecurityReport {
  // Filter scans belonging to this repository
  const repoScans = scans.filter(
    s => s.repoName === repoName || s.repoUrl === repoUrl
  )

  // Group latest scan per branch
  const branchMap = new Map<string, ScanItem>()
  repoScans.forEach(s => {
    const existing = branchMap.get(s.branch)
    if (!existing || new Date(s.createdAt) > new Date(existing.createdAt)) {
      branchMap.set(s.branch, s)
    }
  })

  const uniqueBranchScans = Array.from(branchMap.values())
  const rawScans = uniqueBranchScans.map(scanItemToRawScanInput)

  return FindingNormalizer.normalizeMultiBranchScan(
    repoName,
    repoUrl,
    rawScans
  )
}

/**
 * Generates consolidated Markdown report for all branches
 */
export function generateFullRepoMarkdownReport(
  repoName: string,
  repoUrl: string,
  scans: ScanItem[]
): string {
  const ir = generateFullRepoSecurityReport(repoName, repoUrl, scans)
  const reporter = new MarkdownReporter()
  return reporter.render(ir)
}

/**
 * Generates consolidated HTML report for all branches
 */
export function generateFullRepoHtmlReport(
  repoName: string,
  repoUrl: string,
  scans: ScanItem[]
): string {
  const ir = generateFullRepoSecurityReport(repoName, repoUrl, scans)
  const reporter = new HtmlReporter()
  return reporter.render(ir)
}

/**
 * Generates consolidated JSON report for all branches
 */
export function generateFullRepoJsonReport(
  repoName: string,
  repoUrl: string,
  scans: ScanItem[]
): string {
  const ir = generateFullRepoSecurityReport(repoName, repoUrl, scans)
  const reporter = new JsonReporter()
  return reporter.render(ir)
}
