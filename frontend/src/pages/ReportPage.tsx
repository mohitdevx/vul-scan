import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  RiArrowLeftLine,
  RiFileTextLine,
  RiDeleteBinLine,
  RiShieldCheckLine,
  RiSearchLine,
  RiGitBranchLine,
  RiRefreshLine,
  RiGitPullRequestLine,
} from '@remixicon/react'
import { scanApi, type ScanItem, type FindingItem } from '../services/api'
import { useToast } from '../context/ToastContext'
import { useConfirm } from '../context/ConfirmContext'
import { CodeBlock } from '../components/atoms/CodeBlock'
import { FixPrModal } from '../components/organisms/FixPrModal'
import {
  generateBranchMarkdownReport,
  generateFullRepoMarkdownReport,
  downloadMarkdownFile,
} from '../utils/reportGenerator'

interface ReportPageProps {
  scanId: string
  onBack: () => void
}

interface FindingWithBranch extends FindingItem {
  branchName?: string
  sourceScanId?: string
}

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const regex = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g
  const parts = text.split(regex)

  return parts.map((part, idx) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return (
        <code
          key={idx}
          className="font-mono text-[11px] bg-zinc-900 text-zinc-200 px-1.5 py-0.5 rounded border border-zinc-800"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
      return (
        <strong key={idx} className="font-semibold text-zinc-100">
          {part.slice(2, -2)}
        </strong>
      )
    }
    if (part.startsWith('*') && part.endsWith('*') && part.length >= 2) {
      return (
        <em key={idx} className="italic text-zinc-300">
          {part.slice(1, -1)}
        </em>
      )
    }
    return part
  })
}

function MarkdownContent({ content }: { content?: string }) {
  if (!content) return null

  const rawLines = content.split('\n')
  const elements: React.ReactNode[] = []

  let i = 0
  let keyIndex = 0

  while (i < rawLines.length) {
    const rawLine = rawLines[i]

    // 1. Fenced code block (```javascript, ```typescript, ```)
    if (rawLine.trim().startsWith('```')) {
      const langMatch = rawLine.trim().match(/^```([a-zA-Z0-9_-]*)/)
      const lang = langMatch && langMatch[1] ? langMatch[1] : 'javascript'
      const codeLines: string[] = []
      i++
      while (i < rawLines.length && !rawLines[i].trim().startsWith('```')) {
        codeLines.push(rawLines[i])
        i++
      }
      i++ // skip closing fence

      elements.push(
        <div key={`code-${keyIndex++}`} className="my-3">
          <CodeBlock
            code={codeLines.join('\n')}
            language={lang}
            variant="minimal"
          />
        </div>
      )
      continue
    }

    const trimmed = rawLine.trim()

    // 2. Empty line
    if (!trimmed) {
      i++
      continue
    }

    // 3. Headings
    if (trimmed.startsWith('# ')) {
      elements.push(
        <h2
          key={`h1-${keyIndex++}`}
          className="text-sm font-semibold text-zinc-100 mt-4 mb-2 pb-1 border-b border-zinc-800/80"
        >
          {renderInlineMarkdown(trimmed.replace(/^#\s+/, ''))}
        </h2>
      )
      i++
      continue
    }
    if (trimmed.startsWith('## ')) {
      elements.push(
        <h3 key={`h2-${keyIndex++}`} className="text-sm font-semibold text-zinc-100 mt-4 mb-2">
          {renderInlineMarkdown(trimmed.replace(/^##\s+/, ''))}
        </h3>
      )
      i++
      continue
    }
    if (trimmed.startsWith('### ')) {
      elements.push(
        <h4
          key={`h3-${keyIndex++}`}
          className="text-xs font-mono font-semibold uppercase tracking-wider text-zinc-200 mt-3.5 mb-1.5"
        >
          {renderInlineMarkdown(trimmed.replace(/^###\s*/, ''))}
        </h4>
      )
      i++
      continue
    }
    if (trimmed.startsWith('#### ')) {
      elements.push(
        <h5 key={`h4-${keyIndex++}`} className="text-xs font-medium text-zinc-300 mt-3 mb-1">
          {renderInlineMarkdown(trimmed.replace(/^####\s*/, ''))}
        </h5>
      )
      i++
      continue
    }

    // 4. Blockquote / Callout (> ...)
    if (trimmed.startsWith('> ')) {
      elements.push(
        <blockquote
          key={`quote-${keyIndex++}`}
          className="border-l-2 border-zinc-700 pl-3 py-1.5 my-2 text-xs text-zinc-400 italic bg-zinc-900/40 rounded-r"
        >
          {renderInlineMarkdown(trimmed.replace(/^>\s*/, ''))}
        </blockquote>
      )
      i++
      continue
    }

    // 5. Bullet list
    if (/^[-*•]\s+/.test(trimmed)) {
      const listItems: string[] = []
      while (i < rawLines.length && /^[-*•]\s+/.test(rawLines[i].trim())) {
        listItems.push(rawLines[i].trim().replace(/^[-*•]\s+/, ''))
        i++
      }
      elements.push(
        <ul key={`ul-${keyIndex++}`} className="space-y-1.5 my-2 pl-2">
          {listItems.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-zinc-300/90 leading-relaxed">
              <span className="text-zinc-500 font-mono select-none mt-0.5">•</span>
              <span className="flex-1">{renderInlineMarkdown(item)}</span>
            </li>
          ))}
        </ul>
      )
      continue
    }

    // 6. Numbered list
    if (/^\d+\.\s+/.test(trimmed)) {
      const listItems: { num: string; text: string }[] = []
      while (i < rawLines.length && /^\d+\.\s+/.test(rawLines[i].trim())) {
        const match = rawLines[i].trim().match(/^(\d+)\.\s+(.*)$/)
        if (match) {
          listItems.push({ num: match[1], text: match[2] })
        }
        i++
      }
      elements.push(
        <ol key={`ol-${keyIndex++}`} className="space-y-1.5 my-2 pl-2">
          {listItems.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-zinc-300/90 leading-relaxed">
              <span className="text-zinc-500 font-mono text-[11px] font-semibold select-none mt-0.5 w-4 shrink-0 text-right">
                {item.num}.
              </span>
              <span className="flex-1">{renderInlineMarkdown(item.text)}</span>
            </li>
          ))}
        </ol>
      )
      continue
    }

    // 7. Regular paragraph
    const paragraphLines: string[] = []
    while (
      i < rawLines.length &&
      rawLines[i].trim() &&
      !rawLines[i].trim().startsWith('```') &&
      !rawLines[i].trim().startsWith('#') &&
      !rawLines[i].trim().startsWith('> ') &&
      !/^[-*•]\s+/.test(rawLines[i].trim()) &&
      !/^\d+\.\s+/.test(rawLines[i].trim())
    ) {
      paragraphLines.push(rawLines[i].trim())
      i++
    }

    if (paragraphLines.length > 0) {
      elements.push(
        <p
          key={`p-${keyIndex++}`}
          className="text-xs text-zinc-300/90 leading-relaxed font-sans my-1.5"
        >
          {renderInlineMarkdown(paragraphLines.join(' '))}
        </p>
      )
    }
  }

  return <div className="space-y-1">{elements}</div>
}

export function ReportPage({ scanId, onBack }: ReportPageProps) {
  const { success, error, info } = useToast()
  const { confirm } = useConfirm()

  const [loading, setLoading] = useState(true)
  const [scan, setScan] = useState<ScanItem | null>(null)
  const [allRepoScans, setAllRepoScans] = useState<ScanItem[]>([])
  const [reportMode, setReportMode] = useState<'branch' | 'full'>('branch')
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH_CRITICAL' | 'MEDIUM'>('ALL')
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CONFIRMED' | 'FALSE_POSITIVES'>('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [isRevalidating, setIsRevalidating] = useState(false)
  const [selectedFindingForFix, setSelectedFindingForFix] = useState<FindingWithBranch | null>(null)
  const [isFixModalOpen, setIsFixModalOpen] = useState(false)

  // Fetch scan details and sibling repository scans
  const loadReportData = useCallback(async () => {
    setLoading(true)
    try {
      const { scan: fetchedScan } = await scanApi.getById(scanId)
      setScan(fetchedScan)

      if (fetchedScan.repoUrl) {
        try {
          const { scans: repoScans } = await scanApi.getRepoScans(fetchedScan.repoUrl)
          setAllRepoScans(repoScans || [fetchedScan])
        } catch {
          setAllRepoScans([fetchedScan])
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load report'
      error(msg, 'Error')
    } finally {
      setLoading(false)
    }
  }, [scanId, error])

  useEffect(() => {
    loadReportData()
  }, [loadReportData])

  const handleRevalidate = async () => {
    if (!scan?.id) return
    setIsRevalidating(true)
    info('Analyzing data flow and verifying findings...', 'Verification')
    try {
      const res = await scanApi.revalidateWithAi(scan.id)
      setScan(res.scan)
      success('Verification completed for all findings', 'Complete')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to complete verification'
      error(msg, 'Verification Error')
    } finally {
      setIsRevalidating(false)
    }
  }

  // Consolidate findings based on active mode (Branch vs Full Repo)
  const displayedFindings = useMemo<FindingWithBranch[]>(() => {
    if (reportMode === 'branch') {
      return (scan?.findings || []).map(f => ({
        ...f,
        branchName: scan?.branch,
        sourceScanId: scan?.id,
      }))
    }

    const combined: FindingWithBranch[] = []
    for (const s of allRepoScans) {
      for (const f of s.findings || []) {
        combined.push({
          ...f,
          branchName: s.branch,
          sourceScanId: s.id,
        })
      }
    }
    return combined
  }, [reportMode, scan, allRepoScans])

  // Filter findings by severity, verification status, and search
  const filteredFindings = useMemo(() => {
    return displayedFindings.filter(f => {
      // Status filter
      if (statusFilter === 'CONFIRMED') {
        if (f.aiAnalysis && f.aiAnalysis.isFalsePositive) return false
      } else if (statusFilter === 'FALSE_POSITIVES') {
        if (!f.aiAnalysis?.isFalsePositive) return false
      }

      if (severityFilter === 'HIGH_CRITICAL') {
        if (f.severity !== 'HIGH' && f.severity !== 'CRITICAL') return false
      } else if (severityFilter === 'MEDIUM') {
        if (f.severity !== 'MEDIUM') return false
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const inPath = (f.filePath || '').toLowerCase().includes(q)
        const inRule = (f.ruleName || '').toLowerCase().includes(q)
        const inSink = (f.sink || '').toLowerCase().includes(q)
        const inBranch = (f.branchName || '').toLowerCase().includes(q)
        const inReason = (f.aiAnalysis?.reason || '').toLowerCase().includes(q)
        const inAnalysis = (f.aiAnalysis?.analysis || '').toLowerCase().includes(q)
        return inPath || inRule || inSink || inBranch || inReason || inAnalysis
      }

      return true
    })
  }, [displayedFindings, severityFilter, statusFilter, searchQuery])

  // Delete individual finding
  const handleDeleteFinding = async (finding: FindingWithBranch) => {
    const targetScanId = finding.sourceScanId || scan?.id
    if (!targetScanId) return

    const confirmed = await confirm({
      title: 'Dismiss Finding',
      description: `Dismiss '${finding.ruleName}' at ${finding.filePath}:${finding.line}?`,
      confirmLabel: 'Dismiss',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })

    if (!confirmed) return

    try {
      const res = await scanApi.deleteFinding(targetScanId, finding.id)
      success('Finding dismissed', 'Updated')

      if (targetScanId === scan?.id) {
        setScan(res.scan)
      }
      setAllRepoScans(prev =>
        prev.map(s => (s.id === targetScanId ? res.scan : s))
      )
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete finding'
      error(msg, 'Action Error')
    }
  }

  // Delete entire scan
  const handleDeleteScan = async () => {
    if (!scan) return

    const confirmed = await confirm({
      title: 'Delete Scan',
      description: `Permanently remove scan for '${scan.repoName}' (${scan.branch})?`,
      confirmLabel: 'Delete Scan',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })

    if (!confirmed) return

    try {
      await scanApi.delete(scan.id)
      success('Scan deleted', 'Removed')
      onBack()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete scan'
      error(msg, 'Action Error')
    }
  }

  // Handle Markdown Report Download
  const handleExportMarkdown = () => {
    if (!scan) return

    if (reportMode === 'branch') {
      const md = generateBranchMarkdownReport(scan)
      const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
      const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')
      downloadMarkdownFile(`vulscan-report-${sanitizedRepo}-${sanitizedBranch}.md`, md)
      info(`Branch report exported for ${scan.branch}`, 'Exported')
    } else {
      const md = generateFullRepoMarkdownReport(scan.repoName || scan.repoUrl, scan.repoUrl, allRepoScans)
      const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
      downloadMarkdownFile(`vulscan-full-report-${sanitizedRepo}.md`, md)
      info(`Consolidated report exported (${allRepoScans.length} branches)`, 'Exported')
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#09090b] text-zinc-100 flex items-center justify-center p-6">
        <div className="flex flex-col items-center gap-3">
          <div className="w-5 h-5 border-2 border-zinc-700 border-t-zinc-200 rounded-full animate-spin" />
          <p className="text-xs font-mono text-zinc-500">Loading audit report...</p>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-[#09090b] text-zinc-100 flex flex-col items-center justify-center p-6">
        <p className="text-sm text-zinc-400 font-mono">Scan record not found.</p>
        <button
          onClick={onBack}
          className="mt-4 px-4 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-xs text-zinc-300 hover:text-white transition-colors cursor-pointer"
        >
          Back to Dashboard
        </button>
      </div>
    )
  }

  const highCriticalCount = displayedFindings.filter(
    f => f.severity === 'HIGH' || f.severity === 'CRITICAL'
  ).length
  const mediumCount = displayedFindings.filter(f => f.severity === 'MEDIUM').length
  const totalCount = displayedFindings.length
  const verifiedCount = displayedFindings.filter(
    f => f.aiAnalysis && !f.aiAnalysis.isFalsePositive
  ).length
  const falsePositiveCount = displayedFindings.filter(
    f => f.aiAnalysis?.isFalsePositive
  ).length

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 selection:bg-rose-500/20 font-sans antialiased">
      {/* Top Header Navigation Bar */}
      <header className="sticky top-0 z-30 bg-[#09090b]/90 backdrop-blur-xl border-b border-[#27272a]/80 px-6 sm:px-8 py-3.5">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-4">
          {/* Back Action */}
          <button
            onClick={onBack}
            className="group flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-zinc-100 transition-colors cursor-pointer"
          >
            <RiArrowLeftLine className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
            <span>Dashboard</span>
          </button>

          {/* Mode Switcher (Branch vs All Branches) */}
          <div className="flex items-center gap-1 p-1 bg-[#121215] border border-zinc-800 rounded-lg text-xs font-mono">
            <button
              type="button"
              onClick={() => setReportMode('branch')}
              className={`px-3 py-1 rounded-md transition-all cursor-pointer ${
                reportMode === 'branch'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Branch ({scan.branch})
            </button>
            <button
              type="button"
              onClick={() => setReportMode('full')}
              className={`px-3 py-1 rounded-md transition-all cursor-pointer ${
                reportMode === 'full'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All Branches ({allRepoScans.length})
            </button>
          </div>

          {/* Utility Actions */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleExportMarkdown}
              className="text-xs font-mono text-zinc-300 hover:text-white bg-[#121215] border border-zinc-800 hover:bg-zinc-800 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Download markdown report"
            >
              <RiFileTextLine className="w-3.5 h-3.5 text-zinc-400" />
              <span className="hidden sm:inline">Export .md</span>
            </button>

            <button
              type="button"
              onClick={handleDeleteScan}
              title="Delete scan record"
              className="p-2 rounded-lg text-zinc-500 hover:text-rose-400 bg-[#121215] border border-zinc-800 hover:bg-zinc-800 transition-colors cursor-pointer"
            >
              <RiDeleteBinLine className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-5xl mx-auto px-6 sm:px-8 py-10">
        {/* Document Header Section */}
        <section className="mb-10">
          <div className="text-[11px] font-mono tracking-widest text-zinc-500 uppercase mb-2">
            Security Posture Audit
          </div>

          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-zinc-100 mb-3">
            {scan.repoName || scan.repoUrl}
          </h1>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-zinc-400">
            <span className="text-zinc-300 font-medium flex items-center gap-1.5">
              <RiGitBranchLine className="w-3.5 h-3.5 text-zinc-500" />
              {reportMode === 'branch' ? scan.branch : `All Branches (${allRepoScans.length})`}
            </span>
            <span className="text-zinc-700">&bull;</span>
            <span>
              {new Date(scan.createdAt).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              })}
            </span>
            <span className="text-zinc-700">&bull;</span>
            <span>AST Engine &bull; {scan.durationMs}ms</span>

            {totalCount > 0 && (
              <button
                type="button"
                onClick={handleRevalidate}
                disabled={isRevalidating}
                className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-[#121215] border border-zinc-800 text-zinc-300 hover:text-white hover:bg-zinc-800 transition-colors cursor-pointer disabled:opacity-50"
                title="Re-run data flow and security analysis"
              >
                <RiRefreshLine className={`w-3.5 h-3.5 ${isRevalidating ? 'animate-spin' : ''}`} />
                <span>{isRevalidating ? 'Analyzing...' : 'Re-verify Findings'}</span>
              </button>
            )}
          </div>

          {/* Clean Executive Summary Metric Cards */}
          {totalCount > 0 && (
            <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl bg-[#121215] border border-[#27272a]">
                <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">High / Critical</div>
                <div className="text-xl font-semibold text-rose-400 mt-1">{highCriticalCount}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#121215] border border-[#27272a]">
                <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Medium</div>
                <div className="text-xl font-semibold text-amber-400 mt-1">{mediumCount}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#121215] border border-[#27272a]">
                <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Confirmed</div>
                <div className="text-xl font-semibold text-zinc-100 mt-1">{verifiedCount}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-[#121215] border border-[#27272a]">
                <div className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">False Positives</div>
                <div className="text-xl font-semibold text-zinc-400 mt-1">{falsePositiveCount}</div>
              </div>
            </div>
          )}
        </section>

        {/* Filter Controls & Search */}
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <button
              type="button"
              onClick={() => setSeverityFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                severityFilter === 'ALL'
                  ? 'bg-zinc-800 text-zinc-100 font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              All ({displayedFindings.length})
            </button>
            <button
              type="button"
              onClick={() => setSeverityFilter('HIGH_CRITICAL')}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                severityFilter === 'HIGH_CRITICAL'
                  ? 'bg-rose-500/15 text-rose-300 font-medium'
                  : 'text-zinc-500 hover:text-rose-400'
              }`}
            >
              High/Crit ({highCriticalCount})
            </button>
            <button
              type="button"
              onClick={() => setSeverityFilter('MEDIUM')}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                severityFilter === 'MEDIUM'
                  ? 'bg-amber-500/15 text-amber-300 font-medium'
                  : 'text-zinc-500 hover:text-amber-400'
              }`}
            >
              Medium ({mediumCount})
            </button>

            <span className="text-zinc-800 mx-1">|</span>

            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'CONFIRMED' ? 'ALL' : 'CONFIRMED')}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                statusFilter === 'CONFIRMED'
                  ? 'bg-zinc-800 text-zinc-100 font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Confirmed {verifiedCount > 0 && `(${verifiedCount})`}
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'FALSE_POSITIVES' ? 'ALL' : 'FALSE_POSITIVES')}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                statusFilter === 'FALSE_POSITIVES'
                  ? 'bg-zinc-800 text-zinc-100 font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              False Positives {falsePositiveCount > 0 && `(${falsePositiveCount})`}
            </button>
          </div>

          <div className="relative w-full sm:w-64">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter findings..."
              className="w-full bg-[#121215] border border-zinc-800 pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 rounded-lg outline-none font-mono transition-colors focus:border-zinc-700"
            />
          </div>
        </div>

        {/* Findings List */}
        {filteredFindings.length === 0 ? (
          <div className="py-24 text-center rounded-xl bg-[#121215] border border-[#27272a] p-8">
            <RiShieldCheckLine className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-base font-medium text-zinc-200">
              Clean Security Posture
            </h3>
            <p className="text-xs font-mono text-zinc-500 mt-1 max-w-md mx-auto">
              {displayedFindings.length === 0
                ? `No vulnerabilities detected on branch '${scan.branch}'. All AST sinks adhere to secure code patterns.`
                : 'No vulnerabilities match your active search query or filter.'}
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {filteredFindings.map((finding, idx) => (
              <div
                key={`${finding.id}-${idx}`}
                className="rounded-xl bg-[#121215] border border-[#27272a] overflow-hidden transition-all shadow-sm"
              >
                {/* Finding Header Bar */}
                <div className="px-6 py-3.5 border-b border-[#27272a]/80 bg-[#151518]/60 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="text-xs font-mono text-zinc-500 font-medium">
                      #{String(idx + 1).padStart(2, '0')}
                    </span>
                    <span
                      className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded ${
                        finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                          ? 'text-rose-400 bg-rose-500/10 border border-rose-500/20'
                          : finding.severity === 'MEDIUM'
                          ? 'text-amber-400 bg-amber-500/10 border border-amber-500/20'
                          : 'text-zinc-400 bg-zinc-800'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs font-mono text-zinc-400 bg-zinc-900 border border-zinc-800 px-2 py-0.5 rounded">
                      {finding.cwe}
                    </span>
                    <span className="text-xs font-mono text-zinc-500">{finding.ruleId}</span>

                    {finding.aiAnalysis && (
                      <span
                        className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                          finding.aiAnalysis.isFalsePositive
                            ? 'bg-zinc-900 border-zinc-800 text-zinc-400'
                            : 'bg-zinc-800/80 border-zinc-700/60 text-zinc-300'
                        }`}
                      >
                        {finding.aiAnalysis.isFalsePositive ? 'False Positive' : 'Confirmed'}
                      </span>
                    )}

                    {reportMode === 'full' && finding.branchName && (
                      <span className="text-xs font-mono text-zinc-400 flex items-center gap-1">
                        <RiGitBranchLine className="w-3 h-3 text-zinc-500" />
                        {finding.branchName}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedFindingForFix(finding)
                        setIsFixModalOpen(true)
                      }}
                      className="inline-flex items-center gap-1.5 text-xs font-mono text-zinc-300 hover:text-emerald-400 hover:bg-zinc-800 border border-zinc-800 px-2.5 py-1 rounded transition-colors cursor-pointer"
                      title="Generate AI Fix & Send Pull Request"
                    >
                      <RiGitPullRequestLine className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Fix & PR</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => handleDeleteFinding(finding)}
                      className="text-xs font-mono text-zinc-500 hover:text-rose-400 hover:bg-zinc-800 px-2.5 py-1 rounded transition-colors cursor-pointer"
                      title="Dismiss finding"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>

                {/* Finding Content Body */}
                <div className="p-6 space-y-5">
                  <div>
                    <h2 className="text-lg font-medium text-zinc-100 tracking-tight">
                      {finding.ruleName}
                    </h2>

                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs font-mono text-zinc-400">
                      <span className="text-zinc-300">{finding.filePath}</span>
                      <span className="text-zinc-600">:</span>
                      <span className="text-rose-400 font-semibold">
                        {finding.line}:{finding.column}
                      </span>
                      <span className="text-zinc-700">&bull;</span>
                      <span className="text-zinc-500">
                        Sink:{' '}
                        <code className="text-zinc-300 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">
                          {finding.sink}
                        </code>
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-zinc-300/90 leading-relaxed font-sans max-w-4xl">
                    {finding.message}
                  </p>

                  {/* Flagged Code Block */}
                  {finding.snippet && (
                    <div>
                      <CodeBlock
                        code={finding.snippet}
                        filePath={`${finding.filePath}:${finding.line}`}
                        highlightLine={finding.line}
                        startLineNumber={Math.max(1, finding.line - 2)}
                        variant="minimal"
                      />
                    </div>
                  )}

                  {/* Deep Security & Taint Flow Analysis */}
                  {finding.aiAnalysis && (
                    <div className="bg-[#09090b] border border-[#27272a] rounded-lg p-5 space-y-4">
                      {/* Analysis Header */}
                      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#27272a]/80">
                        <div className="flex items-center gap-2 text-xs font-mono text-zinc-300 font-medium">
                          <RiShieldCheckLine className="w-4 h-4 text-zinc-400" />
                          <span className="tracking-wider uppercase">Security & Taint Analysis</span>
                        </div>

                        <div className="flex items-center gap-2">
                          {finding.aiAnalysis.sanitizerDetected && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                              Sanitizer Evaluated
                            </span>
                          )}
                          {finding.aiAnalysis.safeCastDetected && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                              Typecast Evaluated
                            </span>
                          )}
                          <span className="text-[11px] font-mono text-zinc-500">
                            {finding.aiAnalysis.confidence}% confidence
                          </span>
                        </div>
                      </div>

                      {/* AI-Generated Dynamic Markdown Advisory with Syntax Highlighting */}
                      <div className="text-xs text-zinc-300/90 leading-relaxed font-sans">
                        <MarkdownContent
                          content={finding.aiAnalysis.analysis || finding.aiAnalysis.reason}
                        />
                      </div>
                    </div>
                  )}

                  {/* Fallback Remediation if no AI analysis was run */}
                  {!finding.aiAnalysis && finding.remediation && (
                    <div className="bg-[#09090b] border border-[#27272a] rounded-lg p-4 space-y-1.5">
                      <div className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 font-medium">
                        Remediation
                      </div>
                      <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                        {finding.remediation}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      <FixPrModal
        isOpen={isFixModalOpen}
        onClose={() => {
          setIsFixModalOpen(false)
          setSelectedFindingForFix(null)
        }}
        scanId={selectedFindingForFix?.sourceScanId || scan?.id || ''}
        finding={selectedFindingForFix}
      />
    </div>
  )
}
