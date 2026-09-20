import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  RiArrowLeftLine,
  RiFileTextLine,
  RiCodeLine,
  RiDeleteBinLine,
  RiShieldCheckLine,
  RiGitBranchLine,
  RiGitPullRequestLine,
  RiCheckLine,
  RiFileCopyLine,
  RiSparklingLine,
  RiAlertLine,
  RiInformationLine,
  RiDownloadLine,
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
  const regex = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\))/g
  const parts = text.split(regex)

  return parts.map((part, idx) => {
    // Inline code
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return (
        <code
          key={idx}
          className="font-mono text-[11px] bg-zinc-900/90 text-zinc-200 px-1.5 py-0.5 rounded border border-zinc-800"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    // Bold
    if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
      return (
        <strong key={idx} className="font-semibold text-zinc-100">
          {part.slice(2, -2)}
        </strong>
      )
    }
    // Italic
    if (part.startsWith('*') && part.endsWith('*') && part.length >= 2) {
      return (
        <em key={idx} className="italic text-zinc-300">
          {part.slice(1, -1)}
        </em>
      )
    }
    // Link [text](url)
    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/)
    if (linkMatch) {
      return (
        <a
          key={idx}
          href={linkMatch[2]}
          target="_blank"
          rel="noopener noreferrer"
          className="text-zinc-200 underline underline-offset-2 hover:text-white transition-colors"
        >
          {linkMatch[1]}
        </a>
      )
    }
    return part
  })
}

interface CompiledMarkdownReportProps {
  markdown: string
}

function CompiledMarkdownReport({ markdown }: CompiledMarkdownReportProps) {
  const rawLines = markdown.split('\n')
  const elements: React.ReactNode[] = []

  let i = 0
  let keyIndex = 0

  while (i < rawLines.length) {
    const rawLine = rawLines[i]
    const trimmed = rawLine.trim()

    // 1. Fenced code block (```javascript, ```typescript, ```)
    if (trimmed.startsWith('```')) {
      const langMatch = trimmed.match(/^```([a-zA-Z0-9_-]*)/)
      const lang = langMatch && langMatch[1] ? langMatch[1] : 'javascript'
      const codeLines: string[] = []
      i++
      while (i < rawLines.length && !rawLines[i].trim().startsWith('```')) {
        codeLines.push(rawLines[i])
        i++
      }
      i++ // skip closing fence

      elements.push(
        <div key={`code-${keyIndex++}`} className="my-4">
          <CodeBlock
            code={codeLines.join('\n')}
            language={lang}
            variant="bordered"
          />
        </div>
      )
      continue
    }

    // 2. Empty line
    if (!trimmed) {
      i++
      continue
    }

    // 3. Horizontal Rule (---, ***, ___)
    if (/^(\*\*\*|---|___)$/.test(trimmed)) {
      elements.push(
        <hr key={`hr-${keyIndex++}`} className="border-zinc-800/80 my-8" />
      )
      i++
      continue
    }

    // 4. GitHub-style Alert or Blockquote (> [!WARNING], > [!NOTE], > ...)
    if (trimmed.startsWith('>')) {
      const quoteLines: string[] = []
      while (i < rawLines.length && rawLines[i].trim().startsWith('>')) {
        quoteLines.push(rawLines[i].trim().replace(/^>\s*/, ''))
        i++
      }

      const firstLine = quoteLines[0] || ''
      let alertType: 'warning' | 'note' | 'tip' | 'quote' = 'quote'
      let cleanLines = quoteLines

      if (firstLine.includes('[!WARNING]') || firstLine.includes('[!CRITICAL]') || firstLine.includes('[!CAUTION]')) {
        alertType = 'warning'
        cleanLines = quoteLines.slice(1)
      } else if (firstLine.includes('[!NOTE]') || firstLine.includes('[!INFO]')) {
        alertType = 'note'
        cleanLines = quoteLines.slice(1)
      } else if (firstLine.includes('[!TIP]')) {
        alertType = 'tip'
        cleanLines = quoteLines.slice(1)
      }

      if (alertType === 'warning') {
        elements.push(
          <div
            key={`alert-${keyIndex++}`}
            className="my-4 p-4 rounded-xl bg-rose-500/[0.06] border border-rose-500/20 text-rose-200 text-xs leading-relaxed space-y-2"
          >
            <div className="flex items-center gap-2 font-mono font-semibold text-rose-400 text-xs uppercase tracking-wider">
              <RiAlertLine className="w-4 h-4 text-rose-400 shrink-0" />
              <span>Security Warning</span>
            </div>
            <div className="text-zinc-300 space-y-1">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx}>{renderInlineMarkdown(line)}</p>
              ))}
            </div>
          </div>
        )
      } else if (alertType === 'note') {
        elements.push(
          <div
            key={`alert-${keyIndex++}`}
            className="my-4 p-4 rounded-xl bg-emerald-500/[0.06] border border-emerald-500/20 text-emerald-200 text-xs leading-relaxed space-y-2"
          >
            <div className="flex items-center gap-2 font-mono font-semibold text-emerald-400 text-xs uppercase tracking-wider">
              <RiShieldCheckLine className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Clean Audit Posture</span>
            </div>
            <div className="text-zinc-300 space-y-1">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx}>{renderInlineMarkdown(line)}</p>
              ))}
            </div>
          </div>
        )
      } else if (alertType === 'tip') {
        elements.push(
          <div
            key={`alert-${keyIndex++}`}
            className="my-4 p-4 rounded-xl bg-cyan-500/[0.06] border border-cyan-500/20 text-cyan-200 text-xs leading-relaxed space-y-2"
          >
            <div className="flex items-center gap-2 font-mono font-semibold text-cyan-400 text-xs uppercase tracking-wider">
              <RiInformationLine className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Security Guidance</span>
            </div>
            <div className="text-zinc-300 space-y-1">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx}>{renderInlineMarkdown(line)}</p>
              ))}
            </div>
          </div>
        )
      } else {
        elements.push(
          <blockquote
            key={`quote-${keyIndex++}`}
            className="border-l-2 border-zinc-700 bg-zinc-900/40 pl-4 py-2 my-3 text-xs text-zinc-300 italic rounded-r leading-relaxed"
          >
            {quoteLines.map((line, lIdx) => (
              <p key={lIdx}>{renderInlineMarkdown(line)}</p>
            ))}
          </blockquote>
        )
      }
      continue
    }

    // 5. Markdown Tables (| Header | Header |)
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      const tableLines: string[] = []
      while (i < rawLines.length && rawLines[i].trim().startsWith('|') && rawLines[i].trim().endsWith('|')) {
        tableLines.push(rawLines[i].trim())
        i++
      }

      if (tableLines.length >= 2) {
        const headerRow = tableLines[0]
          .split('|')
          .slice(1, -1)
          .map(c => c.trim())

        const bodyRows = tableLines.slice(2).map(row =>
          row
            .split('|')
            .slice(1, -1)
            .map(c => c.trim())
        )

        elements.push(
          <div key={`table-${keyIndex++}`} className="my-5 overflow-x-auto rounded-lg border border-zinc-800/80">
            <table className="w-full text-left text-xs font-sans border-collapse">
              <thead>
                <tr className="bg-zinc-900/90 text-zinc-400 font-mono text-[11px] uppercase tracking-wider border-b border-zinc-800">
                  {headerRow.map((h, hIdx) => (
                    <th key={hIdx} className="py-2.5 px-3.5 font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-900 font-sans">
                {bodyRows.map((row, rIdx) => (
                  <tr key={rIdx} className="hover:bg-zinc-900/30 transition-colors">
                    {row.map((cell, cIdx) => (
                      <td key={cIdx} className="py-2.5 px-3.5 text-zinc-300">
                        {renderInlineMarkdown(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
        continue
      }
    }

    // 6. Headings
    if (trimmed.startsWith('# ')) {
      elements.push(
        <h1
          key={`h1-${keyIndex++}`}
          className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100 pb-3 border-b border-zinc-800/80 mb-6 mt-4"
        >
          {renderInlineMarkdown(trimmed.replace(/^#\s+/, ''))}
        </h1>
      )
      i++
      continue
    }

    if (trimmed.startsWith('## ')) {
      elements.push(
        <h2
          key={`h2-${keyIndex++}`}
          className="text-lg font-semibold tracking-tight text-zinc-100 mt-8 mb-3 pb-2 border-b border-zinc-800/60"
        >
          {renderInlineMarkdown(trimmed.replace(/^##\s+/, ''))}
        </h2>
      )
      i++
      continue
    }

    if (trimmed.startsWith('### ')) {
      elements.push(
        <h3
          key={`h3-${keyIndex++}`}
          className="text-base font-semibold text-zinc-100 tracking-tight mt-7 mb-2 pb-1.5 border-b border-zinc-800/40"
        >
          {renderInlineMarkdown(trimmed.replace(/^###\s+/, ''))}
        </h3>
      )
      i++
      continue
    }

    if (trimmed.startsWith('#### ')) {
      elements.push(
        <h4
          key={`h4-${keyIndex++}`}
          className="text-xs font-mono font-semibold uppercase tracking-wider text-zinc-400 mt-4 mb-1.5"
        >
          {renderInlineMarkdown(trimmed.replace(/^####\s+/, ''))}
        </h4>
      )
      i++
      continue
    }

    if (trimmed.startsWith('##### ')) {
      elements.push(
        <h5
          key={`h5-${keyIndex++}`}
          className="text-xs font-medium text-zinc-400 mt-3 mb-1"
        >
          {renderInlineMarkdown(trimmed.replace(/^#####\s+/, ''))}
        </h5>
      )
      i++
      continue
    }

    // 7. Bullet Lists
    if (/^[-*•]\s+/.test(trimmed)) {
      const listItems: string[] = []
      while (i < rawLines.length && /^[-*•]\s+/.test(rawLines[i].trim())) {
        listItems.push(rawLines[i].trim().replace(/^[-*•]\s+/, ''))
        i++
      }
      elements.push(
        <ul key={`ul-${keyIndex++}`} className="space-y-1.5 my-2.5 pl-1">
          {listItems.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-zinc-300 leading-relaxed">
              <span className="text-zinc-500 select-none mt-0.5">•</span>
              <span className="flex-1">{renderInlineMarkdown(item)}</span>
            </li>
          ))}
        </ul>
      )
      continue
    }

    // 8. Numbered Lists
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
        <ol key={`ol-${keyIndex++}`} className="space-y-1.5 my-2.5 pl-1">
          {listItems.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-zinc-300 leading-relaxed">
              <span className="text-zinc-500 font-mono text-[11px] select-none mt-0.5 w-4 shrink-0 text-right">
                {item.num}.
              </span>
              <span className="flex-1">{renderInlineMarkdown(item.text)}</span>
            </li>
          ))}
        </ol>
      )
      continue
    }

    // 9. Regular paragraph
    const paragraphLines: string[] = []
    while (
      i < rawLines.length &&
      rawLines[i].trim() &&
      !rawLines[i].trim().startsWith('```') &&
      !rawLines[i].trim().startsWith('#') &&
      !rawLines[i].trim().startsWith('>') &&
      !rawLines[i].trim().startsWith('|') &&
      !/^(\*\*\*|---|___)$/.test(rawLines[i].trim()) &&
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
          className="text-xs sm:text-sm text-zinc-300 leading-relaxed font-sans my-2"
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
  const [viewMode, setViewMode] = useState<'rendered' | 'raw'>('rendered')
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH_CRITICAL' | 'MEDIUM'>('ALL')
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CONFIRMED' | 'FALSE_POSITIVES'>('ALL')
  const [isRevalidating, setIsRevalidating] = useState(false)
  const [selectedFindingForFix, setSelectedFindingForFix] = useState<FindingWithBranch | null>(null)
  const [isFixModalOpen, setIsFixModalOpen] = useState(false)
  const [copiedMd, setCopiedMd] = useState(false)

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

  // Filter findings by severity and verification status
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

      return true
    })
  }, [displayedFindings, severityFilter, statusFilter])

  // Dynamically generate markdown string for active view & filters
  const reportMarkdown = useMemo(() => {
    if (!scan) return ''

    if (reportMode === 'branch') {
      const filteredScan: ScanItem = {
        ...scan,
        findings: filteredFindings,
        findingsCount: filteredFindings.length,
        highCount: filteredFindings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length,
        mediumCount: filteredFindings.filter(f => f.severity === 'MEDIUM').length,
        lowCount: filteredFindings.filter(f => f.severity === 'LOW').length,
      }
      return generateBranchMarkdownReport(filteredScan)
    } else {
      return generateFullRepoMarkdownReport(
        scan.repoName || scan.repoUrl,
        scan.repoUrl,
        allRepoScans
      )
    }
  }, [reportMode, scan, filteredFindings, allRepoScans])

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

    const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
    if (reportMode === 'branch') {
      const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')
      downloadMarkdownFile(`vulscan-report-${sanitizedRepo}-${sanitizedBranch}.md`, reportMarkdown)
      info(`Branch report exported for ${scan.branch}`, 'Exported')
    } else {
      downloadMarkdownFile(`vulscan-full-report-${sanitizedRepo}.md`, reportMarkdown)
      info(`Consolidated report exported (${allRepoScans.length} branches)`, 'Exported')
    }
  }

  // Copy raw markdown to clipboard
  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(reportMarkdown)
    setCopiedMd(true)
    setTimeout(() => setCopiedMd(false), 2000)
    success('Markdown report copied to clipboard', 'Copied')
  }

  // Handle Fix & PR trigger from toolbar
  const handleOpenFixModal = () => {
    const target = filteredFindings[0] || displayedFindings[0]
    if (target) {
      setSelectedFindingForFix(target)
      setIsFixModalOpen(true)
    } else {
      info('No security findings available to remediate.', 'Info')
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#09090b] text-zinc-100 flex items-center justify-center p-6">
        <div className="flex flex-col items-center gap-3">
          <div className="w-5 h-5 border-2 border-zinc-700 border-t-zinc-200 rounded-full animate-spin" />
          <p className="text-xs font-mono text-zinc-500">Compiling security audit report...</p>
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
    <div className="min-h-screen bg-[#09090b] text-zinc-100 selection:bg-rose-500/20 font-sans antialiased flex flex-col">
      {/* Top Sticky Header */}
      <header className="sticky top-0 z-30 bg-[#09090b]/90 backdrop-blur-xl border-b border-zinc-800/80 px-4 sm:px-8 py-3">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-4">
          {/* Breadcrumb Navigation */}
          <div className="flex items-center gap-2.5 text-xs font-mono min-w-0">
            <button
              onClick={onBack}
              className="group flex items-center gap-1.5 text-zinc-400 hover:text-zinc-100 transition-colors cursor-pointer shrink-0"
            >
              <RiArrowLeftLine className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
              <span>Dashboard</span>
            </button>
            <span className="text-zinc-700 select-none">/</span>
            <span className="text-zinc-200 font-medium truncate">
              {scan.repoName || scan.repoUrl}
            </span>
          </div>

          {/* Mode Switcher (Branch vs All Branches) */}
          <div className="flex items-center gap-1 p-0.5 bg-zinc-900/90 border border-zinc-800/80 rounded-lg text-xs font-mono">
            <button
              type="button"
              onClick={() => setReportMode('branch')}
              className={`px-3 py-1 rounded-md transition-all cursor-pointer flex items-center gap-1.5 ${
                reportMode === 'branch'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <RiGitBranchLine className="w-3.5 h-3.5 text-zinc-400" />
              <span>Branch ({scan.branch})</span>
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

          {/* Action Tools */}
          <div className="flex items-center gap-2 shrink-0">
            {/* View Mode Toggle: HTML Report vs Raw Markdown */}
            <div className="flex items-center gap-0.5 bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs font-mono">
              <button
                type="button"
                onClick={() => setViewMode('rendered')}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                  viewMode === 'rendered'
                    ? 'bg-zinc-800 text-zinc-100 font-medium'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="View formatted HTML report"
              >
                <RiFileTextLine className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Report</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('raw')}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                  viewMode === 'raw'
                    ? 'bg-zinc-800 text-zinc-100 font-medium'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
                title="View raw Markdown source"
              >
                <RiCodeLine className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Raw .md</span>
              </button>
            </div>

            {totalCount > 0 && (
              <button
                type="button"
                onClick={handleRevalidate}
                disabled={isRevalidating}
                className="hidden md:inline-flex items-center gap-1.5 text-xs font-mono text-zinc-300 hover:text-white bg-zinc-900/80 border border-zinc-800 hover:bg-zinc-800 px-3 py-1.5 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                title="Re-run taint flow analysis and AI verification"
              >
                <RiSparklingLine className={`w-3.5 h-3.5 text-zinc-400 ${isRevalidating ? 'animate-spin' : ''}`} />
                <span>{isRevalidating ? 'Analyzing...' : 'Re-verify'}</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleExportMarkdown}
              className="text-xs font-mono text-zinc-300 hover:text-white bg-zinc-900/80 border border-zinc-800 hover:bg-zinc-800 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Download markdown report file"
            >
              <RiDownloadLine className="w-3.5 h-3.5 text-zinc-400" />
              <span className="hidden lg:inline">Export</span>
            </button>

            <button
              type="button"
              onClick={handleDeleteScan}
              title="Delete scan record"
              className="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-zinc-800/80 transition-colors cursor-pointer"
            >
              <RiDeleteBinLine className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Full-Width Document Body */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-6 sm:px-12 py-8 space-y-8">
        {/* Document Top Action & Filter Ribbon (Naturally spaced with breathing room) */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-zinc-800/60">
          {/* Segmented Filter Control */}
          <div className="flex flex-wrap items-center gap-1 p-1 bg-zinc-900/80 border border-zinc-800/80 rounded-xl text-xs font-mono">
            <button
              type="button"
              onClick={() => setSeverityFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                severityFilter === 'ALL'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All ({displayedFindings.length})
            </button>
            <button
              type="button"
              onClick={() => setSeverityFilter('HIGH_CRITICAL')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                severityFilter === 'HIGH_CRITICAL'
                  ? 'bg-rose-500/15 text-rose-300 font-medium border border-rose-500/30 shadow-sm'
                  : 'text-zinc-400 hover:text-rose-400'
              }`}
            >
              High/Crit ({highCriticalCount})
            </button>
            <button
              type="button"
              onClick={() => setSeverityFilter('MEDIUM')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                severityFilter === 'MEDIUM'
                  ? 'bg-amber-500/15 text-amber-300 font-medium border border-amber-500/30 shadow-sm'
                  : 'text-zinc-400 hover:text-amber-400'
              }`}
            >
              Medium ({mediumCount})
            </button>

            <div className="w-px h-4 bg-zinc-800 mx-1" />

            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'CONFIRMED' ? 'ALL' : 'CONFIRMED')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                statusFilter === 'CONFIRMED'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Confirmed ({verifiedCount})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'FALSE_POSITIVES' ? 'ALL' : 'FALSE_POSITIVES')}
              className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                statusFilter === 'FALSE_POSITIVES'
                  ? 'bg-zinc-800 text-zinc-100 font-medium shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              False Positives ({falsePositiveCount})
            </button>
          </div>

          {/* Prominent Fix & PR Button */}
          {totalCount > 0 && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleOpenFixModal}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold shadow-md hover:shadow-emerald-500/10 transition-all cursor-pointer"
                title="Generate AI security fix and open Pull Request on GitHub"
              >
                <RiGitPullRequestLine className="w-4 h-4" />
                <span>Fix & PR</span>
              </button>
            </div>
          )}
        </div>

        {/* Document Content View */}
        {viewMode === 'rendered' ? (
          /* Publication-Grade Compiled HTML Report */
          <article className="prose prose-invert max-w-none">
            <CompiledMarkdownReport markdown={reportMarkdown} />
          </article>
        ) : (
          /* Raw Markdown Source View with Copy Action */
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
              <div className="text-xs font-mono text-zinc-400 flex items-center gap-2">
                <RiCodeLine className="w-4 h-4 text-zinc-500" />
                <span>Raw Markdown Source ({reportMarkdown.length} characters)</span>
              </div>
              <button
                type="button"
                onClick={handleCopyMarkdown}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono transition-colors cursor-pointer"
              >
                {copiedMd ? (
                  <>
                    <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <RiFileCopyLine className="w-3.5 h-3.5" />
                    <span>Copy Raw Markdown</span>
                  </>
                )}
              </button>
            </div>

            <pre className="p-5 rounded-xl bg-[#121215] border border-zinc-800 text-zinc-300 font-mono text-xs whitespace-pre-wrap leading-relaxed overflow-x-auto selection:bg-rose-500/20">
              {reportMarkdown}
            </pre>
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
