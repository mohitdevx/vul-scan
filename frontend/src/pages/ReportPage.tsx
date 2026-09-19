import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  RiArrowLeftLine,
  RiFileTextLine,
  RiDeleteBinLine,
  RiShieldCheckLine,
  RiSearchLine,
  RiGitBranchLine,
  RiBrainLine,
  RiSparklingLine,
  RiCheckDoubleLine,
  RiRefreshLine,
} from '@remixicon/react'
import { scanApi, type ScanItem, type FindingItem } from '../services/api'
import { useToast } from '../context/ToastContext'
import { useConfirm } from '../context/ConfirmContext'
import { CodeBlock } from '../components/atoms/CodeBlock'
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

export function ReportPage({ scanId, onBack }: ReportPageProps) {
  const { success, error, info } = useToast()
  const { confirm } = useConfirm()

  const [loading, setLoading] = useState(true)
  const [scan, setScan] = useState<ScanItem | null>(null)
  const [allRepoScans, setAllRepoScans] = useState<ScanItem[]>([])
  const [reportMode, setReportMode] = useState<'branch' | 'full'>('branch')
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH_CRITICAL' | 'MEDIUM'>('ALL')
  const [aiFilter, setAiFilter] = useState<'ALL' | 'CONFIRMED' | 'FALSE_POSITIVES'>('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [isRevalidating, setIsRevalidating] = useState(false)
  const [aiStatus, setAiStatus] = useState<{ available: boolean; model: string } | null>(null)

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

      // Check AI backend status
      try {
        const aiInfo = await scanApi.getAiStatus()
        setAiStatus(aiInfo)
      } catch {
        // AI status check non-blocking
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

  const handleRevalidateWithAi = async () => {
    if (!scan?.id) return
    setIsRevalidating(true)
    info('Running AI security verification with Qwen 2.5 Coder 1.5B...', 'AI Triage')
    try {
      const res = await scanApi.revalidateWithAi(scan.id)
      setScan(res.scan)
      success('AI analysis completed for all findings', 'Triage Complete')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to execute AI triage'
      error(msg, 'AI Error')
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

  // Filter findings by severity, AI triage, and search
  const filteredFindings = useMemo(() => {
    return displayedFindings.filter(f => {
      // AI filter
      if (aiFilter === 'CONFIRMED') {
        if (f.aiAnalysis && f.aiAnalysis.isFalsePositive) return false
      } else if (aiFilter === 'FALSE_POSITIVES') {
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
        const inAiReason = (f.aiAnalysis?.reason || '').toLowerCase().includes(q)
        return inPath || inRule || inSink || inBranch || inAiReason
      }

      return true
    })
  }, [displayedFindings, severityFilter, aiFilter, searchQuery])

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
          className="mt-4 px-4 py-2 bg-zinc-900 rounded-lg text-xs text-zinc-300 hover:text-white transition-colors cursor-pointer"
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
  const aiConfirmedCount = displayedFindings.filter(
    f => f.aiAnalysis && !f.aiAnalysis.isFalsePositive
  ).length
  const aiFalsePositiveCount = displayedFindings.filter(
    f => f.aiAnalysis?.isFalsePositive
  ).length

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 selection:bg-rose-500/20 font-sans antialiased">
      {/* Top Floating / Seamless Bar */}
      <header className="sticky top-0 z-30 bg-[#09090b]/90 backdrop-blur-xl px-8 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between gap-6">
          {/* Back Action */}
          <button
            onClick={onBack}
            className="group flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-zinc-100 transition-colors cursor-pointer"
          >
            <RiArrowLeftLine className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform" />
            <span>Dashboard</span>
          </button>

          {/* Mode Switcher (Branch vs All Branches) */}
          <div className="flex items-center gap-1 p-1 bg-zinc-900/60 rounded-lg text-xs font-mono">
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
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleExportMarkdown}
              className="text-xs font-mono text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900 px-2.5 py-1.5 rounded-md transition-colors flex items-center gap-1.5 cursor-pointer"
              title="Download markdown report"
            >
              <RiFileTextLine className="w-3.5 h-3.5" />
              <span>Export .md</span>
            </button>

            <button
              type="button"
              onClick={handleDeleteScan}
              title="Delete scan record"
              className="p-1.5 rounded-md text-zinc-500 hover:text-rose-400 hover:bg-zinc-900 transition-colors cursor-pointer"
            >
              <RiDeleteBinLine className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Document Content */}
      <main className="max-w-4xl mx-auto px-8 py-12">
        {/* Document Header Section */}
        <section className="mb-14">
          <div className="text-[11px] font-mono tracking-widest text-zinc-500 uppercase mb-2">
            Security Posture Audit
          </div>

          <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-zinc-100 mb-3">
            {scan.repoName || scan.repoUrl}
          </h1>

          <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-zinc-400">
            <span className="text-zinc-300 font-medium flex items-center gap-1">
              <RiGitBranchLine className="w-3.5 h-3.5 text-zinc-500" />
              {reportMode === 'branch' ? scan.branch : `All Branches (${allRepoScans.length})`}
            </span>
            <span className="text-zinc-700">&bull;</span>
            <span>{new Date(scan.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</span>
            <span className="text-zinc-700">&bull;</span>
            <span>AST Engine &bull; {scan.durationMs}ms</span>
            <span className="text-zinc-700">&bull;</span>
            <span className="flex items-center gap-1.5 text-cyan-400 font-medium">
              <RiBrainLine className="w-3.5 h-3.5" />
              <span>AI Triage: {aiStatus?.model || 'qwen2.5-coder:1.5b'}</span>
            </span>

            {totalCount > 0 && (
              <button
                type="button"
                onClick={handleRevalidateWithAi}
                disabled={isRevalidating}
                className="ml-auto inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono bg-cyan-950/40 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-900/50 hover:text-cyan-100 transition-all cursor-pointer disabled:opacity-50"
                title="Re-run AI verification with Qwen 2.5 Coder"
              >
                <RiRefreshLine className={`w-3.5 h-3.5 ${isRevalidating ? 'animate-spin' : ''}`} />
                <span>{isRevalidating ? 'Analyzing...' : 'AI Re-Verify'}</span>
              </button>
            )}
          </div>

          {/* Natural Stats Row without boxes */}
          {totalCount > 0 && (
            <div className="mt-6 flex flex-wrap items-center gap-6 text-xs font-mono">
              <div className="flex items-center gap-1.5">
                <span className="text-zinc-100 font-semibold">{highCriticalCount}</span>
                <span className="text-zinc-400">High / Critical</span>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-zinc-100 font-semibold">{mediumCount}</span>
                <span className="text-zinc-400">Medium</span>
              </div>

              {aiConfirmedCount > 0 && (
                <div className="flex items-center gap-1.5 text-rose-400">
                  <span className="font-semibold">{aiConfirmedCount}</span>
                  <span className="text-rose-400/80">AI Confirmed</span>
                </div>
              )}

              {aiFalsePositiveCount > 0 && (
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <span className="font-semibold">{aiFalsePositiveCount}</span>
                  <span className="text-emerald-400/80">AI False Positives</span>
                </div>
              )}

              <div className="flex items-center gap-1.5 text-zinc-500">
                <span>{totalCount} Total Finding{totalCount === 1 ? '' : 's'}</span>
              </div>
            </div>
          )}
        </section>

        {/* Minimal Controls: Severity Filter, AI Filter & Search */}
        <div className="mb-12 flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <button
              onClick={() => setSeverityFilter('ALL')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                severityFilter === 'ALL'
                  ? 'bg-zinc-800/80 text-zinc-100 font-medium'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              All ({displayedFindings.length})
            </button>
            <button
              onClick={() => setSeverityFilter('HIGH_CRITICAL')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                severityFilter === 'HIGH_CRITICAL'
                  ? 'bg-rose-500/15 text-rose-300 font-medium'
                  : 'text-zinc-500 hover:text-rose-400'
              }`}
            >
              High/Crit ({highCriticalCount})
            </button>
            <button
              onClick={() => setSeverityFilter('MEDIUM')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                severityFilter === 'MEDIUM'
                  ? 'bg-amber-500/15 text-amber-300 font-medium'
                  : 'text-zinc-500 hover:text-amber-400'
              }`}
            >
              Medium ({mediumCount})
            </button>

            <span className="text-zinc-700 mx-1">|</span>

            <button
              onClick={() => setAiFilter(aiFilter === 'CONFIRMED' ? 'ALL' : 'CONFIRMED')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                aiFilter === 'CONFIRMED'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-medium'
                  : 'text-zinc-500 hover:text-rose-400'
              }`}
            >
              <RiSparklingLine className="w-3 h-3" />
              <span>AI Confirmed</span>
              {aiConfirmedCount > 0 && <span className="opacity-70">({aiConfirmedCount})</span>}
            </button>
            <button
              onClick={() => setAiFilter(aiFilter === 'FALSE_POSITIVES' ? 'ALL' : 'FALSE_POSITIVES')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                aiFilter === 'FALSE_POSITIVES'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-medium'
                  : 'text-zinc-500 hover:text-emerald-400'
              }`}
            >
              <RiCheckDoubleLine className="w-3 h-3" />
              <span>False Positives</span>
              {aiFalsePositiveCount > 0 && <span className="opacity-70">({aiFalsePositiveCount})</span>}
            </button>
          </div>

          <div className="relative w-full sm:w-64">
            <RiSearchLine className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by file, sink, rule, AI..."
              className="w-full bg-zinc-900/40 hover:bg-zinc-900/70 focus:bg-zinc-900/90 pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 rounded-lg outline-none font-mono transition-all"
            />
          </div>
        </div>

        {/* Findings Stream */}
        {filteredFindings.length === 0 ? (
          <div className="py-24 text-center">
            <RiShieldCheckLine className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-base font-medium text-zinc-200">
              Clean Security Posture
            </h3>
            <p className="text-xs font-mono text-zinc-500 mt-1 max-w-md mx-auto">
              {displayedFindings.length === 0
                ? `No vulnerabilities detected on branch '${scan.branch}'. All AST sinks adhere to hardened security patterns.`
                : 'No vulnerabilities match your current search query or filter.'}
            </p>
          </div>
        ) : (
          <div className="space-y-16">
            {filteredFindings.map((finding, idx) => (
              <article key={`${finding.id}-${idx}`} className="group space-y-4">
                {/* Index and Severity Pill */}
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-zinc-600">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                    <span
                      className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded ${
                        finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                          ? 'text-rose-400 bg-rose-500/10'
                          : 'text-amber-400 bg-amber-500/10'
                      }`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs font-mono text-zinc-500">{finding.cwe}</span>
                    <span className="text-xs font-mono text-zinc-600">&bull;</span>
                    <span className="text-xs font-mono text-zinc-500">{finding.ruleId}</span>

                    {finding.aiAnalysis && (
                      <>
                        <span className="text-xs font-mono text-zinc-600">&bull;</span>
                        <span
                          className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded flex items-center gap-1 ${
                            finding.aiAnalysis.isFalsePositive
                              ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                              : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                              ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                              : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          <RiBrainLine className="w-3 h-3" />
                          <span>
                            {finding.aiAnalysis.isFalsePositive
                              ? 'AI False Positive'
                              : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                              ? 'AI Confirmed Vuln'
                              : 'AI Needs Review'}{' '}
                            ({finding.aiAnalysis.confidence}%)
                          </span>
                        </span>
                      </>
                    )}

                    {reportMode === 'full' && finding.branchName && (
                      <>
                        <span className="text-xs font-mono text-zinc-600">&bull;</span>
                        <span className="text-xs font-mono text-zinc-400 flex items-center gap-1">
                          <RiGitBranchLine className="w-3 h-3 text-zinc-500" />
                          {finding.branchName}
                        </span>
                      </>
                    )}
                  </div>

                  {/* Quiet Dismiss Action */}
                  <button
                    type="button"
                    onClick={() => handleDeleteFinding(finding)}
                    className="text-xs font-mono text-zinc-500 hover:text-rose-400 transition-colors cursor-pointer py-1 px-2 rounded hover:bg-zinc-900"
                    title="Dismiss finding"
                  >
                    Dismiss
                  </button>
                </div>

                {/* Finding Title */}
                <div>
                  <h2 className="text-xl font-medium text-zinc-100 tracking-tight">
                    {finding.ruleName}
                  </h2>

                  {/* File & Line Coordinate */}
                  <div className="mt-1 flex items-center gap-2 text-xs font-mono text-zinc-400">
                    <span className="text-zinc-300">{finding.filePath}</span>
                    <span className="text-zinc-600">:</span>
                    <span className="text-rose-400 font-semibold">{finding.line}:{finding.column}</span>
                    <span className="text-zinc-600">&bull;</span>
                    <span className="text-zinc-500">
                      Sink: <code className="text-zinc-300">{finding.sink}</code>
                    </span>
                  </div>
                </div>

                {/* Vulnerability Explanation */}
                <p className="text-sm text-zinc-300/90 leading-relaxed font-sans max-w-3xl">
                  {finding.message}
                </p>

                {/* Seamless Code Viewer */}
                {finding.snippet && (
                  <div className="pt-2">
                    <CodeBlock
                      code={finding.snippet}
                      filePath={`${finding.filePath}:${finding.line}`}
                      highlightLine={finding.line}
                      startLineNumber={Math.max(1, finding.line - 2)}
                      variant="minimal"
                    />
                  </div>
                )}

                {/* AI Business Logic Triage Callout */}
                {finding.aiAnalysis && (
                  <div
                    className={`mt-4 p-4 rounded-xl border transition-all ${
                      finding.aiAnalysis.isFalsePositive
                        ? 'bg-emerald-950/20 border-emerald-500/30'
                        : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                        ? 'bg-rose-950/20 border-rose-500/30'
                        : 'bg-amber-950/20 border-amber-500/30'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <RiBrainLine
                          className={`w-4 h-4 ${
                            finding.aiAnalysis.isFalsePositive
                              ? 'text-emerald-400'
                              : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        />
                        <span
                          className={`text-xs font-mono font-semibold uppercase tracking-wider ${
                            finding.aiAnalysis.isFalsePositive
                              ? 'text-emerald-400'
                              : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {finding.aiAnalysis.isFalsePositive
                            ? 'AI Security Verdict: False Positive'
                            : finding.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY'
                            ? 'AI Security Verdict: Confirmed Vulnerability'
                            : 'AI Security Verdict: Needs Manual Inspection'}
                        </span>
                        <span className="text-[11px] font-mono text-zinc-500">
                          &bull; {finding.aiAnalysis.confidence}% confidence &bull; {finding.aiAnalysis.model}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {finding.aiAnalysis.sanitizerDetected && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            Sanitizer Detected
                          </span>
                        )}
                        {finding.aiAnalysis.safeCastDetected && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            Safe Typecast
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed font-sans">
                      {finding.aiAnalysis.reason}
                    </p>
                  </div>
                )}

                {/* Remediation Note */}
                {(finding.aiAnalysis?.remediation || finding.remediation) && (
                  <div className="border-l-2 border-emerald-500/50 pl-4 py-0.5 mt-3">
                    <div className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-medium">
                      Remediation
                    </div>
                    <p className="text-xs text-zinc-400 leading-relaxed font-sans mt-0.5 max-w-3xl">
                      {finding.aiAnalysis?.remediation || finding.remediation}
                    </p>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
