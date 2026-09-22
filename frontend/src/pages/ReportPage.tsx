import React, { useState, useEffect, useCallback, useMemo } from 'react'
import {
  RiArrowLeftLine,
  RiDeleteBinLine,
  RiShieldCheckLine,
  RiGitBranchLine,
  RiGitPullRequestLine,
  RiCheckLine,
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
import { Navbar } from '../components/organisms/Navbar'
import { Button } from '../components/atoms/Button'
import {
  generateBranchMarkdownReport,
  generateBranchHtmlReport,
  generateBranchJsonReport,
  generateFullRepoMarkdownReport,
  generateFullRepoHtmlReport,
  generateFullRepoJsonReport,
  downloadMarkdownFile,
  downloadHtmlFile,
  downloadJsonFile,
} from '../utils/reportGenerator'

interface ReportPageProps {
  scanId: string
  onBack: () => void
  onNavigate?: (view: 'home' | 'dashboard' | 'profile') => void
}

interface FindingWithBranch extends FindingItem {
  branchName?: string
  sourceScanId?: string
}

function decodeEntities(str: string): string {
  return str
    .replace(/&nbsp;/g, ' ')
    .replace(/&mdash;/g, '—')
    .replace(/&ndash;/g, '–')
    .replace(/&bull;/g, '•')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
}

function renderInlineMarkdown(rawText: string): React.ReactNode[] {
  if (!rawText) return []

  const text = decodeEntities(rawText)

  // Tokenize code, bold, italic, links, HTML anchors, HTML tags, severity badges
  const tokenRegex = /(<a\s+[^>]*>.*?<\/a>|<a\s+[^>]*\/>|<a\s+[^>]*>|<\/a>|<span\s*[^>]*>.*?<\/span>|<code\s*[^>]*>.*?<\/code>|<kbd\s*[^>]*>.*?<\/kbd>|<mark\s*[^>]*>.*?<\/mark>|<br\s*\/?>|<[^>]+>|`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\)|\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\])/gi

  const parts = text.split(tokenRegex)
  const result: React.ReactNode[] = []

  for (let idx = 0; idx < parts.length; idx++) {
    const part = parts[idx]
    if (!part) continue

    // 1. Inline code `code`
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      result.push(
        <code
          key={`code-${idx}`}
          className="font-mono text-[11px] bg-zinc-900/90 text-zinc-200 px-1.5 py-0.5 rounded border border-zinc-800"
        >
          {part.slice(1, -1)}
        </code>
      )
      continue
    }

    // 2. Bold **text**
    if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
      result.push(
        <strong key={`bold-${idx}`} className="font-semibold text-zinc-100">
          {renderInlineMarkdown(part.slice(2, -2))}
        </strong>
      )
      continue
    }

    // 3. Italic *text*
    if (part.startsWith('*') && part.endsWith('*') && part.length >= 2) {
      result.push(
        <em key={`italic-${idx}`} className="italic text-zinc-300">
          {renderInlineMarkdown(part.slice(1, -1))}
        </em>
      )
      continue
    }

    // 4. Markdown link [text](url)
    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/)
    if (linkMatch) {
      const isAnchor = linkMatch[2].startsWith('#')
      result.push(
        <a
          key={`link-${idx}`}
          href={linkMatch[2]}
          target={isAnchor ? undefined : '_blank'}
          rel={isAnchor ? undefined : 'noopener noreferrer'}
          className="text-zinc-200 underline underline-offset-2 hover:text-white transition-colors cursor-pointer"
        >
          {renderInlineMarkdown(linkMatch[1])}
        </a>
      )
      continue
    }

    // 5. HTML anchor <a ...>...</a>
    const htmlAnchorMatch = part.match(/^<a\s+([^>]*?)>(.*?)<\/a>$/i)
    if (htmlAnchorMatch) {
      const attrs = htmlAnchorMatch[1]
      const innerContent = htmlAnchorMatch[2]
      const idMatch = attrs.match(/(?:id|name)=["']([^"']+)["']/i)
      const hrefMatch = attrs.match(/href=["']([^"']+)["']/i)

      if (hrefMatch) {
        result.push(
          <a
            key={`a-${idx}`}
            id={idMatch ? idMatch[1] : undefined}
            href={hrefMatch[1]}
            target="_blank"
            rel="noopener noreferrer"
            className="text-zinc-200 underline underline-offset-2 hover:text-white transition-colors cursor-pointer"
          >
            {renderInlineMarkdown(innerContent)}
          </a>
        )
      } else if (idMatch) {
        result.push(
          <span key={`a-id-${idx}`} id={idMatch[1]} className="scroll-mt-20">
            {renderInlineMarkdown(innerContent)}
          </span>
        )
      } else if (innerContent) {
        result.push(...renderInlineMarkdown(innerContent))
      }
      continue
    }

    // 6. Solo/Opening anchor <a id="...">
    const soloAnchorMatch = part.match(/^<a\s+(?:id|name)=["']([^"']+)["'][^>]*\/?>$/i)
    if (soloAnchorMatch) {
      result.push(<span key={`anchor-${idx}`} id={soloAnchorMatch[1]} className="scroll-mt-20" />)
      continue
    }

    // 7. Closing </a>
    if (/^<\/a>$/i.test(part)) {
      continue
    }

    // 8. HTML <code>...</code>
    const htmlCodeMatch = part.match(/^<code(?:\s+[^>]*)?>([\s\S]*?)<\/code>$/i)
    if (htmlCodeMatch) {
      result.push(
        <code
          key={`code-tag-${idx}`}
          className="font-mono text-[11px] bg-zinc-900/90 text-zinc-200 px-1.5 py-0.5 rounded border border-zinc-800"
        >
          {htmlCodeMatch[1]}
        </code>
      )
      continue
    }

    // 9. HTML <span>...</span>
    const htmlSpanMatch = part.match(/^<span(?:\s+[^>]*)?>([\s\S]*?)<\/span>$/i)
    if (htmlSpanMatch) {
      result.push(<span key={`span-${idx}`}>{renderInlineMarkdown(htmlSpanMatch[1])}</span>)
      continue
    }

    // 10. Line breaks <br> / <br/>
    if (/^<br\s*\/?>$/i.test(part)) {
      result.push(<br key={`br-${idx}`} />)
      continue
    }

    // 11. Any other stray HTML tag
    if (/^<[^>]+>$/.test(part)) {
      continue
    }

    // 12. Styled severity token [CRITICAL], [HIGH], [MEDIUM], [LOW], [INFO]
    const badgeMatch = part.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]$/i)
    if (badgeMatch) {
      const sev = badgeMatch[1].toUpperCase()
      const colorCls =
        sev === 'CRITICAL'
          ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
          : sev === 'HIGH'
          ? 'bg-orange-500/15 text-orange-300 border-orange-500/30'
          : sev === 'MEDIUM'
          ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
          : sev === 'LOW'
          ? 'bg-blue-500/15 text-blue-300 border-blue-500/30'
          : 'bg-zinc-800 text-zinc-400 border-zinc-700'

      result.push(
        <span
          key={`badge-${idx}`}
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border ${colorCls} mr-1.5 select-none`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-current" />
          {sev}
        </span>
      )
      continue
    }

    // 13. Plain text
    result.push(part)
  }

  return result
}

interface CompiledMarkdownReportProps {
  markdown: string
}

function CompiledMarkdownReport({ markdown }: CompiledMarkdownReportProps) {
  if (!markdown) return null

  const rawLines = markdown.split('\n')
  const elements: React.ReactNode[] = []

  let i = 0
  let keyIndex = 0

  while (i < rawLines.length) {
    const startI = i
    const rawLine = rawLines[i]
    const trimmed = rawLine.trim()

    // 1. Empty lines
    if (!trimmed) {
      i++
      continue
    }

    // 2. Fenced code block (```javascript, ```typescript, ```)
    if (trimmed.startsWith('```')) {
      const langMatch = trimmed.match(/^```([a-zA-Z0-9_-]*)/)
      const lang = langMatch && langMatch[1] ? langMatch[1] : 'javascript'
      const codeLines: string[] = []
      i++
      while (i < rawLines.length && !rawLines[i].trim().startsWith('```')) {
        codeLines.push(rawLines[i])
        i++
      }
      if (i < rawLines.length && rawLines[i].trim().startsWith('```')) {
        i++ // skip closing fence
      }

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
            className="my-4 p-4 rounded-lg bg-rose-500/[0.04] border border-rose-500/20 text-text-primary text-xs leading-relaxed flex items-start gap-3"
          >
            <RiAlertLine className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1 flex-1 text-text-secondary">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx} className={lIdx === 0 ? 'font-medium text-text-primary' : ''}>
                  {renderInlineMarkdown(line)}
                </p>
              ))}
            </div>
          </div>
        )
      } else if (alertType === 'note') {
        elements.push(
          <div
            key={`alert-${keyIndex++}`}
            className="my-4 p-4 rounded-lg bg-emerald-500/[0.04] border border-emerald-500/20 text-text-primary text-xs leading-relaxed flex items-start gap-3"
          >
            <RiShieldCheckLine className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="space-y-1 flex-1 text-text-secondary">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx} className={lIdx === 0 ? 'font-medium text-text-primary' : ''}>
                  {renderInlineMarkdown(line)}
                </p>
              ))}
            </div>
          </div>
        )
      } else if (alertType === 'tip') {
        elements.push(
          <div
            key={`alert-${keyIndex++}`}
            className="my-4 p-4 rounded-lg bg-cyan-500/[0.04] border border-cyan-500/20 text-text-primary text-xs leading-relaxed flex items-start gap-3"
          >
            <RiInformationLine className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-1 flex-1 text-text-secondary">
              {cleanLines.map((line, lIdx) => (
                <p key={lIdx} className={lIdx === 0 ? 'font-medium text-text-primary' : ''}>
                  {renderInlineMarkdown(line)}
                </p>
              ))}
            </div>
          </div>
        )
      } else {
        elements.push(
          <blockquote
            key={`quote-${keyIndex++}`}
            className="border-l-2 border-border-subtle bg-surface/30 pl-4 py-2 my-3 text-xs text-text-secondary italic rounded-r leading-relaxed"
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
    if (trimmed.startsWith('|')) {
      const tableLines: string[] = []
      while (i < rawLines.length && rawLines[i].trim().startsWith('|')) {
        tableLines.push(rawLines[i].trim())
        i++
      }

      if (tableLines.length >= 2) {
        const headerRow = tableLines[0]
          .split('|')
          .slice(1, tableLines[0].endsWith('|') ? -1 : undefined)
          .map(c => c.trim())

        // Skip separator line (|---|---|) if present
        const startBodyIdx = tableLines.length > 1 && /^\|?\s*[-:]+[-| :]*\|?$/.test(tableLines[1]) ? 2 : 1
        const bodyRows = tableLines.slice(startBodyIdx).map(row =>
          row
            .split('|')
            .slice(1, row.endsWith('|') ? -1 : undefined)
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
      }
      continue
    }

    // 6. Headings (# -> ######)
    const headingMatch = trimmed.match(/^(#{1,6})\s+(.*)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const headingRaw = headingMatch[2]
      const anchorMatch = headingRaw.match(/(?:id|name)=["']([^"']+)["']/i)
      const cleanHeading = headingRaw.replace(/<a\s+[^>]*>.*?<\/a>|<a\s+[^>]*\/?>|<\/a>/gi, '').trim()
      const slugId = anchorMatch ? anchorMatch[1] : cleanHeading.toLowerCase().replace(/[^a-z0-9_-]+/g, '-')

      if (level === 1) {
        elements.push(
          <h1
            key={`h1-${keyIndex++}`}
            id={slugId}
            className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100 pb-3 border-b border-zinc-800/80 mb-6 mt-4 flex items-center gap-3"
          >
            <RiShieldCheckLine className="w-6 h-6 text-rose-400 shrink-0" />
            <span>{renderInlineMarkdown(cleanHeading)}</span>
          </h1>
        )
      } else if (level === 2) {
        elements.push(
          <h2
            key={`h2-${keyIndex++}`}
            id={slugId}
            className="text-lg font-semibold tracking-tight text-zinc-100 mt-8 mb-3 pb-2 border-b border-zinc-800/60 scroll-mt-20 flex items-center gap-2"
          >
            {renderInlineMarkdown(cleanHeading)}
          </h2>
        )
      } else if (level === 3) {
        elements.push(
          <h3
            key={`h3-${keyIndex++}`}
            id={slugId}
            className="text-base font-semibold text-zinc-100 tracking-tight mt-7 mb-2 pb-1.5 border-b border-zinc-800/40 scroll-mt-20 flex flex-wrap items-center gap-2"
          >
            {renderInlineMarkdown(cleanHeading)}
          </h3>
        )
      } else if (level === 4) {
        elements.push(
          <h4
            key={`h4-${keyIndex++}`}
            className="text-xs font-mono font-semibold uppercase tracking-wider text-zinc-400 mt-5 mb-1.5 flex items-center gap-1.5"
          >
            {renderInlineMarkdown(cleanHeading)}
          </h4>
        )
      } else {
        elements.push(
          <h5
            key={`h5-${keyIndex++}`}
            className="text-xs font-medium text-zinc-400 mt-3 mb-1"
          >
            {renderInlineMarkdown(cleanHeading)}
          </h5>
        )
      }
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

    // 9. Regular paragraph (groups consecutive non-empty lines)
    const paragraphLines: string[] = []
    while (
      i < rawLines.length &&
      rawLines[i].trim() &&
      !rawLines[i].trim().startsWith('```') &&
      !rawLines[i].trim().match(/^#{1,6}\s+/) &&
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

    // Safety fallback: guarantee loop advances if no rule matched
    if (i === startI) {
      elements.push(
        <p
          key={`p-fallback-${keyIndex++}`}
          className="text-xs sm:text-sm text-zinc-300 leading-relaxed font-sans my-2"
        >
          {renderInlineMarkdown(rawLines[i])}
        </p>
      )
      i++
    }
  }

  return <div className="space-y-1">{elements}</div>
}

export function ReportPage({ scanId, onBack, onNavigate }: ReportPageProps) {
  const { success, error, info } = useToast()
  const { confirm } = useConfirm()

  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [scan, setScan] = useState<ScanItem | null>(null)
  const [allRepoScans, setAllRepoScans] = useState<ScanItem[]>([])
  const [reportMode, setReportMode] = useState<'branch' | 'full'>('branch')
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'HIGH_CRITICAL' | 'MEDIUM'>('ALL')
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CONFIRMED' | 'FALSE_POSITIVES'>('ALL')
  const [isRevalidating, setIsRevalidating] = useState(false)
  const [selectedFindingForFix, setSelectedFindingForFix] = useState<FindingWithBranch | null>(null)
  const [isFixModalOpen, setIsFixModalOpen] = useState(false)
  const [exportMenuOpen, setExportMenuOpen] = useState(false)
  
  // Persistent tracking of created PRs across browser reloads
  const [sentPrs, setSentPrs] = useState<Record<string, { prNumber: number; prUrl: string }>>(() => {
    try {
      const saved = localStorage.getItem(`vulscan_sent_prs_${scanId}`)
      return saved ? JSON.parse(saved) : {}
    } catch {
      return {}
    }
  })

  // Fetch scan details and sibling repository scans
  const loadReportData = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const { scan: fetchedScan } = await scanApi.getById(scanId)
      setScan(fetchedScan)

      // Merge any PRs recorded in database findings with local state
      if (fetchedScan.findings) {
        const fromDb: Record<string, { prNumber: number; prUrl: string }> = {}
        fetchedScan.findings.forEach(f => {
          if (f.pr) {
            fromDb[f.id] = { prNumber: f.pr.prNumber, prUrl: f.pr.prUrl }
          }
        })
        if (Object.keys(fromDb).length > 0) {
          setSentPrs(prev => {
            const merged = { ...prev, ...fromDb }
            try {
              localStorage.setItem(`vulscan_sent_prs_${scanId}`, JSON.stringify(merged))
            } catch {}
            return merged
          })
        }
      }

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
      setLoadError(msg)
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
      info(`Branch report exported as Markdown for ${scan.branch}`, 'Exported')
    } else {
      downloadMarkdownFile(`vulscan-full-report-${sanitizedRepo}.md`, reportMarkdown)
      info(`Consolidated report exported as Markdown (${allRepoScans.length} branches)`, 'Exported')
    }
    setExportMenuOpen(false)
  }

  // Handle Standalone HTML Report Download
  const handleExportHtml = () => {
    if (!scan) return

    const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
    if (reportMode === 'branch') {
      const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')
      const html = generateBranchHtmlReport(scan)
      downloadHtmlFile(`vulscan-report-${sanitizedRepo}-${sanitizedBranch}.html`, html)
      info(`Branch report exported as standalone HTML for ${scan.branch}`, 'Exported')
    } else {
      const html = generateFullRepoHtmlReport(scan.repoName || scan.repoUrl, scan.repoUrl, allRepoScans)
      downloadHtmlFile(`vulscan-full-report-${sanitizedRepo}.html`, html)
      info(`Consolidated report exported as standalone HTML (${allRepoScans.length} branches)`, 'Exported')
    }
    setExportMenuOpen(false)
  }

  // Handle JSON Report Download
  const handleExportJson = () => {
    if (!scan) return

    const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
    if (reportMode === 'branch') {
      const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')
      const json = generateBranchJsonReport(scan)
      downloadJsonFile(`vulscan-report-${sanitizedRepo}-${sanitizedBranch}.json`, json)
      info(`Branch report exported as JSON for ${scan.branch}`, 'Exported')
    } else {
      const json = generateFullRepoJsonReport(scan.repoName || scan.repoUrl, scan.repoUrl, allRepoScans)
      downloadJsonFile(`vulscan-full-report-${sanitizedRepo}.json`, json)
      info(`Consolidated report exported as JSON (${allRepoScans.length} branches)`, 'Exported')
    }
    setExportMenuOpen(false)
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
      <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
        <Navbar onNavigate={onNavigate || (() => onBack())} currentView="report" />
        <div className="flex-1 flex flex-col items-center justify-center gap-3">
          <div className="w-5 h-5 border-2 border-border border-t-text-primary rounded-full animate-spin" />
          <span className="text-xs font-mono text-text-muted">Loading security audit report...</span>
        </div>
      </div>
    )
  }

  if (loadError) {
    return (
      <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
        <Navbar onNavigate={onNavigate || (() => onBack())} currentView="report" />
        <div className="flex-1 flex flex-col items-center justify-center p-6 space-y-4">
          <div className="p-5 rounded-lg bg-danger/10 border border-danger/20 text-danger max-w-md text-center space-y-2">
            <div className="flex items-center justify-center gap-2 font-medium text-sm">
              <RiAlertLine className="w-4 h-4" />
              <span>Unable to load scan report</span>
            </div>
            <p className="text-xs text-text-muted font-mono">{loadError}</p>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="secondary" size="sm" onClick={() => loadReportData()}>
              Retry
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onBack}
              icon={<RiArrowLeftLine className="w-3.5 h-3.5" />}
            >
              Back to Dashboard
            </Button>
          </div>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
        <Navbar onNavigate={onNavigate || (() => onBack())} currentView="report" />
        <div className="flex-1 flex flex-col items-center justify-center p-6 text-center space-y-4">
          <p className="text-sm text-text-secondary font-mono">Scan record not found or has been deleted.</p>
          <Button
            variant="outline"
            size="sm"
            onClick={onBack}
            icon={<RiArrowLeftLine className="w-3.5 h-3.5" />}
          >
            Back to Dashboard
          </Button>
        </div>
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
    <div className="min-h-screen bg-canvas text-text-primary selection:bg-rose-500/20 font-sans antialiased flex flex-col">
      {/* Primary Application Navbar */}
      <Navbar onNavigate={onNavigate || (() => onBack())} currentView="report" />

      {/* Main Document Container with generous spacing from navbar */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-6 sm:px-12 pt-8 pb-16 space-y-8">
        {/* Report Top Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-border-subtle">
          {/* Branch Switcher Underline Tabs */}
          <div className="flex items-center gap-6 text-xs font-mono">
            <button
              type="button"
              onClick={() => setReportMode('branch')}
              className={`inline-flex items-center gap-1.5 pb-2 -mb-[13px] transition-colors cursor-pointer border-b-2 ${
                reportMode === 'branch'
                  ? 'border-text-primary text-text-primary font-medium'
                  : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
            >
              <RiGitBranchLine className="w-3.5 h-3.5 text-text-muted shrink-0" />
              <span>{scan.branch}</span>
            </button>
            <button
              type="button"
              onClick={() => setReportMode('full')}
              className={`inline-flex items-center gap-1.5 pb-2 -mb-[13px] transition-colors cursor-pointer border-b-2 ${
                reportMode === 'full'
                  ? 'border-text-primary text-text-primary font-medium'
                  : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
            >
              <span>All Branches</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono leading-none ${
                reportMode === 'full' ? 'bg-surface-muted text-text-primary' : 'bg-surface text-text-muted border border-border-subtle'
              }`}>
                {allRepoScans.length}
              </span>
            </button>
          </div>

          {/* Action Tools */}
          <div className="flex items-center gap-3 text-xs font-mono shrink-0">
            <button
              type="button"
              onClick={handleRevalidate}
              disabled={isRevalidating}
              className="inline-flex items-center gap-1.5 py-1 px-2 rounded text-text-muted hover:text-text-primary hover:bg-surface transition-colors cursor-pointer disabled:opacity-50"
              title="Re-run taint flow analysis and verification"
            >
              <RiSparklingLine className={`w-3.5 h-3.5 shrink-0 ${isRevalidating ? 'animate-spin' : ''}`} />
              <span>Re-verify</span>
            </button>

            {/* Export Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setExportMenuOpen(!exportMenuOpen)}
                className="inline-flex items-center gap-1.5 py-1 px-2 rounded text-text-muted hover:text-text-primary hover:bg-surface transition-colors cursor-pointer"
                title="Export report in various formats"
              >
                <RiDownloadLine className="w-3.5 h-3.5 shrink-0" />
                <span>Export</span>
              </button>

              {exportMenuOpen && (
                <div
                  className="absolute right-0 mt-2 w-48 py-1.5 bg-surface border border-border rounded-xl shadow-2xl z-50 flex flex-col font-mono text-xs animate-in fade-in slide-in-from-top-1 duration-150"
                  onMouseLeave={() => setExportMenuOpen(false)}
                >
                  <button
                    type="button"
                    onClick={handleExportHtml}
                    className="px-3 py-2 text-left text-text-secondary hover:text-text-primary hover:bg-surface-hover flex items-center justify-between transition-colors cursor-pointer"
                  >
                    <span>HTML (.html)</span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">Dashboard</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportMarkdown}
                    className="px-3 py-2 text-left text-text-secondary hover:text-text-primary hover:bg-surface-hover flex items-center justify-between transition-colors cursor-pointer"
                  >
                    <span>Markdown (.md)</span>
                    <span className="text-[10px] text-text-muted bg-surface-muted px-1.5 py-0.5 rounded">GFM</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportJson}
                    className="px-3 py-2 text-left text-text-secondary hover:text-text-primary hover:bg-surface-hover flex items-center justify-between transition-colors cursor-pointer"
                  >
                    <span>JSON (.json)</span>
                    <span className="text-[10px] text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">Schema 1.0</span>
                  </button>
                </div>
              )}
            </div>

            {/* Delete Button */}
            <button
              type="button"
              onClick={handleDeleteScan}
              title="Delete scan record"
              className="inline-flex items-center justify-center p-1.5 rounded text-text-muted hover:text-danger hover:bg-danger/10 transition-colors cursor-pointer"
            >
              <RiDeleteBinLine className="w-3.5 h-3.5 shrink-0" />
            </button>
          </div>
        </div>

        {totalCount === 0 ? (
          /* Simple, human, un-boxed zero-vulnerability message */
          <div className="py-24 flex flex-col items-center justify-center text-center space-y-4">
            <RiShieldCheckLine className="w-10 h-10 text-emerald-500 shrink-0" />
            <div className="space-y-1 max-w-sm">
              <h2 className="text-base font-medium text-text-primary">
                No vulnerabilities detected
              </h2>
              <p className="text-xs text-text-muted">
                Scan completed on <span className="font-mono text-text-secondary">{scan.branch}</span> with 0 security findings.
              </p>
            </div>
            <div className="pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={onBack}
                icon={<RiArrowLeftLine className="w-3.5 h-3.5" />}
              >
                Back to Dashboard
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Findings Filter Ribbon */}
            <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-0 border-b border-border-subtle">
              {/* Underline Filter Control */}
              <div className="flex flex-wrap items-center gap-6 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setSeverityFilter('ALL')}
                  className={`pb-3 transition-all cursor-pointer border-b-2 -mb-px ${
                    severityFilter === 'ALL'
                      ? 'border-text-primary text-text-primary font-semibold'
                      : 'border-transparent text-text-secondary hover:text-text-primary'
                  }`}
                >
                  All ({displayedFindings.length})
                </button>
                <button
                  type="button"
                  onClick={() => setSeverityFilter('HIGH_CRITICAL')}
                  className={`pb-3 transition-all cursor-pointer border-b-2 -mb-px ${
                    severityFilter === 'HIGH_CRITICAL'
                      ? 'border-rose-400 text-rose-300 font-semibold'
                      : 'border-transparent text-text-secondary hover:text-rose-400'
                  }`}
                >
                  High/Crit ({highCriticalCount})
                </button>
                <button
                  type="button"
                  onClick={() => setSeverityFilter('MEDIUM')}
                  className={`pb-3 transition-all cursor-pointer border-b-2 -mb-px ${
                    severityFilter === 'MEDIUM'
                      ? 'border-amber-400 text-amber-300 font-semibold'
                      : 'border-transparent text-text-secondary hover:text-amber-400'
                  }`}
                >
                  Medium ({mediumCount})
                </button>

                <span className="text-border-subtle select-none pb-3">|</span>

                <button
                  type="button"
                  onClick={() => setStatusFilter(statusFilter === 'CONFIRMED' ? 'ALL' : 'CONFIRMED')}
                  className={`pb-3 transition-all cursor-pointer border-b-2 -mb-px ${
                    statusFilter === 'CONFIRMED'
                      ? 'border-emerald-400 text-emerald-300 font-semibold'
                      : 'border-transparent text-text-secondary hover:text-emerald-400'
                  }`}
                >
                  Confirmed ({verifiedCount})
                </button>
                <button
                  type="button"
                  onClick={() => setStatusFilter(statusFilter === 'FALSE_POSITIVES' ? 'ALL' : 'FALSE_POSITIVES')}
                  className={`pb-3 transition-all cursor-pointer border-b-2 -mb-px ${
                    statusFilter === 'FALSE_POSITIVES'
                      ? 'border-text-secondary text-text-primary font-semibold'
                      : 'border-transparent text-text-muted hover:text-text-secondary'
                  }`}
                >
                  False Positives ({falsePositiveCount})
                </button>
              </div>

              {/* Fix & PR Button */}
              <div className="flex items-center gap-2 pb-2.5">
                <button
                  type="button"
                  onClick={handleOpenFixModal}
                  className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-mono text-xs font-semibold shadow-sm transition-all cursor-pointer ${
                    Object.keys(sentPrs).length > 0
                      ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/25'
                      : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                  }`}
                  title={Object.keys(sentPrs).length > 0 ? 'Pull Request already sent to GitHub' : 'Generate security fix and open Pull Request on GitHub'}
                >
                  {Object.keys(sentPrs).length > 0 ? (
                    <>
                      <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                      <span>PR Sent</span>
                    </>
                  ) : (
                    <>
                      <RiGitPullRequestLine className="w-3.5 h-3.5 text-white" />
                      <span>Fix & PR</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Publication-Grade Compiled HTML Report */}
            <article className="prose prose-invert max-w-none">
              <CompiledMarkdownReport markdown={reportMarkdown} />
            </article>
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
        onPrCreated={(findingId, prNumber, prUrl) => {
          setSentPrs(prev => {
            const next = { ...prev, [findingId]: { prNumber, prUrl } }
            try {
              localStorage.setItem(`vulscan_sent_prs_${scanId}`, JSON.stringify(next))
            } catch {}
            return next
          })
        }}
      />
    </div>
  )
}
