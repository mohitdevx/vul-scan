import { type FC, useEffect } from 'react'
import {
  RiCloseLine,
  RiGitBranchLine,
  RiTimeLine,
  RiShieldCheckLine,
} from '@remixicon/react'
import { CodeBlock } from '../atoms/CodeBlock'
import type { ScanItem } from '../../services/api'

interface FindingsModalProps {
  scan: ScanItem | null
  onClose: () => void
}

export const FindingsModal: FC<FindingsModalProps> = ({ scan, onClose }) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  if (!scan) return null

  const findings = scan.findings || []

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-3xl max-h-[85vh] flex flex-col rounded-xl border border-zinc-800 bg-[#0c0c0f] shadow-2xl shadow-black overflow-hidden text-left"
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800/80 bg-zinc-950/80">
          <div className="space-y-1 min-w-0 pr-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-zinc-100 truncate">
                {scan.repoName || scan.repoUrl}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-850 text-zinc-400 border border-zinc-750">
                {scan.status}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-zinc-500 font-mono">
              <span className="flex items-center gap-1">
                <RiGitBranchLine className="w-3.5 h-3.5" />
                {scan.branch}
              </span>
              <span>&bull;</span>
              <span className="flex items-center gap-1">
                <RiTimeLine className="w-3.5 h-3.5" />
                {scan.durationMs}ms
              </span>
              <span>&bull;</span>
              <span>{new Date(scan.createdAt).toLocaleString()}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            <RiCloseLine className="w-5 h-5" />
          </button>
        </div>

        {/* Severity Summary Bar */}
        <div className="px-6 py-3 border-b border-zinc-800/60 bg-zinc-950/40 flex items-center gap-3 text-xs font-mono">
          <span className="text-zinc-400">Findings:</span>
          {scan.highCount > 0 && (
            <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[11px]">
              {scan.highCount} High
            </span>
          )}
          {scan.mediumCount > 0 && (
            <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[11px]">
              {scan.mediumCount} Medium
            </span>
          )}
          {scan.lowCount > 0 && (
            <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 text-[11px]">
              {scan.lowCount} Low
            </span>
          )}
          {findings.length === 0 && (
            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] flex items-center gap-1">
              <RiShieldCheckLine className="w-3.5 h-3.5" />
              Clean &bull; 0 Vulnerabilities
            </span>
          )}
        </div>

        {/* Modal Body - Findings List */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 no-scrollbar">
          {findings.length === 0 ? (
            <div className="py-12 text-center text-zinc-500 text-sm">
              <RiShieldCheckLine className="w-8 h-8 mx-auto mb-2 text-emerald-400" />
              <p className="text-zinc-300 font-medium">No vulnerabilities flagged</p>
              <p className="text-xs text-zinc-500 mt-1">
                AST syntax walker found zero matching vulnerable patterns in this scan.
              </p>
            </div>
          ) : (
            findings.map((item, idx) => (
              <div
                key={item.id || idx}
                className="rounded-lg border border-zinc-800 bg-[#09090c] p-4 space-y-3 text-left"
              >
                {/* Finding Header */}
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[9.5px] font-mono uppercase px-1.5 py-0.5 rounded font-semibold ${
                          item.severity === 'HIGH'
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {item.severity}
                      </span>
                      <span className="text-sm font-semibold text-zinc-200">
                        {item.ruleName}
                      </span>
                      <span className="text-[10.5px] font-mono text-zinc-400 bg-zinc-850 px-1.5 py-0.2 rounded">
                        {item.cwe}
                      </span>
                    </div>
                    <p className="text-xs text-zinc-400 leading-relaxed pt-0.5">
                      {item.message}
                    </p>
                  </div>

                  <span className="text-xs font-mono text-zinc-400 shrink-0 bg-zinc-900 px-2 py-0.5 rounded border border-zinc-800">
                    {item.filePath}:{item.line}
                  </span>
                </div>

                {/* Code Snippet with Syntax Highlighting */}
                <CodeBlock
                  code={item.snippet}
                  highlightToken={item.sink}
                  highlightType={item.severity === 'HIGH' ? 'unsafe' : 'safe'}
                  startLine={item.line}
                  className="w-full"
                />

                {/* Remediation Note */}
                <div className="pt-2 border-t border-zinc-850/80 text-[11.5px] text-zinc-400 leading-relaxed">
                  <span className="font-semibold text-zinc-300 font-mono text-[11px]">
                    Remediation:{' '}
                  </span>
                  {item.remediation}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
