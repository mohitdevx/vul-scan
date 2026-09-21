import React, { useEffect, useState } from 'react'
import {
  RiShieldCheckLine,
  RiGitBranchLine,
  RiGithubLine,
  RiCheckLine,
  RiLoader4Line,
  RiTimeLine,
  RiAlertLine,
  RiCloseLine,
} from '@remixicon/react'

export interface ScanProgressProps {
  isOpen: boolean
  repoUrl: string
  branch: string
  error?: string | null
  onClose?: () => void
}

interface Step {
  id: string
  title: string
  description: string
  weight: number
}

const SCAN_STEPS: Step[] = [
  {
    id: 'clone',
    title: 'Cloning Repository',
    description: 'Fetching repository snapshot from GitHub',
    weight: 25,
  },
  {
    id: 'analysis',
    title: 'Static Analysis',
    description: 'Scanning source files for security vulnerabilities and injection sinks',
    weight: 35,
  },
  {
    id: 'triage',
    title: 'Security Triage',
    description: 'Verifying data flow and sanitization contexts',
    weight: 25,
  },
  {
    id: 'report',
    title: 'Generating Report',
    description: 'Compiling vulnerability findings and remediation guidance',
    weight: 15,
  },
]

export const ScanProgressModal: React.FC<ScanProgressProps> = ({
  isOpen,
  repoUrl,
  branch,
  error,
  onClose,
}) => {
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const [currentStepIndex, setCurrentStepIndex] = useState(0)
  const [progressPercent, setProgressPercent] = useState(10)

  // Timer & progress simulation while scan request is in flight
  useEffect(() => {
    if (!isOpen || error) return

    setElapsedSeconds(0)
    setCurrentStepIndex(0)
    setProgressPercent(15)

    const timer = setInterval(() => {
      setElapsedSeconds(prev => prev + 1)
    }, 1000)

    // Progressive stage transitions
    const step1Timer = setTimeout(() => {
      setCurrentStepIndex(1)
      setProgressPercent(45)
    }, 1800)

    const step2Timer = setTimeout(() => {
      setCurrentStepIndex(2)
      setProgressPercent(75)
    }, 3800)

    const step3Timer = setTimeout(() => {
      setCurrentStepIndex(3)
      setProgressPercent(92)
    }, 6500)

    return () => {
      clearInterval(timer)
      clearTimeout(step1Timer)
      clearTimeout(step2Timer)
      clearTimeout(step3Timer)
    }
  }, [isOpen, error])

  if (!isOpen) return null

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60)
    const remSecs = secs % 60
    return `${mins.toString().padStart(2, '0')}:${remSecs.toString().padStart(2, '0')}`
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="relative w-full max-w-xl bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Top Gradient Glow Accent */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-600 via-indigo-500 to-emerald-500" />

        {/* Modal Header */}
        <div className="p-6 pb-4 border-b border-zinc-800/80">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-blue-400">
                <RiShieldCheckLine className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-zinc-100">
                  {error ? 'Scan Failed' : 'Scanning Repository'}
                </h3>
                <div className="flex items-center gap-2 mt-1 text-xs font-mono text-zinc-400">
                  <div className="flex items-center gap-1 text-zinc-300 max-w-[240px] truncate">
                    <RiGithubLine className="w-3.5 h-3.5 shrink-0 text-zinc-500" />
                    <span className="truncate">{repoUrl}</span>
                  </div>
                  <span className="text-zinc-600">&bull;</span>
                  <div className="flex items-center gap-1 text-zinc-400">
                    <RiGitBranchLine className="w-3.5 h-3.5 text-zinc-500" />
                    <span>{branch}</span>
                  </div>
                </div>
              </div>
            </div>

            {error && onClose && (
              <button
                onClick={onClose}
                className="p-1 rounded-lg text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
              >
                <RiCloseLine className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6">
          {error ? (
            <div className="p-4 rounded-xl bg-red-950/30 border border-red-850/50 text-red-300 space-y-2 text-xs font-mono">
              <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                <RiAlertLine className="w-4 h-4 shrink-0" />
                <span>Execution Error</span>
              </div>
              <p className="text-red-300/90 leading-relaxed font-sans">{error}</p>
            </div>
          ) : (
            <>
              {/* Progress Bar & Status */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-zinc-300 font-medium">
                    {SCAN_STEPS[currentStepIndex]?.title || 'Processing...'}
                  </span>
                  <span className="text-zinc-400">{progressPercent}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-zinc-900 border border-zinc-800/80 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-500 ease-out"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
              </div>

              {/* Step Flow List */}
              <div className="space-y-3 pt-1">
                {SCAN_STEPS.map((step, idx) => {
                  const isDone = currentStepIndex > idx
                  const isCurrent = currentStepIndex === idx

                  return (
                    <div
                      key={step.id}
                      className={`flex items-start gap-3 p-2.5 rounded-xl transition-all ${
                        isCurrent
                          ? 'bg-zinc-900/90 border border-zinc-800 text-zinc-100'
                          : isDone
                          ? 'text-zinc-400 opacity-80'
                          : 'text-zinc-600 opacity-40'
                      }`}
                    >
                      <div className="mt-0.5 shrink-0">
                        {isDone ? (
                          <div className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center">
                            <RiCheckLine className="w-3 h-3 stroke-[2.5]" />
                          </div>
                        ) : isCurrent ? (
                          <div className="w-5 h-5 rounded-full bg-blue-500/20 border border-blue-500/40 text-blue-400 flex items-center justify-center">
                            <RiLoader4Line className="w-3 h-3 animate-spin" />
                          </div>
                        ) : (
                          <div className="w-5 h-5 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-600 flex items-center justify-center text-[10px] font-mono">
                            0{idx + 1}
                          </div>
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <h4
                            className={`text-xs font-medium ${
                              isCurrent ? 'text-zinc-100' : isDone ? 'text-zinc-300' : 'text-zinc-500'
                            }`}
                          >
                            {step.title}
                          </h4>
                          {isCurrent && (
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                              Active
                            </span>
                          )}
                          {isDone && (
                            <span className="text-[10px] font-mono text-emerald-400">
                              Done
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-zinc-400 mt-0.5 leading-snug truncate">
                          {step.description}
                        </p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 px-6 bg-zinc-950 border-t border-zinc-900 flex items-center justify-between text-xs font-mono text-zinc-500">
          <div className="flex items-center gap-1.5">
            <RiTimeLine className="w-3.5 h-3.5 text-zinc-400" />
            <span>Elapsed: {formatTime(elapsedSeconds)}</span>
          </div>

          {error ? (
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium cursor-pointer transition-colors"
            >
              Close
            </button>
          ) : (
            <span className="text-zinc-500 text-[11px]">
              AST static analysis &bull; Fast triage
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
