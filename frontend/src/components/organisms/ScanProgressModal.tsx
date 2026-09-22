import React, { useEffect, useState } from 'react'
import { RiCloseLine, RiAlertLine } from '@remixicon/react'
import { Button } from '../atoms/Button'

export interface ScanProgressProps {
  isOpen: boolean
  repoUrl: string
  branch: string
  error?: string | null
  onClose?: () => void
}

const ACTION_PHASES = [
  { atSeconds: 0, text: 'Connecting to repository snapshot...', progress: 15 },
  { atSeconds: 1.5, text: 'Parsing JavaScript & TypeScript ASTs...', progress: 38 },
  { atSeconds: 3.5, text: 'Tracing source-to-sink taint flows...', progress: 65 },
  { atSeconds: 6, text: 'Validating sanitization and escape boundaries...', progress: 84 },
  { atSeconds: 9, text: 'Compiling security findings and audit summary...', progress: 95 },
]

export const ScanProgressModal: React.FC<ScanProgressProps> = ({
  isOpen,
  repoUrl,
  branch,
  error,
  onClose,
}) => {
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const [currentAction, setCurrentAction] = useState(ACTION_PHASES[0].text)
  const [progress, setProgress] = useState(ACTION_PHASES[0].progress)

  useEffect(() => {
    if (!isOpen || error) return

    setElapsedSeconds(0)
    setCurrentAction(ACTION_PHASES[0].text)
    setProgress(ACTION_PHASES[0].progress)

    const startTime = Date.now()

    const timer = setInterval(() => {
      const elapsed = (Date.now() - startTime) / 1000
      setElapsedSeconds(Math.floor(elapsed))

      let activePhase = ACTION_PHASES[0]
      for (const phase of ACTION_PHASES) {
        if (elapsed >= phase.atSeconds) {
          activePhase = phase
        }
      }
      setCurrentAction(activePhase.text)
      setProgress(activePhase.progress)
    }, 250)

    return () => clearInterval(timer)
  }, [isOpen, error])

  if (!isOpen) return null

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60)
    const remSecs = secs % 60
    return `${mins.toString().padStart(2, '0')}:${remSecs.toString().padStart(2, '0')}`
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs font-sans">
      <div className="relative w-full max-w-md bg-surface border border-border rounded-xl shadow-2xl overflow-hidden p-6 space-y-5 text-text-primary">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0">
            {!error ? (
              <div className="w-4 h-4 border-2 border-border border-t-text-primary rounded-full animate-spin shrink-0 mt-0.5" />
            ) : (
              <RiAlertLine className="w-4 h-4 text-danger shrink-0 mt-0.5" />
            )}
            <div className="min-w-0">
              <h3 className="text-sm font-medium text-text-primary">
                {error ? 'Scan failed' : 'Scanning repository'}
              </h3>
              <p className="text-xs font-mono text-text-muted truncate mt-0.5">
                {repoUrl} &bull; {branch}
              </p>
            </div>
          </div>

          {error && onClose && (
            <button
              onClick={onClose}
              className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface-hover transition-colors cursor-pointer"
              title="Close"
            >
              <RiCloseLine className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Content */}
        {error ? (
          <div className="space-y-4">
            <div className="p-3.5 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs space-y-1.5">
              <div className="font-medium">Error details</div>
              <p className="text-text-secondary leading-relaxed font-mono break-words">{error}</p>
            </div>
            {onClose && (
              <div className="flex justify-end pt-1">
                <Button variant="secondary" size="sm" onClick={onClose}>
                  Close
                </Button>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-3 pt-1">
            {/* Active Changing Progress Bar */}
            <div className="w-full h-1.5 bg-surface-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-text-primary rounded-full transition-all duration-500 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Running Text Action Visualization */}
            <div className="flex items-center justify-between text-xs font-mono text-text-muted gap-2">
              <span className="truncate text-text-secondary transition-all duration-300">
                {currentAction}
              </span>
              <span className="shrink-0 text-text-muted">
                {formatTime(elapsedSeconds)}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
