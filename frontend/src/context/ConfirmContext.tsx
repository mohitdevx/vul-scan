import { createContext, useContext, useState, useCallback, useRef, type ReactNode, useEffect } from 'react'
import { RiAlertLine, RiDeleteBin7Line, RiCloseLine } from '@remixicon/react'

export interface ConfirmOptions {
  title?: string
  description: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: 'danger' | 'warning' | 'neutral'
  icon?: ReactNode
}

interface ConfirmContextType {
  confirm: (options: ConfirmOptions) => Promise<boolean>
}

const ConfirmContext = createContext<ConfirmContextType | undefined>(undefined)

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false)
  const [options, setOptions] = useState<ConfirmOptions>({
    title: 'Confirm Action',
    description: 'Are you sure you want to proceed?',
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    variant: 'danger',
  })

  const resolveRef = useRef<((value: boolean) => void) | null>(null)

  const confirm = useCallback((opts: ConfirmOptions): Promise<boolean> => {
    setOptions({
      title: opts.title || 'Confirm Action',
      description: opts.description,
      confirmLabel: opts.confirmLabel || (opts.variant === 'danger' ? 'Delete' : 'Confirm'),
      cancelLabel: opts.cancelLabel || 'Cancel',
      variant: opts.variant || 'danger',
      icon: opts.icon,
    })
    setIsOpen(true)

    return new Promise<boolean>(resolve => {
      resolveRef.current = resolve
    })
  }, [])

  const handleConfirm = useCallback(() => {
    setIsOpen(false)
    if (resolveRef.current) {
      resolveRef.current(true)
      resolveRef.current = null
    }
  }, [])

  const handleCancel = useCallback(() => {
    setIsOpen(false)
    if (resolveRef.current) {
      resolveRef.current(false)
      resolveRef.current = null
    }
  }, [])

  // Close on Escape key
  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleCancel()
      } else if (e.key === 'Enter') {
        handleConfirm()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, handleCancel, handleConfirm])

  return (
    <ConfirmContext.Provider value={{ confirm }}>
      {children}

      {/* Global Action Confirm Modal */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 select-none animate-in fade-in duration-200">
          {/* Backdrop blur with high contrast dark overlay */}
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={handleCancel}
          />

          {/* Modal Dialog */}
          <div
            className="relative w-full max-w-sm bg-[#111114] rounded-2xl p-6 shadow-2xl shadow-black/90 ring-1 ring-white/10 z-10 scale-100 transition-all"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
            aria-describedby="confirm-dialog-description"
          >
            {/* Top Close Icon Button */}
            <button
              onClick={handleCancel}
              className="absolute top-4 right-4 p-1 rounded-md text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
              aria-label="Close"
            >
              <RiCloseLine className="w-4 h-4" />
            </button>

            <div className="flex items-start gap-3.5">
              {/* Subtle Icon */}
              <div className="shrink-0 mt-0.5">
                {options.icon || (
                  options.variant === 'danger' ? (
                    <RiDeleteBin7Line className="w-5 h-5 text-rose-400" />
                  ) : (
                    <RiAlertLine className="w-5 h-5 text-amber-400" />
                  )
                )}
              </div>

              {/* Text Information */}
              <div className="flex-1 pr-2">
                <h3
                  id="confirm-dialog-title"
                  className="text-sm font-semibold text-zinc-100 tracking-tight"
                >
                  {options.title}
                </h3>
                <p
                  id="confirm-dialog-description"
                  className="mt-1 text-xs text-zinc-400 leading-relaxed font-sans"
                >
                  {options.description}
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="mt-6 flex items-center justify-end gap-2.5">
              <button
                type="button"
                onClick={handleCancel}
                className="px-3.5 py-1.5 rounded-lg text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-white/5 transition-colors cursor-pointer"
              >
                {options.cancelLabel}
              </button>

              <button
                type="button"
                autoFocus
                onClick={handleConfirm}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
                  options.variant === 'danger'
                    ? 'bg-rose-500 hover:bg-rose-400 text-white'
                    : 'bg-zinc-100 hover:bg-white text-zinc-950 font-semibold'
                }`}
              >
                {options.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  )
}

export function useConfirm() {
  const context = useContext(ConfirmContext)
  if (!context) {
    throw new Error('useConfirm must be used within a ConfirmProvider')
  }
  return context
}
