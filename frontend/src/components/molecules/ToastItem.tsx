import React from 'react'
import {
  RiCheckboxCircleLine,
  RiErrorWarningLine,
  RiAlertLine,
  RiInformationLine,
  RiCloseLine,
} from '@remixicon/react'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastMessage {
  id: string
  type: ToastType
  title?: string
  message: string
  duration?: number
}

interface ToastItemProps {
  toast: ToastMessage
  onDismiss: (id: string) => void
}

const toastIcons: Record<ToastType, React.ElementType> = {
  success: RiCheckboxCircleLine,
  error: RiErrorWarningLine,
  warning: RiAlertLine,
  info: RiInformationLine,
}

export const ToastItem: React.FC<ToastItemProps> = ({ toast, onDismiss }) => {
  const Icon = toastIcons[toast.type]

  return (
    <div
      role="alert"
      className="pointer-events-auto flex items-start gap-2.5 w-full max-w-[340px] rounded-lg bg-zinc-900 border border-zinc-800 p-3 shadow-2xl transition-all duration-200 ease-out text-left"
    >
      <div className="shrink-0 mt-0.5 text-zinc-400">
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0 pr-1">
        {toast.title && (
          <p className="text-xs font-medium text-zinc-200 mb-0.5 leading-snug">
            {toast.title}
          </p>
        )}
        <p className="text-xs text-zinc-400 leading-snug break-words">
          {toast.message}
        </p>
      </div>
      <button
        type="button"
        onClick={() => onDismiss(toast.id)}
        className="text-zinc-500 hover:text-zinc-200 p-0.5 rounded transition-colors cursor-pointer shrink-0 mt-0.5"
        aria-label="Dismiss"
      >
        <RiCloseLine className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
