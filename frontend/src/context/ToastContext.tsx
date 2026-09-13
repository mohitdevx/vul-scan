import React, { createContext, useContext, useState, useCallback } from 'react'
import type { ToastMessage, ToastType } from '../components/molecules/ToastItem'
import { ToastContainer } from '../components/organisms/ToastContainer'

interface ToastContextValue {
  showToast: (type: ToastType, message: string, title?: string, duration?: number) => void
  success: (message: string, title?: string) => void
  error: (message: string, title?: string) => void
  warning: (message: string, title?: string) => void
  info: (message: string, title?: string) => void
  dismissToast: (id: string) => void
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined)

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const showToast = useCallback(
    (type: ToastType, message: string, title?: string, duration = 4000) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
      const newToast: ToastMessage = { id, type, message, title, duration }

      setToasts(prev => [...prev, newToast])

      if (duration > 0) {
        setTimeout(() => {
          dismissToast(id)
        }, duration)
      }
    },
    [dismissToast]
  )

  const success = useCallback(
    (message: string, title?: string) => showToast('success', message, title),
    [showToast]
  )
  const error = useCallback(
    (message: string, title?: string) => showToast('error', message, title),
    [showToast]
  )
  const warning = useCallback(
    (message: string, title?: string) => showToast('warning', message, title),
    [showToast]
  )
  const info = useCallback(
    (message: string, title?: string) => showToast('info', message, title),
    [showToast]
  )

  return (
    <ToastContext.Provider
      value={{ showToast, success, error, warning, info, dismissToast }}
    >
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}
