import React, { useState, useEffect, useRef } from 'react'
import {
  RiSparklingLine,
  RiArrowDownSLine,
  RiCheckLine,
  RiAddLine,
  RiCpuLine,
  RiSignalWifiLine,
  RiSignalWifiErrorLine,
} from '@remixicon/react'
import { scanApi } from '../../services/api'

interface AiModelSelectorProps {
  selectedModel?: string
  onModelChange?: (model: string) => void
  variant?: 'navbar' | 'compact' | 'inline'
  className?: string
}

const STORAGE_KEY = 'vulscan_selected_model'
const MODEL_CHANGE_EVENT = 'vulscan:model-change'

export const AiModelSelector: React.FC<AiModelSelectorProps> = ({
  selectedModel: propModel,
  onModelChange,
  variant = 'navbar',
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [availableModels, setAvailableModels] = useState<string[]>([])
  const [currentModel, setCurrentModel] = useState<string>(() => {
    return propModel || localStorage.getItem(STORAGE_KEY) || 'qwen2.5-coder:3b'
  })
  const [customModelInput, setCustomModelInput] = useState('')
  const [isCustomMode, setIsCustomMode] = useState(false)
  const [provider, setProvider] = useState<string>('AI')
  const [baseUrl, setBaseUrl] = useState<string>('')
  const [isOnline, setIsOnline] = useState<boolean | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const dropdownRef = useRef<HTMLDivElement>(null)

  // Fetch status and available models
  const fetchStatus = () => {
    scanApi
      .getAiStatus()
      .then(res => {
        setIsOnline(res.available)
        setProvider(res.provider || 'AI')
        setBaseUrl(res.baseUrl || '')
        setErrorMessage(res.error || null)

        const list = res.models || []
        const active = propModel || localStorage.getItem(STORAGE_KEY) || res.model || 'qwen2.5-coder:3b'
        const merged = Array.from(new Set([active, res.model, ...list].filter(Boolean))) as string[]
        setAvailableModels(merged)

        if (!localStorage.getItem(STORAGE_KEY) && res.model) {
          setCurrentModel(res.model)
          try {
            localStorage.setItem(STORAGE_KEY, res.model)
          } catch {}
        }
      })
      .catch(err => {
        setIsOnline(false)
        setErrorMessage(err.message || 'Cannot reach AI backend')
        setAvailableModels([
          'qwen2.5-coder:3b',
          'deepseek-chat',
          'gpt-4o-mini',
          'gpt-4o',
          'meta/llama-3.1-70b-instruct',
        ])
      })
  }

  useEffect(() => {
    fetchStatus()

    const handleGlobalModelChange = (e: CustomEvent<string>) => {
      if (e.detail && e.detail !== currentModel) {
        setCurrentModel(e.detail)
      }
    }

    window.addEventListener(MODEL_CHANGE_EVENT as any, handleGlobalModelChange)
    return () => {
      window.removeEventListener(MODEL_CHANGE_EVENT as any, handleGlobalModelChange)
    }
  }, [])

  useEffect(() => {
    if (propModel && propModel !== currentModel) {
      setCurrentModel(propModel)
    }
  }, [propModel])

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false)
        setIsCustomMode(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleSelectModel = (model: string) => {
    const trimmed = model.trim()
    if (!trimmed) return

    setCurrentModel(trimmed)
    try {
      localStorage.setItem(STORAGE_KEY, trimmed)
    } catch {}

    window.dispatchEvent(new CustomEvent(MODEL_CHANGE_EVENT, { detail: trimmed }))
    if (onModelChange) {
      onModelChange(trimmed)
    }

    if (!availableModels.includes(trimmed)) {
      setAvailableModels(prev => [trimmed, ...prev])
    }

    setIsOpen(false)
    setIsCustomMode(false)
    setCustomModelInput('')
  }

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    handleSelectModel(customModelInput)
  }

  // Model name formatter for display
  const formatModelDisplay = (name: string) => {
    if (name.length > 22) {
      return name.substring(0, 20) + '…'
    }
    return name
  }

  return (
    <div className={`relative inline-block text-left font-sans ${className}`} ref={dropdownRef}>
      {/* Trigger Button */}
      {variant === 'navbar' && (
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface/80 hover:bg-surface border border-border/80 hover:border-border text-xs font-mono transition-all cursor-pointer shadow-xs"
          title={`Active AI Model: ${currentModel} (${provider})`}
        >
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                isOnline === true ? 'bg-emerald-400' : isOnline === false ? 'bg-amber-400' : 'bg-text-muted'
              }`}
            />
            <RiSparklingLine className="w-3.5 h-3.5 text-primary-light shrink-0" />
            <span className="text-text-muted font-sans text-[11px] hidden md:inline">Model:</span>
            <span className="text-text-primary font-medium">{formatModelDisplay(currentModel)}</span>
          </div>
          <RiArrowDownSLine className={`w-3.5 h-3.5 text-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>
      )}

      {variant === 'inline' && (
        <div className="flex items-center gap-2">
          <label className="text-xs font-mono text-text-muted">AI Model:</label>
          <button
            type="button"
            onClick={() => setIsOpen(!isOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface border border-border hover:border-primary/50 text-xs font-mono transition-all cursor-pointer"
          >
            <RiCpuLine className="w-3.5 h-3.5 text-primary-light" />
            <span className="text-text-primary font-medium">{currentModel}</span>
            <span className="text-[10px] text-text-muted px-1.5 py-0.5 rounded bg-surface-muted border border-border-subtle">
              {provider}
            </span>
            <RiArrowDownSLine className={`w-3.5 h-3.5 text-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} />
          </button>
        </div>
      )}

      {variant === 'compact' && (
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface border border-border text-[11px] font-mono hover:bg-surface-hover transition-colors cursor-pointer"
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isOnline === true ? 'bg-emerald-400' : 'bg-amber-400'
            }`}
          />
          <span className="text-text-secondary">{formatModelDisplay(currentModel)}</span>
          <RiArrowDownSLine className="w-3 h-3 text-text-muted" />
        </button>
      )}

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-72 sm:w-80 rounded-xl bg-surface border border-border shadow-2xl z-50 overflow-hidden animate-in fade-in zoom-in-95 duration-100">
          {/* Header */}
          <div className="p-3 border-b border-border bg-surface-muted/30 flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                <RiCpuLine className="w-4 h-4 text-primary-light" />
                <span>Select AI Model</span>
              </div>
              <p className="text-[11px] text-text-muted mt-0.5">
                Provider: <span className="text-text-secondary font-medium">{provider}</span>
                {baseUrl ? ` (${baseUrl.replace(/https?:\/\//, '').split('/')[0]})` : ''}
              </p>
            </div>
            <div className="flex items-center gap-1">
              {isOnline ? (
                <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-mono bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                  <RiSignalWifiLine className="w-3 h-3" /> Online
                </span>
              ) : (
                <span
                  className="inline-flex items-center gap-1 text-[10px] text-amber-400 font-mono bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20"
                  title={errorMessage || undefined}
                >
                  <RiSignalWifiErrorLine className="w-3 h-3" /> Offline
                </span>
              )}
            </div>
          </div>

          {/* Offline Notice */}
          {!isOnline && errorMessage && (
            <div className="px-3 py-1.5 bg-amber-500/10 border-b border-amber-500/20 text-[10px] font-mono text-amber-300 truncate">
              {errorMessage}
            </div>
          )}

          {/* Model Options List */}
          <div className="max-h-60 overflow-y-auto p-1.5 space-y-0.5">
            <div className="px-2 py-1 text-[10px] font-mono text-text-muted uppercase tracking-wider">
              Available Models
            </div>
            {availableModels.map(model => {
              const isSelected = model === currentModel
              return (
                <button
                  key={model}
                  type="button"
                  onClick={() => handleSelectModel(model)}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg text-xs font-mono flex items-center justify-between transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-primary/15 text-primary-light font-medium border border-primary/30'
                      : 'text-text-secondary hover:bg-surface-hover hover:text-text-primary'
                  }`}
                >
                  <span className="truncate">{model}</span>
                  {isSelected && <RiCheckLine className="w-3.5 h-3.5 text-primary-light shrink-0" />}
                </button>
              )
            })}
          </div>

          {/* Custom Model Input or Mode Toggle */}
          <div className="p-2 border-t border-border bg-surface-muted/20">
            {isCustomMode ? (
              <form onSubmit={handleCustomSubmit} className="space-y-2">
                <input
                  type="text"
                  value={customModelInput}
                  onChange={e => setCustomModelInput(e.target.value)}
                  placeholder="e.g. gpt-4o, deepseek-coder"
                  autoFocus
                  className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg bg-surface border border-border focus:border-primary focus:outline-none text-text-primary"
                />
                <div className="flex items-center justify-end gap-1.5">
                  <button
                    type="button"
                    onClick={() => setIsCustomMode(false)}
                    className="px-2 py-1 text-[11px] rounded text-text-muted hover:text-text-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={!customModelInput.trim()}
                    className="px-2.5 py-1 text-[11px] rounded bg-primary text-white hover:bg-primary-hover disabled:opacity-50 font-medium cursor-pointer"
                  >
                    Set Model
                  </button>
                </div>
              </form>
            ) : (
              <button
                type="button"
                onClick={() => setIsCustomMode(true)}
                className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 text-[11px] font-mono text-text-muted hover:text-text-primary hover:bg-surface rounded-lg transition-colors cursor-pointer border border-dashed border-border"
              >
                <RiAddLine className="w-3.5 h-3.5" />
                <span>Specify Custom Model...</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
