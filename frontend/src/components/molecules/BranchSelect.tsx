import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  RiGitBranchLine,
  RiRefreshLine,
  RiArrowDownSLine,
  RiCheckLine,
  RiSearchLine,
} from '@remixicon/react'
import { Spinner } from '../atoms/Spinner'
import { scanApi } from '../../services/api'

export interface BranchSelectProps {
  repoUrl: string
  value: string
  onChange: (branch: string) => void
  disabled?: boolean
  className?: string
}

function isValidGitUrl(url: string): boolean {
  if (!url) return false
  const trimmed = url.trim().toLowerCase()
  return (
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('file://') ||
    trimmed.startsWith('/') ||
    trimmed.includes('github.com/') ||
    trimmed.includes('gitlab.com/') ||
    trimmed.includes('bitbucket.org/')
  )
}

export const BranchSelect: React.FC<BranchSelectProps> = ({
  repoUrl,
  value,
  onChange,
  disabled = false,
  className = '',
}) => {
  const [branches, setBranches] = useState<string[]>([])
  const [defaultBranch, setDefaultBranch] = useState<string>('main')
  const [isLoading, setIsLoading] = useState(false)
  const [isOpen, setIsOpen] = useState(false)
  const [searchFilter, setSearchFilter] = useState('')

  const containerRef = useRef<HTMLDivElement>(null)
  const lastFetchedUrl = useRef<string>('')

  const fetchBranches = useCallback(
    async (url: string) => {
      const cleanUrl = url.trim()
      if (!isValidGitUrl(cleanUrl)) {
        setBranches([])
        return
      }

      setIsLoading(true)
      try {
        const res = await scanApi.getBranches(cleanUrl)
        const branchList = res.branches || []
        const def = res.defaultBranch || (branchList.length > 0 ? branchList[0] : 'main')

        setBranches(branchList)
        setDefaultBranch(def)
        lastFetchedUrl.current = cleanUrl

        // If current value is empty or not in newly fetched list, auto-select default branch
        if (!value || !branchList.includes(value)) {
          onChange(def)
        }
      } catch {
        setBranches([])
      } finally {
        setIsLoading(false)
      }
    },
    [value, onChange]
  )

  // Auto-sync branches when repoUrl changes
  useEffect(() => {
    const cleanUrl = repoUrl.trim()
    if (!cleanUrl || cleanUrl === lastFetchedUrl.current) return

    const timer = setTimeout(() => {
      fetchBranches(cleanUrl)
    }, 400)

    return () => clearTimeout(timer)
  }, [repoUrl, fetchBranches])

  // Handle click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false)
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      document.addEventListener('keydown', handleKeyDown)
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen])

  const handleRefresh = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (repoUrl.trim()) {
      fetchBranches(repoUrl.trim())
    }
  }

  const filteredBranches = branches.filter(b =>
    b.toLowerCase().includes(searchFilter.trim().toLowerCase())
  )

  const hasSyncedBranches = branches.length > 0
  const isTriggerDisabled = disabled || isLoading || (!hasSyncedBranches && !repoUrl.trim())

  return (
    <div ref={containerRef} className={`relative select-none ${className}`}>
      {/* Dropdown Trigger Button */}
      <button
        type="button"
        disabled={isTriggerDisabled}
        onClick={() => {
          if (!isTriggerDisabled) {
            setIsOpen(prev => !prev)
            setSearchFilter('')
          }
        }}
        className={`w-full h-10 px-3 py-2 rounded-md bg-zinc-900/90 border flex items-center justify-between text-xs font-mono transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${
          isOpen
            ? 'border-zinc-500 ring-1 ring-zinc-500/20 text-zinc-100'
            : 'border-zinc-800 hover:border-zinc-700 text-zinc-300'
        }`}
      >
        <div className="flex items-center gap-2 min-w-0 pr-2">
          <RiGitBranchLine className="w-4 h-4 text-zinc-500 shrink-0" />
          {isLoading ? (
            <div className="flex items-center gap-2 text-zinc-400">
              <Spinner size="sm" />
              <span className="truncate">Syncing branches...</span>
            </div>
          ) : hasSyncedBranches ? (
            <div className="flex items-center gap-1.5 truncate">
              <span className="text-zinc-100 font-medium truncate max-w-[130px]">
                {value || defaultBranch}
              </span>
              {(value === defaultBranch || (!value && defaultBranch)) && (
                <span className="text-[9.5px] px-1 py-0.2 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                  default
                </span>
              )}
            </div>
          ) : repoUrl.trim() ? (
            <span className="text-zinc-500 italic truncate">Syncing with repo...</span>
          ) : (
            <span className="text-zinc-600 truncate">Branch (auto-sync)</span>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {repoUrl.trim() && !isLoading && (
            <span
              role="button"
              onClick={handleRefresh}
              title="Re-sync branches from repository"
              className="p-1 rounded text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
            >
              <RiRefreshLine className="w-3.5 h-3.5" />
            </span>
          )}
          <RiArrowDownSLine
            className={`w-3.5 h-3.5 text-zinc-500 transition-transform duration-150 ${
              isOpen ? 'rotate-180 text-zinc-300' : ''
            }`}
          />
        </div>
      </button>

      {/* Popover Dropdown Menu */}
      {isOpen && hasSyncedBranches && (
        <div className="absolute top-full mt-1.5 left-0 right-0 z-50 rounded-lg border border-zinc-800 bg-[#101014] shadow-2xl shadow-black overflow-hidden animate-in fade-in duration-100">
          {/* Quick Search if multiple branches */}
          {branches.length > 5 && (
            <div className="p-2 border-b border-zinc-850 bg-zinc-950/60">
              <div className="relative flex items-center">
                <RiSearchLine className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Filter synced branches..."
                  value={searchFilter}
                  onChange={e => setSearchFilter(e.target.value)}
                  autoFocus
                  className="w-full bg-zinc-900 border border-zinc-800 text-zinc-200 text-xs font-mono pl-8 pr-2.5 py-1.5 rounded outline-none focus:border-zinc-600 placeholder:text-zinc-600"
                />
              </div>
            </div>
          )}

          {/* Synced Branches List */}
          <div className="max-h-56 overflow-y-auto p-1 space-y-0.5 no-scrollbar">
            {filteredBranches.length === 0 ? (
              <div className="py-4 text-center text-xs text-zinc-500 font-mono">
                No matching branches found
              </div>
            ) : (
              filteredBranches.map(branchName => {
                const isSelected = (value || defaultBranch) === branchName
                const isDefault = branchName === defaultBranch

                return (
                  <button
                    key={branchName}
                    type="button"
                    onClick={() => {
                      onChange(branchName)
                      setIsOpen(false)
                    }}
                    className={`w-full px-2.5 py-1.5 rounded-md flex items-center justify-between text-xs font-mono transition-colors text-left cursor-pointer ${
                      isSelected
                        ? 'bg-zinc-800 text-zinc-100 font-medium'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate pr-2">
                      <span className="truncate">{branchName}</span>
                      {isDefault && (
                        <span className="text-[9.5px] px-1 py-0.2 rounded bg-zinc-850 text-zinc-500 border border-zinc-800">
                          default
                        </span>
                      )}
                    </div>

                    {isSelected && (
                      <RiCheckLine className="w-3.5 h-3.5 text-zinc-200 shrink-0" />
                    )}
                  </button>
                )
              })
            )}
          </div>
        </div>
      )}
    </div>
  )
}
