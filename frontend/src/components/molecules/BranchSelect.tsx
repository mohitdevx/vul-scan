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
  variant?: 'default' | 'seamless' | 'compact'
  showAllOption?: boolean
  initialBranches?: string[]
  initialDefaultBranch?: string
  lazy?: boolean
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
  variant = 'default',
  showAllOption = false,
  initialBranches = [],
  initialDefaultBranch = 'main',
  lazy = false,
}) => {
  const [branches, setBranches] = useState<string[]>(initialBranches)
  const [defaultBranch, setDefaultBranch] = useState<string>(initialDefaultBranch)
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
        if (!value || (!branchList.includes(value) && value !== '__ALL__')) {
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

  // Auto-sync branches when repoUrl changes (only when lazy mode is disabled)
  useEffect(() => {
    if (lazy) return
    const cleanUrl = repoUrl.trim()
    if (!cleanUrl || cleanUrl === lastFetchedUrl.current) return

    const timer = setTimeout(() => {
      fetchBranches(cleanUrl)
    }, 400)

    return () => clearTimeout(timer)
  }, [repoUrl, fetchBranches, lazy])

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

  const cleanUrl = repoUrl.trim()

  const handleTriggerClick = () => {
    if (disabled || !cleanUrl) return
    const nextOpen = !isOpen
    setIsOpen(nextOpen)
    setSearchFilter('')

    if (nextOpen && (cleanUrl !== lastFetchedUrl.current || branches.length === 0) && !isLoading) {
      fetchBranches(cleanUrl)
    }
  }

  const handleRefresh = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (cleanUrl) {
      fetchBranches(cleanUrl)
    }
  }

  const filteredBranches = branches.filter(b =>
    b.toLowerCase().includes(searchFilter.trim().toLowerCase())
  )

  const hasSyncedBranches = branches.length > 0
  const isTriggerDisabled = disabled || !cleanUrl
  const isAllSelected = value === '__ALL__'
  const displayBranch = value || initialDefaultBranch || defaultBranch || 'main'
  const isDisplayDefault =
    !isAllSelected && (displayBranch === defaultBranch || displayBranch === initialDefaultBranch)

  const triggerClass =
    variant === 'seamless'
      ? `w-full h-9 px-3 rounded-lg flex items-center justify-between text-xs font-mono transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-40 ${
          isOpen
            ? 'bg-zinc-800 text-zinc-100'
            : 'bg-zinc-800/40 hover:bg-zinc-800 text-zinc-300'
        }`
      : variant === 'compact'
      ? `w-full h-7 px-2 py-1 rounded bg-zinc-900 border flex items-center justify-between text-[11px] font-mono transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-40 ${
          isOpen
            ? 'border-zinc-500 bg-zinc-850 text-zinc-100'
            : 'border-zinc-800 hover:border-zinc-700 hover:bg-zinc-850 text-zinc-300'
        }`
      : `w-full h-10 px-3 py-2 rounded-md bg-zinc-900/90 border flex items-center justify-between text-xs font-mono transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${
          isOpen
            ? 'border-zinc-500 ring-1 ring-zinc-500/20 text-zinc-100'
            : 'border-zinc-800 hover:border-zinc-700 text-zinc-300'
        }`

  const popoverClass =
    variant === 'seamless'
      ? 'absolute top-full mt-2 left-0 right-0 sm:w-64 sm:right-auto z-50 rounded-xl bg-[#121216] shadow-2xl shadow-black ring-1 ring-white/10 overflow-hidden animate-in fade-in duration-100'
      : variant === 'compact'
      ? 'absolute top-full mt-1 left-0 w-52 z-50 rounded-lg border border-zinc-800 bg-[#121216] shadow-2xl shadow-black overflow-hidden animate-in fade-in duration-100'
      : 'absolute top-full mt-1.5 left-0 right-0 z-50 rounded-lg border border-zinc-800 bg-[#101014] shadow-2xl shadow-black overflow-hidden animate-in fade-in duration-100'

  return (
    <div ref={containerRef} className={`relative select-none ${className}`}>
      {/* Dropdown Trigger Button */}
      <button
        type="button"
        disabled={isTriggerDisabled}
        onClick={handleTriggerClick}
        className={triggerClass}
      >
        <div className="flex items-center gap-1.5 min-w-0 pr-1.5">
          <RiGitBranchLine className={`${variant === 'compact' ? 'w-3 h-3' : 'w-4 h-4'} text-zinc-500 shrink-0`} />
          {isLoading ? (
            <div className="flex items-center gap-1.5 text-zinc-400">
              <Spinner size="sm" />
              <span className="truncate">Syncing...</span>
            </div>
          ) : isAllSelected ? (
            <div className="flex items-center gap-1 truncate">
              <span className="text-zinc-100 font-medium truncate">
                All branches
              </span>
              {hasSyncedBranches && (
                <span className="text-[9.5px] px-1 py-0.2 rounded bg-zinc-800 text-zinc-400">
                  {branches.length}
                </span>
              )}
            </div>
          ) : cleanUrl ? (
            <div className="flex items-center gap-1 truncate">
              <span className="text-zinc-100 font-medium truncate max-w-[130px]">
                {displayBranch}
              </span>
              {isDisplayDefault && (
                <span className="text-[9.5px] px-1 py-0.2 rounded bg-zinc-800 text-zinc-400">
                  default
                </span>
              )}
            </div>
          ) : (
            <span className="text-zinc-500 truncate">Branch</span>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {cleanUrl && !isLoading && variant !== 'compact' && (
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
            className={`${variant === 'compact' ? 'w-3 h-3' : 'w-3.5 h-3.5'} text-zinc-500 transition-transform duration-150 ${
              isOpen ? 'rotate-180 text-zinc-300' : ''
            }`}
          />
        </div>
      </button>

      {/* Popover Dropdown Menu */}
      {isOpen && (
        <div className={popoverClass}>
          {isLoading ? (
            <div className="py-6 px-4 flex flex-col items-center justify-center gap-2 text-zinc-400 font-mono text-xs">
              <Spinner size="sm" />
              <span>Fetching branches...</span>
            </div>
          ) : branches.length === 0 ? (
            <div className="py-4 px-3 text-center text-xs text-zinc-500 font-mono">
              <p>No branches found</p>
              {cleanUrl && (
                <button
                  type="button"
                  onClick={() => fetchBranches(cleanUrl)}
                  className="mt-2 inline-flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 underline cursor-pointer"
                >
                  <RiRefreshLine className="w-3 h-3" />
                  <span>Retry sync</span>
                </button>
              )}
            </div>
          ) : (
            <>
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
                {/* All Branches Option */}
                {showAllOption && !searchFilter.trim() && (
                  <button
                    type="button"
                    onClick={() => {
                      onChange('__ALL__')
                      setIsOpen(false)
                    }}
                    className={`w-full px-2.5 py-1.5 rounded-md flex items-center justify-between text-xs font-mono transition-colors text-left cursor-pointer border-b border-zinc-850 mb-0.5 ${
                      isAllSelected
                        ? 'bg-zinc-800 text-zinc-100 font-medium'
                        : 'text-zinc-300 hover:text-white hover:bg-zinc-850'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate pr-2">
                      <RiGitBranchLine className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                      <span className="font-medium">Scan all branches</span>
                      <span className="text-[9.5px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                        {branches.length} total
                      </span>
                    </div>
                    {isAllSelected && <RiCheckLine className="w-3.5 h-3.5 text-zinc-200 shrink-0" />}
                  </button>
                )}

                {filteredBranches.length === 0 ? (
                  <div className="py-4 text-center text-xs text-zinc-500 font-mono">
                    No matching branches found
                  </div>
                ) : (
                  filteredBranches.map(branchName => {
                    const isSelected = !isAllSelected && displayBranch === branchName
                    const isDefault = branchName === defaultBranch || branchName === initialDefaultBranch

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
            </>
          )}
        </div>
      )}
    </div>
  )
}
