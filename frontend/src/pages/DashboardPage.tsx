import React, { useState, useEffect, useCallback } from 'react'
import {
  RiGithubLine,
  RiGitBranchLine,
  RiPlayLine,
  RiRefreshLine,
  RiDeleteBinLine,
  RiFolderLine,
  RiHistoryLine,
  RiExternalLinkLine,
  RiAddLine,
  RiSearchLine,
  RiShieldCheckLine,
  RiTimeLine,
  RiFileTextLine,
  RiDownloadLine,
} from '@remixicon/react'
import { Button } from '../components/atoms/Button'
import { Badge } from '../components/atoms/Badge'
import { Spinner } from '../components/atoms/Spinner'
import { useConfirm } from '../context/ConfirmContext'
import { useToast } from '../context/ToastContext'
import { BranchSelect } from '../components/molecules/BranchSelect'
import {
  repositoryApi,
  scanApi,
  type RepositoryItem,
  type ScanItem,
  type DashboardStats,
} from '../services/api'
import {
  generateBranchMarkdownReport,
  generateFullRepoMarkdownReport,
  downloadMarkdownFile,
} from '../utils/reportGenerator'
import { ScanProgressModal } from '../components/organisms/ScanProgressModal'
import { Navbar } from '../components/organisms/Navbar'

interface DashboardPageProps {
  onNavigate: (view: 'home' | 'dashboard') => void
  onInspectScan?: (scan: ScanItem) => void
  initialScanRepo?: string
  onClearInitialScan?: () => void
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onNavigate,
  onInspectScan,
  initialScanRepo,
  onClearInitialScan,
}) => {
  const { success, error, info } = useToast()
  const { confirm } = useConfirm()

  // Data states
  const [repositories, setRepositories] = useState<RepositoryItem[]>([])
  const [scans, setScans] = useState<ScanItem[]>([])
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Interaction states
  const [activeTab, setActiveTab] = useState<'repos' | 'scans'>('repos')
  const [repoUrlInput, setRepoUrlInput] = useState('')
  const [branchInput, setBranchInput] = useState('main')
  const [searchQuery, setSearchQuery] = useState('')
  const [scanningRepoId, setScanningRepoId] = useState<string | null>(null)
  const [isScanningNew, setIsScanningNew] = useState(false)
  const [isAddingRepo, setIsAddingRepo] = useState(false)
  const [scanModal, setScanModal] = useState<{
    isOpen: boolean
    repoUrl: string
    branch: string
    error?: string | null
  }>({
    isOpen: false,
    repoUrl: '',
    branch: 'main',
    error: null,
  })

  // Fetch all dashboard data
  const fetchData = useCallback(async (isSilent = false) => {
    if (!isSilent) setRefreshing(true)
    try {
      const [reposRes, scansRes, statsRes] = await Promise.allSettled([
        repositoryApi.list(),
        scanApi.list(),
        scanApi.getStats(),
      ])

      if (reposRes.status === 'fulfilled') {
        setRepositories(reposRes.value.repositories || [])
      }
      if (scansRes.status === 'fulfilled') {
        setScans(scansRes.value.scans || [])
      }
      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value.stats || null)
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to refresh dashboard data'
      error(msg, 'Data Fetch Error')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [error])

  // Handle manual or initial repo scan
  const executeScan = useCallback(
    async (targetUrl: string, targetBranch: string = 'main', repoId?: string) => {
      const cleanUrl = targetUrl.trim()
      if (!cleanUrl) {
        error('Please provide a repository URL to scan', 'Input Error')
        return
      }

      if (repoId) {
        setScanningRepoId(repoId)
      } else {
        setIsScanningNew(true)
      }

      setScanModal({
        isOpen: true,
        repoUrl: cleanUrl,
        branch: targetBranch || 'main',
        error: null,
      })

      try {
        const result = await scanApi.trigger({
          repoUrl: cleanUrl,
          branch: targetBranch || 'main',
        })

        const scan = result.scan
        const findingsCount = scan.findingsCount || 0

        if (findingsCount > 0) {
          info(
            `Scan identified ${findingsCount} potential vulnerabilities (${scan.highCount} High, ${scan.mediumCount} Medium).`,
            'Scan Completed'
          )
        } else {
          success('Clean scan: 0 security vulnerabilities detected.', 'Scan Completed')
        }

        // Brief delay for user to register 100% completion in modal
        setTimeout(() => {
          setScanModal(prev => ({ ...prev, isOpen: false }))
          if (onInspectScan) {
            onInspectScan(scan)
          }
        }, 500)

        // Refresh lists in background
        await fetchData(true)
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Scan execution failed'
        error(msg, 'Scan Failed')
        setScanModal(prev => ({ ...prev, error: msg }))
      } finally {
        if (repoId) {
          setScanningRepoId(null)
        } else {
          setIsScanningNew(false)
        }
      }
    },
    [error, info, success, fetchData, onInspectScan]
  )

  // Initial load
  useEffect(() => {
    fetchData()
  }, [fetchData])

  // Handle prefilling repository when redirected from HomePage input
  useEffect(() => {
    if (initialScanRepo && initialScanRepo.trim()) {
      const target = initialScanRepo.trim()
      setRepoUrlInput(target)
      onClearInitialScan?.()
    }
  }, [initialScanRepo, onClearInitialScan])

  // Add Repository to tracked list without triggering a scan
  const handleAddRepository = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleanUrl = repoUrlInput.trim()
    if (!cleanUrl) {
      error('Please enter a valid repository URL', 'Validation Error')
      return
    }

    setIsAddingRepo(true)
    try {
      const res = await repositoryApi.add({
        url: cleanUrl,
        defaultBranch: branchInput.trim() || 'main',
      })
      success(`Repository ${res.repository.name} added to tracked list.`, 'Repository Added')
      setRepoUrlInput('')
      setBranchInput('main')
      await fetchData(true)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to add repository'
      error(msg, 'Error')
    } finally {
      setIsAddingRepo(false)
    }
  }

  // Delete Repository
  const handleDeleteRepo = async (id: string, name: string) => {
    const confirmed = await confirm({
      title: 'Remove Repository',
      description: `Are you sure you want to remove '${name}' from your tracked repositories? Historical scans will be preserved.`,
      confirmLabel: 'Remove',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })
    if (!confirmed) return

    try {
      await repositoryApi.delete(id)
      success(`Repository ${name} removed`, 'Removed')
      setRepositories(prev => prev.filter(r => r.id !== id))
      fetchData(true)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete repository'
      error(msg, 'Error')
    }
  }

  // Delete single scan from history
  const handleDeleteScan = async (scanId: string, repoName?: string, branch?: string) => {
    const confirmed = await confirm({
      title: 'Delete Scan Record',
      description: `Delete this scan history record for '${repoName || 'repository'}' (${branch || 'branch'})?`,
      confirmLabel: 'Delete',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })
    if (!confirmed) return

    try {
      await scanApi.delete(scanId)
      success('Scan record deleted from history', 'Deleted')
      setScans(prev => prev.filter(s => s.id !== scanId))
      fetchData(true)
    } catch (err: any) {
      error(err.message || 'Failed to delete scan record', 'Delete Error')
    }
  }

  // Delete all scans from history
  const handleDeleteAllScans = async () => {
    if (scans.length === 0) return

    const confirmed = await confirm({
      title: 'Delete All Scan History',
      description: `Are you sure you want to permanently delete all ${scans.length} scan history records? All recorded vulnerabilities and reports will be removed.`,
      confirmLabel: 'Delete All',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })
    if (!confirmed) return

    try {
      await scanApi.deleteAll()
      setScans([])
      success('All scan history deleted', 'Cleared')
      fetchData(true)
    } catch (err: any) {
      error(err.message || 'Failed to delete all scans', 'Delete Error')
    }
  }

  // Export full multi-branch repository report
  const handleDownloadFullReportForRepo = async (repoName: string, repoUrl: string) => {
    try {
      const res = await scanApi.getRepoScans(repoUrl)
      const allScans = res.scans || []
      const md = generateFullRepoMarkdownReport(repoName, repoUrl, allScans)
      const sanitized = repoName.replace(/[^a-zA-Z0-9_-]/g, '_')
      downloadMarkdownFile(`vulscan-full-report-${sanitized}.md`, md)
      success(`Full repository report exported for ${repoName}`, 'Report Downloaded')
    } catch (err: any) {
      error(err.message || 'Failed to generate repository report', 'Export Error')
    }
  }

  // Filtered items
  const filteredRepos = repositories.filter(repo => {
    const q = searchQuery.toLowerCase()
    return (
      repo.name.toLowerCase().includes(q) ||
      repo.url.toLowerCase().includes(q) ||
      repo.defaultBranch.toLowerCase().includes(q)
    )
  })

  const filteredScans = scans.filter(scan => {
    const q = searchQuery.toLowerCase()
    return (
      scan.repoName.toLowerCase().includes(q) ||
      scan.repoUrl.toLowerCase().includes(q) ||
      scan.branch.toLowerCase().includes(q)
    )
  })

  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans selection:bg-zinc-800 selection:text-zinc-100">
      {/* App Header / Navbar */}
      <Navbar
        onOpenAuth={() => {}}
        onNavigate={onNavigate}
        currentView="dashboard"
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Page Title Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-sans">
                Vulnerability Dashboard
              </h1>
            </div>
            <p className="text-xs sm:text-sm text-zinc-400">
              Manage repositories and view vulnerability scan reports.
            </p>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchData()}
            disabled={refreshing}
            icon={
              <RiRefreshLine
                className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`}
              />
            }
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>
        </div>

        {/* Scan / Track Input Bar */}
        <section className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-zinc-500 px-0.5">
            <span className="uppercase tracking-wider">Scan or Track Repository</span>
          </div>

          <form
            onSubmit={e => {
              e.preventDefault()
              executeScan(repoUrlInput, branchInput)
            }}
            className="flex flex-col sm:flex-row items-center gap-2 p-1.5 rounded-xl bg-zinc-900/50 transition-colors"
          >
            {/* Repo URL Input */}
            <div className="flex-1 flex items-center gap-2.5 px-3 w-full">
              <RiGithubLine className="w-4 h-4 text-zinc-500 shrink-0" />
              <input
                type="text"
                placeholder="https://github.com/organization/repository or local path..."
                value={repoUrlInput}
                onChange={e => setRepoUrlInput(e.target.value)}
                className="w-full bg-transparent text-xs sm:text-sm text-zinc-100 placeholder-zinc-500 font-mono outline-none py-1.5"
              />
            </div>

            {/* Seamless Branch Select */}
            <div className="w-full sm:w-48 shrink-0">
              <BranchSelect
                repoUrl={repoUrlInput}
                value={branchInput}
                onChange={setBranchInput}
                variant="seamless"
              />
            </div>

            {/* Actions */}
            <div className="flex items-center gap-1.5 w-full sm:w-auto justify-end shrink-0 px-1 sm:px-0">
              <button
                type="submit"
                disabled={isScanningNew || !repoUrlInput.trim()}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-zinc-100 hover:bg-white text-zinc-950 font-mono text-xs font-medium transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                {isScanningNew ? (
                  <>
                    <Spinner size="sm" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <RiPlayLine className="w-3.5 h-3.5 fill-current" />
                    <span>Scan</span>
                  </>
                )}
              </button>

              <button
                type="button"
                disabled={isAddingRepo || !repoUrlInput.trim()}
                onClick={handleAddRepository}
                className="flex items-center gap-1 px-3 py-1.5 rounded-md text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 font-mono text-xs transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                title="Add to tracked list without scanning"
              >
                {isAddingRepo ? <Spinner size="sm" /> : <RiAddLine className="w-3.5 h-3.5" />}
                <span>Track</span>
              </button>
            </div>
          </form>
        </section>

        {/* Executive Metrics Bar */}
        <section className="bg-surface/50 rounded-xl px-6 py-3.5">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 sm:gap-8">
            <div className="flex items-center gap-3">
              <span className="text-2xl font-semibold tracking-tight text-zinc-100 font-mono">
                {loading ? '—' : (stats?.totalRepositories ?? repositories.length)}
              </span>
              <span className="text-xs font-mono text-zinc-400">
                Tracked Repos
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-2xl font-semibold tracking-tight text-zinc-100 font-mono">
                {loading ? '—' : (stats?.totalScans ?? scans.length)}
              </span>
              <span className="text-xs font-mono text-zinc-400">
                Total Scans
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-2xl font-semibold tracking-tight text-zinc-100 font-mono">
                {loading ? '—' : (stats?.highSeverity ?? 0)}
              </span>
              <span className="text-xs font-mono text-zinc-400">
                High Severity
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-2xl font-semibold tracking-tight text-zinc-100 font-mono">
                {loading ? '—' : (stats?.cleanScans ?? 0)}
              </span>
              <span className="text-xs font-mono text-zinc-400">
                Clean Scans
              </span>
            </div>
          </div>
        </section>

        {/* Repositories & History Tabbed Section */}
        <section className="bg-surface/60 rounded-xl overflow-hidden">
          {/* Tabs & Search Controls Header */}
          <div className="px-5 pt-3 pb-0 bg-zinc-950/40 border-b border-zinc-800/80 flex flex-col sm:flex-row sm:items-end justify-between gap-3">
            <div className="flex items-center gap-6 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveTab('repos')}
                className={`flex items-center gap-2 pb-3 text-xs font-mono font-medium transition-all cursor-pointer border-b-2 -mb-px ${
                  activeTab === 'repos'
                    ? 'border-zinc-100 text-zinc-100 font-semibold'
                    : 'border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <RiFolderLine className="w-3.5 h-3.5" />
                <span>Tracked Repositories</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  activeTab === 'repos' ? 'bg-zinc-800 text-zinc-200' : 'bg-zinc-900 text-zinc-500'
                }`}>
                  {repositories.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('scans')}
                className={`flex items-center gap-2 pb-3 text-xs font-mono font-medium transition-all cursor-pointer border-b-2 -mb-px ${
                  activeTab === 'scans'
                    ? 'border-zinc-100 text-zinc-100 font-semibold'
                    : 'border-transparent text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <RiHistoryLine className="w-3.5 h-3.5" />
                <span>Scan History</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  activeTab === 'scans' ? 'bg-zinc-800 text-zinc-200' : 'bg-zinc-900 text-zinc-500'
                }`}>
                  {scans.length}
                </span>
              </button>
            </div>

            <div className="flex items-center gap-2.5 w-full sm:w-auto pb-2.5">
              {activeTab === 'scans' && scans.length > 0 && (
                <button
                  type="button"
                  onClick={handleDeleteAllScans}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium text-zinc-400 hover:text-red-400 hover:bg-red-500/10 transition-all cursor-pointer shrink-0"
                  title="Delete all scan history"
                >
                  <RiDeleteBinLine className="w-3.5 h-3.5" />
                  <span>Clear All History</span>
                </button>
              )}

              <div className="relative w-full sm:w-64">
                <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500" />
                <input
                  type="text"
                  placeholder={`Filter ${activeTab === 'repos' ? 'repositories' : 'scans'}...`}
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full bg-zinc-900/40 hover:bg-zinc-900/70 focus:bg-zinc-900/90 pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 rounded-lg outline-none font-mono transition-all"
                />
              </div>
            </div>
          </div>

          {/* Tab 1: Repositories List (Fixed height and scrollable) */}
          {activeTab === 'repos' && (
            <div className="h-[380px] overflow-y-auto overflow-x-auto">
              {loading ? (
                <div className="py-16 flex flex-col items-center justify-center gap-3 text-zinc-500">
                  <Spinner size="md" />
                  <span className="text-xs font-mono">Loading repositories...</span>
                </div>
              ) : filteredRepos.length === 0 ? (
                <div className="py-16 text-center text-zinc-500">
                  <RiFolderLine className="w-10 h-10 mx-auto mb-2 text-zinc-600 stroke-1" />
                  <p className="text-zinc-300 font-medium text-sm">
                    {searchQuery ? 'No matching repositories found' : 'No tracked repositories yet'}
                  </p>
                  <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                    {searchQuery
                      ? 'Try adjusting your search term.'
                      : 'Scan a repository using the form above to add it to your security dashboard.'}
                  </p>
                </div>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 z-10 bg-[#0e0e12] text-zinc-500 font-mono uppercase text-[10.5px]">
                    <tr>
                      <th className="py-2.5 px-5">Repository</th>
                      <th className="py-2.5 px-4">Default Branch</th>
                      <th className="py-2.5 px-4">Latest Posture</th>
                      <th className="py-2.5 px-4">Last Scanned</th>
                      <th className="py-2.5 px-5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60 font-sans">
                    {filteredRepos.map(repo => {
                      const latest = repo.latestScan
                      const isScanningThis = scanningRepoId === repo.id

                      return (
                        <tr
                          key={repo.id}
                          className="hover:bg-zinc-900/40 transition-colors"
                        >
                          {/* Repo Name & Link */}
                          <td className="py-4 px-5">
                            <div className="flex items-center gap-2.5">
                              <RiGithubLine className="w-4 h-4 text-zinc-400 shrink-0" />
                              <div>
                                <a
                                  href={repo.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="font-medium text-zinc-200 hover:text-white flex items-center gap-1.5 transition-colors font-mono"
                                >
                                  <span>{repo.name}</span>
                                  <RiExternalLinkLine className="w-3 h-3 text-zinc-500" />
                                </a>
                                <span className="text-[11px] text-zinc-500 truncate block max-w-xs font-mono">
                                  {repo.url}
                                </span>
                              </div>
                            </div>
                          </td>

                          {/* Default Branch */}
                          <td className="py-4 px-4 font-mono text-zinc-400">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[11px]">
                              <RiGitBranchLine className="w-3 h-3 text-zinc-500" />
                              {repo.defaultBranch}
                            </span>
                          </td>

                          {/* Latest Scan Status */}
                          <td className="py-4 px-4">
                            {latest ? (
                              <div className="flex items-center gap-1.5">
                                {latest.highCount > 0 ? (
                                  <Badge variant="high">
                                    {latest.highCount} High
                                  </Badge>
                                ) : null}
                                {latest.mediumCount > 0 ? (
                                  <Badge variant="medium">
                                    {latest.mediumCount} Med
                                  </Badge>
                                ) : null}
                                {latest.findingsCount === 0 ? (
                                  <Badge variant="clean">Clean</Badge>
                                ) : null}
                              </div>
                            ) : (
                              <span className="text-zinc-600 font-mono text-[11px]">
                                Not scanned yet
                              </span>
                            )}
                          </td>

                          {/* Timestamp */}
                          <td className="py-4 px-4 font-mono text-zinc-500 text-[11px]">
                            {latest
                              ? new Date(latest.createdAt).toLocaleDateString(undefined, {
                                  month: 'short',
                                  day: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit',
                                })
                              : '—'}
                          </td>

                          {/* Action Buttons */}
                          <td className="py-4 px-5 text-right">
                            <div className="inline-flex items-center justify-end gap-2">
                              <Button
                                variant="outline"
                                size="sm"
                                isLoading={isScanningThis}
                                loadingText="Scanning..."
                                onClick={() =>
                                  executeScan(repo.url, repo.defaultBranch, repo.id)
                                }
                                icon={<RiPlayLine className="w-3.5 h-3.5" />}
                              >
                                Scan Now
                              </Button>

                              <button
                                type="button"
                                onClick={() => handleDownloadFullReportForRepo(repo.name, repo.url)}
                                title="Download full repository markdown report (.md)"
                                className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900 border border-zinc-800 transition-colors cursor-pointer"
                              >
                                <RiDownloadLine className="w-4 h-4" />
                              </button>

                              <button
                                type="button"
                                onClick={() => handleDeleteRepo(repo.id, repo.name)}
                                title="Remove repository"
                                className="p-1.5 rounded text-zinc-500 hover:text-red-400 hover:bg-zinc-900 border border-transparent hover:border-zinc-800 transition-colors cursor-pointer"
                              >
                                <RiDeleteBinLine className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* Tab 2: Historical Scans List (Fixed height and scrollable) */}
          {activeTab === 'scans' && (
            <div className="h-[380px] overflow-y-auto overflow-x-auto">
              {loading ? (
                <div className="py-16 flex flex-col items-center justify-center gap-3 text-zinc-500">
                  <Spinner size="md" />
                  <span className="text-xs font-mono">Loading scan history...</span>
                </div>
              ) : filteredScans.length === 0 ? (
                <div className="py-16 text-center text-zinc-500">
                  <RiHistoryLine className="w-10 h-10 mx-auto mb-2 text-zinc-600 stroke-1" />
                  <p className="text-zinc-300 font-medium text-sm">
                    {searchQuery ? 'No matching scans found' : 'No scan history recorded'}
                  </p>
                  <p className="text-xs text-zinc-500 mt-1 max-w-sm mx-auto">
                    {searchQuery
                      ? 'Try adjusting your search criteria.'
                      : 'Trigger a scan from the top bar to inspect syntax trees and record results.'}
                  </p>
                </div>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 z-10 bg-[#0e0e12] text-zinc-500 font-mono uppercase text-[10.5px]">
                    <tr>
                      <th className="py-2.5 px-5">Target Repository</th>
                      <th className="py-2.5 px-4">Branch</th>
                      <th className="py-2.5 px-4">Analysis Duration</th>
                      <th className="py-2.5 px-4">Findings Breakdown</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Scanned At</th>
                      <th className="py-2.5 px-5 text-right">Report</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60 font-sans">
                    {filteredScans.map(scan => (
                      <tr
                        key={scan.id}
                        className="hover:bg-zinc-900/40 transition-colors"
                      >
                        {/* Target Repo */}
                        <td className="py-3.5 px-5">
                          <div className="flex items-center gap-2">
                            <RiGithubLine className="w-4 h-4 text-zinc-400 shrink-0" />
                            <div className="font-mono font-medium text-zinc-200 truncate max-w-[200px]">
                              {scan.repoName || scan.repoUrl}
                            </div>
                          </div>
                        </td>

                        {/* Branch */}
                        <td className="py-3.5 px-4 font-mono text-zinc-400">
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[10.5px]">
                            <RiGitBranchLine className="w-3 h-3 text-zinc-500" />
                            {scan.branch}
                          </span>
                        </td>

                        {/* Duration */}
                        <td className="py-3.5 px-4 font-mono text-zinc-400">
                          <span className="inline-flex items-center gap-1 text-[11px]">
                            <RiTimeLine className="w-3 h-3 text-zinc-500" />
                            {scan.durationMs}ms
                          </span>
                        </td>

                        {/* Findings Breakdown */}
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-1.5">
                            {scan.highCount > 0 && (
                              <Badge variant="high">{scan.highCount} High</Badge>
                            )}
                            {scan.mediumCount > 0 && (
                              <Badge variant="medium">{scan.mediumCount} Med</Badge>
                            )}
                            {scan.findingsCount === 0 && (
                              <Badge variant="clean">Clean</Badge>
                            )}
                          </div>
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4 font-mono">
                          <span className="text-[10.5px] uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded font-semibold">
                            {scan.status}
                          </span>
                        </td>

                        {/* Timestamp */}
                        <td className="py-3.5 px-4 font-mono text-zinc-500 text-[11px]">
                          {new Date(scan.createdAt).toLocaleDateString(undefined, {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })}
                        </td>

                        {/* Actions */}
                        <td className="py-3.5 px-5 text-right">
                          <div className="inline-flex items-center justify-end gap-1.5">
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => onInspectScan?.(scan)}
                              icon={<RiShieldCheckLine className="w-3.5 h-3.5" />}
                            >
                              Inspect
                            </Button>

                            <button
                              type="button"
                              onClick={() => {
                                const md = generateBranchMarkdownReport(scan)
                                const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
                                const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')
                                downloadMarkdownFile(`vulscan-report-${sanitizedRepo}-${sanitizedBranch}.md`, md)
                                success(`Branch report exported for ${scan.branch}`, 'Report Downloaded')
                              }}
                              title="Export branch markdown report (.md)"
                              className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900 border border-zinc-800 transition-colors cursor-pointer"
                            >
                              <RiFileTextLine className="w-4 h-4" />
                            </button>

                            <button
                              type="button"
                              onClick={() => handleDeleteScan(scan.id, scan.repoName, scan.branch)}
                              title="Delete this scan history"
                              className="p-1.5 rounded text-zinc-500 hover:text-red-400 hover:bg-zinc-900 border border-transparent hover:border-zinc-800 transition-colors cursor-pointer"
                            >
                              <RiDeleteBinLine className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </section>
      </main>

      <ScanProgressModal
        isOpen={scanModal.isOpen}
        repoUrl={scanModal.repoUrl}
        branch={scanModal.branch}
        error={scanModal.error}
        onClose={() => setScanModal(prev => ({ ...prev, isOpen: false, error: null }))}
      />
    </div>
  )
}
