import React, { useState, useEffect, useCallback } from 'react'
import {
  RiArrowLeftLine,
  RiLogoutBoxRLine,
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
  RiAlertLine,
  RiTimeLine,
} from '@remixicon/react'
import { Button } from '../components/atoms/Button'
import { Input } from '../components/atoms/Input'
import { Badge } from '../components/atoms/Badge'
import { Logo } from '../components/atoms/Logo'
import { Spinner } from '../components/atoms/Spinner'
import { StatCard } from '../components/molecules/StatCard'
import { FindingsModal } from '../components/organisms/FindingsModal'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { BranchSelect } from '../components/molecules/BranchSelect'
import {
  repositoryApi,
  scanApi,
  type RepositoryItem,
  type ScanItem,
  type DashboardStats,
} from '../services/api'

interface DashboardPageProps {
  onNavigate: (view: 'home' | 'dashboard') => void
  initialScanRepo?: string
  onClearInitialScan?: () => void
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onNavigate,
  initialScanRepo,
  onClearInitialScan,
}) => {
  const { user, logout } = useAuth()
  const { success, error, info } = useToast()

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
  const [selectedScan, setSelectedScan] = useState<ScanItem | null>(null)

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

      try {
        info(`Cloning & running AST syntax analysis on ${cleanUrl} [${targetBranch}]...`, 'Scan Started')
        const result = await scanApi.trigger({
          repoUrl: cleanUrl,
          branch: targetBranch || 'main',
        })

        const scan = result.scan
        const findingsCount = scan.findingsCount || 0

        if (findingsCount > 0) {
          info(
            `AST Scan identified ${findingsCount} potential vulnerabilities (${scan.highCount} High, ${scan.mediumCount} Medium).`,
            'Scan Completed'
          )
        } else {
          success('Clean scan: 0 security vulnerabilities detected.', 'Scan Completed')
        }

        // Auto open findings modal to view results
        setSelectedScan(scan)

        // Clear input if this was a new repo scan
        if (!repoId) {
          setRepoUrlInput('')
        }

        // Refresh lists in background
        await fetchData(true)
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Scan execution failed'
        error(msg, 'Scan Failed')
      } finally {
        if (repoId) {
          setScanningRepoId(null)
        } else {
          setIsScanningNew(false)
        }
      }
    },
    [error, info, success, fetchData]
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
    if (!window.confirm(`Are you sure you want to remove ${name} from your tracked repositories?`)) {
      return
    }

    try {
      await repositoryApi.delete(id)
      success(`Repository ${name} has been removed.`, 'Removed')
      setRepositories(prev => prev.filter(r => r.id !== id))
      fetchData(true)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete repository'
      error(msg, 'Error')
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
      {/* App Header */}
      <header className="border-b border-border bg-surface/90 backdrop-blur-md px-4 sm:px-8 py-3.5 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div
              onClick={() => onNavigate('home')}
              className="cursor-pointer select-none"
            >
              <Logo showWordmark size="md" />
            </div>

            <div className="hidden md:flex items-center gap-2 text-xs text-zinc-500 font-mono border-l border-zinc-800 pl-4">
              <span>Security Center</span>
              <span className="text-zinc-700">/</span>
              <span className="text-zinc-300">AST Analysis Engine</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {user && (
              <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md bg-zinc-900/90 border border-zinc-800 text-xs font-mono">
                <span className="text-zinc-200 font-medium">{user.orgName}</span>
                <span className="text-zinc-600">&bull;</span>
                <span className="text-zinc-400">{user.email}</span>
              </div>
            )}

            <Button
              variant="ghost"
              size="sm"
              onClick={() => onNavigate('home')}
              icon={<RiArrowLeftLine className="w-4 h-4" />}
            >
              Home
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={logout}
              icon={<RiLogoutBoxRLine className="w-4 h-4" />}
            >
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Page Title Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-sans">
                Vulnerability Dashboard
              </h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                v2.4.0-AST
              </span>
            </div>
            <p className="text-xs sm:text-sm text-zinc-400">
              Deterministic AST syntax tree security scanning and repository vulnerability history.
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

        {/* Quick Scan & Track Box */}
        <section className="bg-surface border border-border rounded-xl p-5 sm:p-6 shadow-sm">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-zinc-200 uppercase tracking-wider font-mono">
              Scan or Track Git Repository
            </h2>
            <p className="text-xs text-zinc-500 mt-0.5">
              Enter any public Git repository. We will traverse the AST syntax tree to flag injection sinks, prototype pollution, and deserialization flaws.
            </p>
          </div>

          <form
            onSubmit={e => {
              e.preventDefault()
              executeScan(repoUrlInput, branchInput)
            }}
            className="flex flex-col lg:flex-row items-stretch gap-3"
          >
            <div className="flex-1">
              <Input
                placeholder="https://github.com/organization/repository"
                value={repoUrlInput}
                onChange={e => setRepoUrlInput(e.target.value)}
                icon={<RiGithubLine className="w-4 h-4 text-zinc-500" />}
                className="bg-zinc-950 font-mono text-xs sm:text-sm"
              />
            </div>

            <div className="w-full lg:w-56">
              <BranchSelect
                repoUrl={repoUrlInput}
                value={branchInput}
                onChange={setBranchInput}
              />
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <Button
                type="submit"
                variant="primary"
                size="md"
                isLoading={isScanningNew}
                loadingText="Analyzing AST..."
                icon={<RiPlayLine className="w-4 h-4" />}
                className="w-full sm:w-auto"
              >
                Scan Repository
              </Button>

              <Button
                type="button"
                variant="secondary"
                size="md"
                isLoading={isAddingRepo}
                onClick={handleAddRepository}
                icon={<RiAddLine className="w-4 h-4" />}
                className="w-full sm:w-auto"
              >
                Track Only
              </Button>
            </div>
          </form>
        </section>

        {/* Stat Cards Grid */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Tracked Repos"
            value={
              loading
                ? '—'
                : String(stats?.totalRepositories ?? repositories.length)
            }
            description="Repositories actively monitored"
            icon={<RiFolderLine className="w-4 h-4" />}
          />
          <StatCard
            label="Total AST Scans"
            value={
              loading
                ? '—'
                : String(stats?.totalScans ?? scans.length)
            }
            description="Historical analysis runs"
            icon={<RiHistoryLine className="w-4 h-4" />}
          />
          <StatCard
            label="High Severity Sinks"
            value={
              loading
                ? '—'
                : String(stats?.highSeverity ?? 0)
            }
            description="Critical injection & execution sinks"
            icon={<RiAlertLine className="w-4 h-4" />}
          />
          <StatCard
            label="Clean Scans"
            value={
              loading
                ? '—'
                : String(stats?.cleanScans ?? 0)
            }
            description="Zero vulnerability findings"
            icon={<RiShieldCheckLine className="w-4 h-4" />}
          />
        </section>

        {/* Repositories & History Tabbed Section */}
        <section className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
          {/* Tabs & Search Controls Header */}
          <div className="px-5 py-3.5 border-b border-border bg-zinc-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveTab('repos')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-mono font-medium transition-colors cursor-pointer ${
                  activeTab === 'repos'
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                }`}
              >
                <RiFolderLine className="w-3.5 h-3.5" />
                <span>Tracked Repositories</span>
                <span className="px-1.5 py-0.2 rounded bg-zinc-900 text-[10px] text-zinc-400 border border-zinc-800">
                  {repositories.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('scans')}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-mono font-medium transition-colors cursor-pointer ${
                  activeTab === 'scans'
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                }`}
              >
                <RiHistoryLine className="w-3.5 h-3.5" />
                <span>Scan History</span>
                <span className="px-1.5 py-0.2 rounded bg-zinc-900 text-[10px] text-zinc-400 border border-zinc-800">
                  {scans.length}
                </span>
              </button>
            </div>

            <div className="w-full sm:w-64">
              <Input
                placeholder={`Search ${activeTab === 'repos' ? 'repositories' : 'scans'}...`}
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                icon={<RiSearchLine className="w-3.5 h-3.5" />}
                className="py-1 text-xs bg-zinc-900"
              />
            </div>
          </div>

          {/* Tab 1: Repositories List */}
          {activeTab === 'repos' && (
            <div className="overflow-x-auto no-scrollbar">
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
                  <thead className="border-b border-border bg-zinc-950/40 text-zinc-500 font-mono uppercase text-[10.5px]">
                    <tr>
                      <th className="py-3 px-5">Repository</th>
                      <th className="py-3 px-4">Default Branch</th>
                      <th className="py-3 px-4">Latest Posture</th>
                      <th className="py-3 px-4">Last Scanned</th>
                      <th className="py-3 px-5 text-right">Actions</th>
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

          {/* Tab 2: Historical Scans List */}
          {activeTab === 'scans' && (
            <div className="overflow-x-auto no-scrollbar">
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
                  <thead className="border-b border-border bg-zinc-950/40 text-zinc-500 font-mono uppercase text-[10.5px]">
                    <tr>
                      <th className="py-3 px-5">Target Repository</th>
                      <th className="py-3 px-4">Branch</th>
                      <th className="py-3 px-4">Analysis Duration</th>
                      <th className="py-3 px-4">Findings Breakdown</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Scanned At</th>
                      <th className="py-3 px-5 text-right">Report</th>
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

                        {/* View Findings Button */}
                        <td className="py-3.5 px-5 text-right">
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => setSelectedScan(scan)}
                            icon={<RiShieldCheckLine className="w-3.5 h-3.5" />}
                          >
                            Inspect
                          </Button>
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

      {/* AST Findings Inspection Modal */}
      <FindingsModal
        scan={selectedScan}
        onClose={() => setSelectedScan(null)}
      />
    </div>
  )
}
