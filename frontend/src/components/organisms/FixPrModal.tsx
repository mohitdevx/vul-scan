import React, { useState, useEffect } from 'react'
import {
  RiCloseLine,
  RiGitPullRequestLine,
  RiGitBranchLine,
  RiCheckLine,
  RiFileCopyLine,
  RiExternalLinkLine,
  RiLoader4Line,
  RiEyeLine,
  RiEyeOffLine,
  RiCodeBoxLine,
  RiAlertLine,
  RiGithubFill,
  RiGitMergeLine,
  RiEditLine,
  RiShieldCheckLine,
} from '@remixicon/react'
import {
  scanApi,
  githubApi,
  type SecurityFixProposal,
  type BatchSecurityFixProposal,
  type FindingFixItem,
  type FindingItem,
} from '../../services/api'
import { useToast } from '../../context/ToastContext'
import { CodeBlock } from '../atoms/CodeBlock'
import { Button } from '../atoms/Button'

interface FixPrModalProps {
  isOpen: boolean
  onClose: () => void
  scanId: string
  finding?: FindingItem | null
  findings?: FindingItem[]
  onPrCreated?: (findingIds: string[], prNumber: number, prUrl: string) => void
}

export const FixPrModal: React.FC<FixPrModalProps> = ({
  isOpen,
  onClose,
  scanId,
  finding,
  findings = [],
  onPrCreated,
}) => {
  const { success, error, info } = useToast()

  // Consolidate candidate findings
  const availableFindings: FindingItem[] = findings.length > 0 ? findings : finding ? [finding] : []

  // Scope: 'ALL' or a specific finding id (e.g. 'CMDI-1')
  const [selectedScope, setSelectedScope] = useState<string>('ALL')

  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Proposals cache and state
  const [singleProposal, setSingleProposal] = useState<SecurityFixProposal | null>(null)
  const [batchProposal, setBatchProposal] = useState<BatchSecurityFixProposal | null>(null)

  // Active selected finding index in batch mode inspection
  const [selectedFixIndex, setSelectedFixIndex] = useState(0)

  // Editable patches dictionary: findingId -> replacementSnippet
  const [editablePatches, setEditablePatches] = useState<Record<string, string>>({})

  const [activeTab, setActiveTab] = useState<'diff' | 'edit' | 'context'>('diff')

  // GitHub Authorization state
  const [ghStatus, setGhStatus] = useState<{
    connected: boolean
    username: string | null
    avatarUrl: string | null
  }>({ connected: false, username: null, avatarUrl: null })
  const [isCheckingAuth, setIsCheckingAuth] = useState(false)
  const [isConnectingGh, setIsConnectingGh] = useState(false)
  const [oauthConfig, setOauthConfig] = useState<{ configured: boolean; url?: string }>({ configured: false })

  // Form states
  const [branchName, setBranchName] = useState('')
  const [prTitle, setPrTitle] = useState('')
  const [prDescription, setPrDescription] = useState('')
  const [inputToken, setInputToken] = useState('')
  const [showToken, setShowToken] = useState(false)

  // Success result
  const [createdPr, setCreatedPr] = useState<{
    prUrl: string
    prNumber: number
    branch: string
    state: string
    fixedCount: number
  } | null>(null)
  const [isMerging, setIsMerging] = useState(false)
  const [isMerged, setIsMerged] = useState(false)
  const [copied, setCopied] = useState(false)

  // Initialize scope when modal opens or findings change
  useEffect(() => {
    if (!isOpen) return
    if (finding) {
      setSelectedScope(finding.id)
    } else if (availableFindings.length === 1) {
      setSelectedScope(availableFindings[0].id)
    } else {
      setSelectedScope('ALL')
    }
  }, [isOpen, finding, availableFindings.length])

  // Check persistent GitHub connection status & OAuth config
  useEffect(() => {
    if (!isOpen) return
    setIsCheckingAuth(true)

    githubApi
      .getStatus()
      .then(res => {
        setGhStatus({
          connected: res.connected,
          username: res.username,
          avatarUrl: res.avatarUrl,
        })
      })
      .catch(() => {
        setGhStatus({ connected: false, username: null, avatarUrl: null })
      })
      .finally(() => {
        setIsCheckingAuth(false)
      })

    githubApi
      .getOAuthUrl()
      .then(res => {
        if (res.configured && res.url) {
          setOauthConfig({ configured: true, url: res.url })
        }
      })
      .catch(() => {})
  }, [isOpen])

  // Listen for OAuth completion message from popup window
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'GITHUB_AUTH_SUCCESS') {
        setGhStatus({
          connected: true,
          username: event.data.username,
          avatarUrl: event.data.avatarUrl,
        })
        success(`GitHub connected as @${event.data.username}`, 'Connected')
      }
    }
    window.addEventListener('message', handleMessage)
    return () => window.removeEventListener('message', handleMessage)
  }, [success])

  const handleOpenOAuthPopup = () => {
    if (!oauthConfig.url) return
    const width = 600
    const height = 700
    const left = window.screenX + (window.outerWidth - width) / 2
    const top = window.screenY + (window.outerHeight - height) / 2
    window.open(oauthConfig.url, 'github-oauth', `width=${width},height=${height},left=${left},top=${top}`)
  }

  // Fetch fix proposals whenever scanId or selectedScope changes
  useEffect(() => {
    if (!isOpen || !scanId || availableFindings.length === 0) {
      setSingleProposal(null)
      setBatchProposal(null)
      setCreatedPr(null)
      return
    }

    let isMounted = true
    setIsLoading(true)
    setCreatedPr(null)

    if (selectedScope === 'ALL' && availableFindings.length > 1) {
      // Multiple findings: Batch fix
      const targetIds = availableFindings.map(f => f.id)
      scanApi
        .generateBatchFixes(scanId, targetIds)
        .then(res => {
          if (!isMounted) return
          setBatchProposal(res.proposal)
          setSingleProposal(null)
          setSelectedFixIndex(0)
          setBranchName(res.proposal.suggestedBranch)
          setPrTitle(res.proposal.prTitle)
          setPrDescription(res.proposal.prDescription)

          const patchMap: Record<string, string> = {}
          res.proposal.fixes.forEach(fix => {
            patchMap[fix.findingId] = fix.replacementSnippet
          })
          setEditablePatches(patchMap)
        })
        .catch(err => {
          if (!isMounted) return
          const msg = err instanceof Error ? err.message : 'Failed to generate remediation proposal'
          error(msg, 'Error')
        })
        .finally(() => {
          if (isMounted) setIsLoading(false)
        })
    } else {
      // Single finding fix: either explicitly selected or single available finding
      const targetId = selectedScope === 'ALL' ? availableFindings[0].id : selectedScope
      scanApi
        .generateFix(scanId, targetId)
        .then(res => {
          if (!isMounted) return
          setSingleProposal(res.proposal)
          setBatchProposal(null)
          setBranchName(res.proposal.suggestedBranch)
          setPrTitle(res.proposal.prTitle)
          setPrDescription(res.proposal.prDescription)
          setEditablePatches({ [targetId]: res.proposal.replacementSnippet })
        })
        .catch(err => {
          if (!isMounted) return
          const msg = err instanceof Error ? err.message : 'Failed to generate remediation proposal'
          error(msg, 'Error')
        })
        .finally(() => {
          if (isMounted) setIsLoading(false)
        })
    }

    return () => {
      isMounted = false
    }
  }, [isOpen, scanId, selectedScope, availableFindings.length])

  if (!isOpen || availableFindings.length === 0) return null

  // Active current fix item for diff view
  const currentFix: FindingFixItem | SecurityFixProposal | null =
    selectedScope === 'ALL' && batchProposal
      ? batchProposal.fixes[selectedFixIndex] || batchProposal.fixes[0]
      : singleProposal

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    success('Copied code to clipboard', 'Copied')
  }

  const handleAuthorizeGitHub = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!inputToken.trim()) return

    setIsConnectingGh(true)
    try {
      const res = await githubApi.connect(inputToken.trim())
      setGhStatus({
        connected: true,
        username: res.username,
        avatarUrl: res.avatarUrl,
      })
      setInputToken('')
      success(`GitHub authorized as @${res.username}`, 'Connected')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to authorize GitHub account'
      error(msg, 'Authorization Failed')
    } finally {
      setIsConnectingGh(false)
    }
  }

  const handleDisconnectGitHub = async () => {
    try {
      await githubApi.disconnect()
      setGhStatus({ connected: false, username: null, avatarUrl: null })
      info('GitHub disconnected', 'Disconnected')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to disconnect GitHub'
      error(msg, 'Error')
    }
  }

  const handleCreatePr = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!ghStatus.connected && !inputToken.trim()) {
      error('Please connect your GitHub authorization first.', 'Authorization Required')
      return
    }

    setIsSubmitting(true)

    try {
      if (selectedScope === 'ALL' && batchProposal && batchProposal.fixes.length > 0) {
        // Multi-finding Pull Request
        const patches = batchProposal.fixes.map(fix => ({
          findingId: fix.findingId,
          filePath: fix.filePath,
          searchSnippet: fix.searchSnippet,
          replacementSnippet:
            editablePatches[fix.findingId] !== undefined
              ? editablePatches[fix.findingId]
              : fix.replacementSnippet,
        }))

        const res = await scanApi.createBatchPr(scanId, {
          githubToken: inputToken.trim() || undefined,
          targetBranch: batchProposal.targetBranch,
          branchName: branchName.trim(),
          patches,
          commitMessage: batchProposal.commitMessage,
          prTitle: prTitle.trim(),
          prDescription: prDescription.trim(),
        })

        const fixedFindingIds = res.result.fixedFindingIds || batchProposal.fixes.map(f => f.findingId)
        setCreatedPr({
          prUrl: res.result.prUrl,
          prNumber: res.result.prNumber,
          branch: res.result.branch,
          state: res.result.state,
          fixedCount: fixedFindingIds.length,
        })
        onPrCreated?.(fixedFindingIds, res.result.prNumber, res.result.prUrl)
        success(`Pull Request #${res.result.prNumber} opened on GitHub`, 'PR Opened')
      } else if (singleProposal) {
        // Single finding Pull Request
        const res = await scanApi.createPr(scanId, singleProposal.findingId, {
          githubToken: inputToken.trim() || undefined,
          targetBranch: singleProposal.targetBranch,
          branchName: branchName.trim(),
          filePath: singleProposal.filePath,
          searchSnippet: singleProposal.searchSnippet,
          replacementSnippet:
            editablePatches[singleProposal.findingId] !== undefined
              ? editablePatches[singleProposal.findingId]
              : singleProposal.replacementSnippet,
          commitMessage: singleProposal.commitMessage,
          prTitle: prTitle.trim(),
          prDescription: prDescription.trim(),
        })

        setCreatedPr({
          prUrl: res.result.prUrl,
          prNumber: res.result.prNumber,
          branch: res.result.branch,
          state: res.result.state,
          fixedCount: 1,
        })
        onPrCreated?.([singleProposal.findingId], res.result.prNumber, res.result.prUrl)
        success(`Pull Request #${res.result.prNumber} opened on GitHub`, 'PR Opened')
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create Pull Request'
      error(msg, 'PR Error')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleMergePr = async () => {
    if (!createdPr || !scanId) return
    setIsMerging(true)
    try {
      await scanApi.mergePr(scanId, createdPr.prNumber)
      setIsMerged(true)
      success(`Pull Request #${createdPr.prNumber} merged successfully`, 'Merged')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to merge Pull Request'
      error(msg, 'Merge Error')
    } finally {
      setIsMerging(false)
    }
  }

  const totalFixesCount =
    selectedScope === 'ALL' && batchProposal ? batchProposal.fixes.length : singleProposal ? 1 : 0
  const canCreate = Boolean(batchProposal?.canCreatePr ?? singleProposal?.canCreatePr)
  const targetBranch = batchProposal?.targetBranch || singleProposal?.targetBranch || 'main'
  const repoOwner = batchProposal?.repoOwner || singleProposal?.repoOwner
  const repoName = batchProposal?.repoName || singleProposal?.repoName

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs overflow-y-auto font-sans">
      <div className="relative w-full max-w-4xl bg-surface border border-border rounded-xl shadow-2xl overflow-hidden my-8 flex flex-col max-h-[92vh] text-text-primary">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-muted/20">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 rounded-lg bg-surface border border-border-subtle text-emerald-400 shrink-0">
              <RiGitPullRequestLine className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-text-primary truncate">
                Create Remediation Pull Request
              </h3>
              <p className="text-xs text-text-muted font-mono mt-0.5 truncate">
                {repoOwner && repoName ? `${repoOwner}/${repoName} • ` : ''}
                Target branch <span className="text-text-secondary">{targetBranch}</span>
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface transition-colors cursor-pointer"
            title="Close"
          >
            <RiCloseLine className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1 text-xs">
          {/* Scope Selector: Allows choosing to fix all or a specific vulnerability */}
          {availableFindings.length > 1 && !createdPr && (
            <div className="space-y-1.5 pb-3 border-b border-border-subtle">
              <label className="block text-[11px] font-mono text-text-muted">
                Remediation Target:
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedScope('ALL')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer border ${
                    selectedScope === 'ALL'
                      ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-medium'
                      : 'bg-surface border-border text-text-secondary hover:text-text-primary hover:bg-surface-hover'
                  }`}
                >
                  All Vulnerabilities ({availableFindings.length})
                </button>

                {availableFindings.map(f => {
                  const isSelected = selectedScope === f.id
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setSelectedScope(f.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer border flex items-center gap-1.5 ${
                        isSelected
                          ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-medium'
                          : 'bg-surface border-border text-text-secondary hover:text-text-primary hover:bg-surface-hover'
                      }`}
                    >
                      <span>{f.id}</span>
                      <span className="text-[10px] text-text-muted font-sans truncate max-w-[120px]">
                        {f.ruleName}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {isLoading ? (
            <div className="py-20 flex flex-col items-center justify-center space-y-3">
              <div className="w-6 h-6 border-2 border-border border-t-emerald-400 rounded-full animate-spin" />
              <p className="text-xs font-mono text-text-muted">
                {selectedScope === 'ALL'
                  ? `Preparing remediation patches for ${availableFindings.length} vulnerabilities...`
                  : `Preparing remediation patch for ${selectedScope}...`}
              </p>
            </div>
          ) : !batchProposal && !singleProposal ? (
            <div className="py-16 text-center space-y-3">
              <RiAlertLine className="w-6 h-6 text-danger mx-auto" />
              <p className="text-xs text-text-secondary font-mono">Unable to generate remediation proposal.</p>
              <Button variant="secondary" size="sm" onClick={onClose}>
                Close
              </Button>
            </div>
          ) : createdPr ? (
            /* Success State */
            <div className="py-12 flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <RiCheckLine className="w-6 h-6" />
              </div>
              <div className="space-y-1 max-w-md">
                <h4 className="text-base font-semibold text-text-primary">
                  Pull Request #{createdPr.prNumber} opened successfully
                </h4>
                <p className="text-xs text-text-muted">
                  Branch <span className="font-mono text-text-secondary">{createdPr.branch}</span> has been pushed to GitHub, resolving{' '}
                  <span className="font-semibold text-emerald-300 font-mono">
                    {createdPr.fixedCount} {createdPr.fixedCount === 1 ? 'vulnerability' : 'vulnerabilities'}
                  </span>.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-3">
                <a
                  href={createdPr.prUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-surface hover:bg-surface-hover text-text-primary font-mono text-xs border border-border transition-colors cursor-pointer"
                >
                  <RiGithubFill className="w-4 h-4" />
                  <span>View PR #{createdPr.prNumber} on GitHub</span>
                  <RiExternalLinkLine className="w-3.5 h-3.5 ml-0.5 text-text-muted" />
                </a>

                {isMerged ? (
                  <span className="inline-flex items-center gap-1.5 px-3.5 py-2 text-emerald-400 font-mono text-xs font-medium">
                    <RiCheckLine className="w-3.5 h-3.5" />
                    <span>Merged into {targetBranch}</span>
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={handleMergePr}
                    disabled={isMerging}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-medium transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
                  >
                    {isMerging ? (
                      <>
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        <span>Merging PR...</span>
                      </>
                    ) : (
                      <>
                        <RiGitMergeLine className="w-3.5 h-3.5" />
                        <span>Merge PR</span>
                      </>
                    )}
                  </button>
                )}

                <Button variant="outline" size="sm" onClick={onClose}>
                  Done
                </Button>
              </div>
            </div>
          ) : (
            <>
              {/* GitHub Authorization Bar */}
              {isCheckingAuth ? (
                <div className="p-3 rounded-lg bg-surface-muted/20 border border-border-subtle flex items-center gap-2 text-text-muted text-xs font-mono">
                  <div className="w-3.5 h-3.5 border-2 border-border border-t-text-primary rounded-full animate-spin" />
                  <span>Checking GitHub authorization...</span>
                </div>
              ) : ghStatus.connected ? (
                <div className="flex items-center justify-between p-3 rounded-lg bg-surface-muted/20 border border-border">
                  <div className="flex items-center gap-2.5">
                    {ghStatus.avatarUrl ? (
                      <img
                        src={ghStatus.avatarUrl}
                        alt={ghStatus.username || 'GitHub User'}
                        className="w-5 h-5 rounded-full border border-border"
                      />
                    ) : (
                      <div className="w-5 h-5 rounded-full bg-surface border border-border flex items-center justify-center text-text-secondary">
                        <RiGithubFill className="w-3 h-3" />
                      </div>
                    )}
                    <span className="text-xs text-text-secondary">
                      Connected to GitHub as <strong className="font-medium text-text-primary">@{ghStatus.username}</strong>
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={handleDisconnectGitHub}
                    className="text-[11px] font-mono text-text-muted hover:text-danger underline transition-colors cursor-pointer"
                  >
                    Disconnect
                  </button>
                </div>
              ) : (
                <div className="p-3.5 rounded-lg bg-surface-muted/20 border border-border space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-text-primary font-medium">
                      <RiGithubFill className="w-4 h-4 text-text-secondary" />
                      <span>GitHub Authorization</span>
                    </div>
                    <span className="text-[10px] font-mono text-text-muted">Required to open Pull Request</span>
                  </div>

                  {oauthConfig.configured ? (
                    <button
                      type="button"
                      onClick={handleOpenOAuthPopup}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-text font-medium text-xs transition-colors cursor-pointer"
                    >
                      <RiGithubFill className="w-4 h-4" />
                      <span>Authorize with GitHub</span>
                    </button>
                  ) : (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <div className="relative flex-1">
                          <input
                            type={showToken ? 'text' : 'password'}
                            value={inputToken}
                            onChange={e => setInputToken(e.target.value)}
                            placeholder="GitHub Personal Access Token (repo scope)..."
                            className="w-full pl-3 pr-8 py-1.5 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border"
                          />
                          <button
                            type="button"
                            onClick={() => setShowToken(!showToken)}
                            className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary cursor-pointer"
                          >
                            {showToken ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                          </button>
                        </div>

                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={handleAuthorizeGitHub}
                          disabled={isConnectingGh || !inputToken.trim()}
                        >
                          {isConnectingGh ? 'Connecting...' : 'Authorize'}
                        </Button>
                      </div>

                      <div className="flex items-center justify-between text-[11px] font-mono text-text-muted">
                        <span>Stored locally in session memory.</span>
                        <a
                          href="https://github.com/settings/tokens/new?scopes=repo&description=VulScan%20PR%20Bot"
                          target="_blank"
                          rel="noreferrer"
                          className="text-text-secondary hover:text-text-primary underline"
                        >
                          Generate token &rarr;
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Multi-Finding Navigation (When 'ALL' scope is active) */}
              {selectedScope === 'ALL' && batchProposal && batchProposal.fixes.length > 1 && (
                <div className="space-y-1.5">
                  <span className="text-[11px] font-mono text-text-muted">
                    Included Patches ({batchProposal.fixes.length}):
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                    {batchProposal.fixes.map((fix, idx) => {
                      const isSelected = idx === selectedFixIndex
                      return (
                        <button
                          key={fix.findingId}
                          type="button"
                          onClick={() => setSelectedFixIndex(idx)}
                          className={`flex flex-col text-left p-2.5 rounded-lg border transition-all cursor-pointer ${
                            isSelected
                              ? 'bg-surface border-emerald-500/50 shadow-xs ring-1 ring-emerald-500/20'
                              : 'bg-surface-muted/20 border-border hover:bg-surface-muted/40 hover:border-zinc-700'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1 mb-0.5">
                            <span className="font-mono font-semibold text-[11px] text-text-primary">
                              {fix.findingId}
                            </span>
                            <span className="text-[9px] font-mono text-text-muted">
                              {fix.severity}
                            </span>
                          </div>
                          <span className="text-[11px] font-medium text-text-secondary truncate">
                            {fix.ruleName}
                          </span>
                          <span className="text-[10px] font-mono text-text-muted truncate mt-0.5">
                            {fix.filePath}:{fix.line}
                          </span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Remediation Explanation */}
              {currentFix?.explanation && (
                <div className="bg-surface-muted/20 border border-border-subtle rounded-lg p-3 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-text-muted flex items-center gap-1.5">
                      <RiShieldCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{currentFix.findingId} • {currentFix.ruleName}</span>
                    </span>
                    <span className="font-mono text-[10px] text-text-muted">
                      {currentFix.filePath}:{currentFix.line}
                    </span>
                  </div>
                  <p className="text-text-secondary leading-relaxed font-sans">{currentFix.explanation}</p>
                </div>
              )}

              {/* Code Diff & Editable Patch Section */}
              {currentFix && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between border-b border-border-subtle pb-0">
                    <div className="flex items-center gap-5 text-xs font-mono">
                      <button
                        type="button"
                        onClick={() => setActiveTab('diff')}
                        className={`pb-2 transition-colors cursor-pointer border-b-2 -mb-px ${
                          activeTab === 'diff'
                            ? 'border-text-primary text-text-primary font-medium'
                            : 'border-transparent text-text-muted hover:text-text-secondary'
                        }`}
                      >
                        Diff View
                      </button>
                      <button
                        type="button"
                        onClick={() => setActiveTab('edit')}
                        className={`pb-2 transition-colors cursor-pointer border-b-2 -mb-px flex items-center gap-1.5 ${
                          activeTab === 'edit'
                            ? 'border-text-primary text-text-primary font-medium'
                            : 'border-transparent text-text-muted hover:text-text-secondary'
                        }`}
                      >
                        <RiEditLine className="w-3.5 h-3.5" />
                        <span>Edit Patch</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setActiveTab('context')}
                        className={`pb-2 transition-colors cursor-pointer border-b-2 -mb-px flex items-center gap-1.5 ${
                          activeTab === 'context'
                            ? 'border-text-primary text-text-primary font-medium'
                            : 'border-transparent text-text-muted hover:text-text-secondary'
                        }`}
                      >
                        <RiCodeBoxLine className="w-3.5 h-3.5" />
                        <span>Context Preview</span>
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        handleCopyCode(
                          editablePatches[currentFix.findingId] !== undefined
                            ? editablePatches[currentFix.findingId]
                            : currentFix.replacementSnippet
                        )
                      }
                      className="inline-flex items-center gap-1.5 text-text-muted hover:text-text-primary font-mono text-[11px] cursor-pointer pb-2"
                    >
                      {copied ? (
                        <>
                          <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <RiFileCopyLine className="w-3.5 h-3.5" />
                          <span>Copy Patch</span>
                        </>
                      )}
                    </button>
                  </div>

                  {activeTab === 'diff' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                      {/* Before / Vulnerable Code */}
                      <div className="bg-surface border border-rose-500/20 rounded-lg overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-rose-500/[0.04] border-b border-rose-500/20 text-rose-300 font-mono text-[11px] flex items-center justify-between">
                          <span>Original Code ({currentFix.filePath}:{currentFix.line})</span>
                          <span className="text-[10px] text-rose-400 font-semibold uppercase tracking-wider">Before</span>
                        </div>
                        <pre className="p-3 text-rose-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed flex-1">
                          {currentFix.searchSnippet}
                        </pre>
                      </div>

                      {/* After / Fixed Code */}
                      <div className="bg-surface border border-emerald-500/20 rounded-lg overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-emerald-500/[0.04] border-b border-emerald-500/20 text-emerald-300 font-mono text-[11px] flex items-center justify-between">
                          <span>Proposed Patch</span>
                          <span className="text-[10px] text-emerald-400 font-semibold uppercase tracking-wider">After</span>
                        </div>
                        <pre className="p-3 text-emerald-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed flex-1">
                          {editablePatches[currentFix.findingId] !== undefined
                            ? editablePatches[currentFix.findingId]
                            : currentFix.replacementSnippet}
                        </pre>
                      </div>
                    </div>
                  )}

                  {activeTab === 'edit' && (
                    <div className="space-y-2 pt-1">
                      <div className="flex items-center justify-between text-[11px] font-mono text-text-muted">
                        <span>Customize replacement code for {currentFix.findingId}:</span>
                        <button
                          type="button"
                          onClick={() => {
                            setEditablePatches(prev => ({
                              ...prev,
                              [currentFix.findingId]: currentFix.replacementSnippet,
                            }))
                          }}
                          className="text-text-secondary hover:text-text-primary underline cursor-pointer"
                        >
                          Reset patch
                        </button>
                      </div>
                      <textarea
                        rows={6}
                        value={
                          editablePatches[currentFix.findingId] !== undefined
                            ? editablePatches[currentFix.findingId]
                            : currentFix.replacementSnippet
                        }
                        onChange={e => {
                          const val = e.target.value
                          setEditablePatches(prev => ({
                            ...prev,
                            [currentFix.findingId]: val,
                          }))
                        }}
                        className="w-full p-3 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border leading-relaxed"
                        placeholder="Write custom patch replacement..."
                      />
                    </div>
                  )}

                  {activeTab === 'context' && (
                    <div className="pt-1">
                      <CodeBlock
                        code={currentFix.fixedContext}
                        language="javascript"
                        variant="bordered"
                        filePath={currentFix.filePath}
                      />
                    </div>
                  )}
                </div>
              )}

              {/* PR Submission Form */}
              <form onSubmit={handleCreatePr} className="space-y-3.5 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-text-muted font-mono text-[11px] mb-1">
                      Target Branch
                    </label>
                    <div className="flex items-center gap-2 px-3 py-1.5 bg-surface border border-border rounded-lg text-text-secondary font-mono text-xs">
                      <RiGitBranchLine className="w-3.5 h-3.5 text-text-muted shrink-0" />
                      <span className="truncate">{targetBranch}</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-text-muted font-mono text-[11px] mb-1">
                      Fix Branch Name
                    </label>
                    <input
                      type="text"
                      value={branchName}
                      onChange={e => setBranchName(e.target.value)}
                      required
                      className="w-full px-3 py-1.5 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-text-muted font-mono text-[11px] mb-1">Pull Request Title</label>
                  <input
                    type="text"
                    value={prTitle}
                    onChange={e => setPrTitle(e.target.value)}
                    required
                    className="w-full px-3 py-1.5 bg-surface border border-border rounded-lg text-text-primary font-sans text-xs focus:outline-none focus:border-border"
                  />
                </div>

                <div>
                  <label className="block text-text-muted font-mono text-[11px] mb-1">
                    Pull Request Description
                  </label>
                  <textarea
                    rows={3}
                    value={prDescription}
                    onChange={e => setPrDescription(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border leading-relaxed"
                  />
                </div>

                {/* Footer Buttons */}
                <div className="flex items-center justify-end gap-3 pt-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={onClose}
                    disabled={isSubmitting}
                  >
                    Cancel
                  </Button>

                  <button
                    type="submit"
                    disabled={isSubmitting || (!ghStatus.connected && !inputToken.trim()) || !canCreate}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-medium transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                  >
                    {isSubmitting ? (
                      <>
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        <span>Creating Pull Request...</span>
                      </>
                    ) : (
                      <>
                        <RiGitPullRequestLine className="w-3.5 h-3.5" />
                        <span>
                          {totalFixesCount > 1
                            ? `Create Pull Request (${totalFixesCount} Fixes)`
                            : 'Create Pull Request'}
                        </span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
