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
  RiFileList3Line,
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

  const isBatchMode = !finding && findings.length > 0
  const activeFindingsList = isBatchMode ? findings : finding ? [finding] : []

  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Proposals
  const [singleProposal, setSingleProposal] = useState<SecurityFixProposal | null>(null)
  const [batchProposal, setBatchProposal] = useState<BatchSecurityFixProposal | null>(null)

  // Active selected finding in batch mode
  const [selectedFixIndex, setSelectedFixIndex] = useState(0)

  // Editable patches dictionary: findingId -> replacementSnippet
  const [editablePatches, setEditablePatches] = useState<Record<string, string>>({})

  const [activeTab, setActiveTab] = useState<'diff' | 'edit' | 'context' | 'overview'>('diff')

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

  // Fetch fix proposals (batch or single) when modal opens
  useEffect(() => {
    if (!isOpen || !scanId || activeFindingsList.length === 0) {
      setSingleProposal(null)
      setBatchProposal(null)
      setCreatedPr(null)
      return
    }

    let isMounted = true
    setIsLoading(true)
    setCreatedPr(null)
    setSelectedFixIndex(0)

    if (isBatchMode || activeFindingsList.length > 1) {
      // Batch mode: remediate all requested findings
      const targetIds = activeFindingsList.map(f => f.id)
      scanApi
        .generateBatchFixes(scanId, targetIds)
        .then(res => {
          if (!isMounted) return
          setBatchProposal(res.proposal)
          setSingleProposal(null)
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
          const msg = err instanceof Error ? err.message : 'Failed to generate batch remediation proposal'
          error(msg, 'Error')
        })
        .finally(() => {
          if (isMounted) setIsLoading(false)
        })
    } else {
      // Single finding mode
      const singleFinding = activeFindingsList[0]
      scanApi
        .generateFix(scanId, singleFinding.id)
        .then(res => {
          if (!isMounted) return
          setSingleProposal(res.proposal)
          setBatchProposal(null)
          setBranchName(res.proposal.suggestedBranch)
          setPrTitle(res.proposal.prTitle)
          setPrDescription(res.proposal.prDescription)
          setEditablePatches({ [singleFinding.id]: res.proposal.replacementSnippet })
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
  }, [isOpen, scanId, finding, findings.length])

  if (!isOpen || activeFindingsList.length === 0) return null

  // Active current fix item
  const currentFix: FindingFixItem | SecurityFixProposal | null = batchProposal
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
      if (batchProposal && batchProposal.fixes.length > 0) {
        // Multi-finding Batch Pull Request
        const patches = batchProposal.fixes.map(fix => ({
          findingId: fix.findingId,
          filePath: fix.filePath,
          searchSnippet: fix.searchSnippet,
          replacementSnippet: editablePatches[fix.findingId] !== undefined ? editablePatches[fix.findingId] : fix.replacementSnippet,
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
        success(`Pull Request #${res.result.prNumber} opened on GitHub covering ${fixedFindingIds.length} vulnerabilities!`, 'PR Opened')
      } else if (singleProposal) {
        // Single finding Pull Request
        const res = await scanApi.createPr(scanId, singleProposal.findingId, {
          githubToken: inputToken.trim() || undefined,
          targetBranch: singleProposal.targetBranch,
          branchName: branchName.trim(),
          filePath: singleProposal.filePath,
          searchSnippet: singleProposal.searchSnippet,
          replacementSnippet: editablePatches[singleProposal.findingId] !== undefined ? editablePatches[singleProposal.findingId] : singleProposal.replacementSnippet,
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

  const totalFixesCount = batchProposal ? batchProposal.fixes.length : singleProposal ? 1 : 0
  const canCreate = Boolean(batchProposal?.canCreatePr ?? singleProposal?.canCreatePr)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs overflow-y-auto font-sans">
      <div className="relative w-full max-w-4xl bg-surface border border-border rounded-xl shadow-2xl overflow-hidden my-8 flex flex-col max-h-[92vh] text-text-primary">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-muted/30">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 rounded-lg bg-surface border border-border-subtle text-emerald-400 shrink-0">
              <RiGitPullRequestLine className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-text-primary truncate">
                  {totalFixesCount > 1
                    ? `Automated Security Remediation (${totalFixesCount} Vulnerabilities)`
                    : 'Remediate Vulnerability Finding'}
                </h3>
                {totalFixesCount > 1 && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                    Comprehensive Batch PR
                  </span>
                )}
              </div>
              <p className="text-xs text-text-muted font-mono mt-0.5 truncate">
                {batchProposal
                  ? `Resolves ${batchProposal.totalFindings} vulnerabilities across target branch '${batchProposal.targetBranch}'`
                  : finding
                  ? `${finding.filePath}:${finding.line} • ${finding.ruleName}`
                  : 'Automated patch generation and Pull Request delivery'}
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
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {isLoading ? (
            <div className="py-24 flex flex-col items-center justify-center space-y-3">
              <div className="w-6 h-6 border-2 border-border border-t-emerald-400 rounded-full animate-spin" />
              <p className="text-xs font-mono text-text-muted">
                {activeFindingsList.length > 1
                  ? `Analyzing and generating security patches for ${activeFindingsList.length} vulnerabilities...`
                  : 'Generating security patch and verification advisory...'}
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
            <div className="py-14 flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <RiCheckLine className="w-6 h-6" />
              </div>
              <div className="space-y-1 max-w-md">
                <h4 className="text-base font-semibold text-text-primary">
                  Pull request #{createdPr.prNumber} opened successfully!
                </h4>
                <p className="text-xs text-text-muted">
                  Branch <span className="font-mono text-text-secondary">{createdPr.branch}</span> has been pushed to GitHub, resolving{' '}
                  <span className="font-semibold text-emerald-300 font-mono">{createdPr.fixedCount} security {createdPr.fixedCount === 1 ? 'vulnerability' : 'vulnerabilities'}</span>.
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
                    <span>Merged into {batchProposal?.targetBranch || singleProposal?.targetBranch}</span>
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
                <div className="p-3 rounded-lg bg-surface-muted/30 border border-border-subtle flex items-center gap-2 text-text-muted text-xs font-mono">
                  <div className="w-3.5 h-3.5 border-2 border-border border-t-text-primary rounded-full animate-spin" />
                  <span>Checking GitHub authorization...</span>
                </div>
              ) : ghStatus.connected ? (
                <div className="flex items-center justify-between p-3.5 rounded-lg bg-surface-muted/30 border border-border">
                  <div className="flex items-center gap-2.5">
                    {ghStatus.avatarUrl ? (
                      <img
                        src={ghStatus.avatarUrl}
                        alt={ghStatus.username || 'GitHub User'}
                        className="w-6 h-6 rounded-full border border-border"
                      />
                    ) : (
                      <div className="w-6 h-6 rounded-full bg-surface border border-border flex items-center justify-center text-text-secondary">
                        <RiGithubFill className="w-3.5 h-3.5" />
                      </div>
                    )}
                    <div>
                      <span className="text-xs font-medium text-text-primary">
                        Connected as @{ghStatus.username}
                      </span>
                    </div>
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
                <div className="p-4 rounded-lg bg-surface-muted/30 border border-border space-y-3">
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
                      className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-text font-medium text-xs transition-colors cursor-pointer"
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
                            className="w-full pl-3 pr-8 py-2 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border"
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
                        <span>Token is securely stored locally in your session.</span>
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

              {/* Multi-Finding Navigation Bar (in Batch Mode) */}
              {batchProposal && batchProposal.fixes.length > 1 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono text-text-muted">
                    <span className="flex items-center gap-1.5">
                      <RiFileList3Line className="w-3.5 h-3.5 text-text-secondary" />
                      <span>Included Vulnerability Fixes ({batchProposal.fixes.length}):</span>
                    </span>
                    <span>Click to inspect & edit individual patch</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                    {batchProposal.fixes.map((fix, idx) => {
                      const isSelected = idx === selectedFixIndex
                      const sevColor =
                        fix.severity === 'CRITICAL'
                          ? 'text-rose-400 border-rose-500/30 bg-rose-500/10'
                          : fix.severity === 'HIGH'
                          ? 'text-orange-400 border-orange-500/30 bg-orange-500/10'
                          : 'text-amber-400 border-amber-500/30 bg-amber-500/10'

                      return (
                        <button
                          key={fix.findingId}
                          type="button"
                          onClick={() => {
                            setSelectedFixIndex(idx)
                            if (activeTab === 'overview') setActiveTab('diff')
                          }}
                          className={`flex flex-col text-left p-2.5 rounded-lg border transition-all cursor-pointer ${
                            isSelected
                              ? 'bg-surface border-emerald-500/60 shadow-sm ring-1 ring-emerald-500/30'
                              : 'bg-surface-muted/20 border-border hover:bg-surface-muted/40 hover:border-zinc-700'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1 mb-1">
                            <span className="font-mono font-semibold text-[11px] text-text-primary">
                              {fix.findingId}
                            </span>
                            <span className={`px-1.5 py-0.2 text-[9px] font-mono font-semibold rounded border ${sevColor}`}>
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
                <div className="bg-surface-muted/20 border border-border-subtle rounded-lg p-3.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-text-muted flex items-center gap-1.5">
                      <RiShieldCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                      <span>
                        Remediation Details for {currentFix.findingId} ({currentFix.ruleName})
                      </span>
                    </span>
                    <span className="font-mono text-[10px] text-text-muted">{currentFix.filePath}:{currentFix.line}</span>
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
                        <div className="px-3 py-1.5 bg-rose-500/[0.06] border-b border-rose-500/20 text-rose-300 font-mono text-[11px] flex items-center justify-between">
                          <span>Original Code ({currentFix.filePath}:{currentFix.line})</span>
                          <span className="text-[10px] text-rose-400 font-semibold">Before</span>
                        </div>
                        <pre className="p-3 text-rose-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed flex-1">
                          {currentFix.searchSnippet}
                        </pre>
                      </div>

                      {/* After / Fixed Code */}
                      <div className="bg-surface border border-emerald-500/20 rounded-lg overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-emerald-500/[0.06] border-b border-emerald-500/20 text-emerald-300 font-mono text-[11px] flex items-center justify-between">
                          <span>Proposed Patch</span>
                          <span className="text-[10px] text-emerald-400 font-semibold">After</span>
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
                        <span>Editable Patch Replacement for {currentFix.findingId}:</span>
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
                          Reset to default patch
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
                        placeholder="Write or customize replacement code snippet..."
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
              <form onSubmit={handleCreatePr} className="space-y-4 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-text-muted font-mono text-[11px] mb-1.5">
                      Target Repository & Branch
                    </label>
                    <div className="flex items-center gap-2 px-3 py-2 bg-surface border border-border rounded-lg text-text-secondary font-mono text-xs">
                      <RiGitBranchLine className="w-3.5 h-3.5 text-text-muted shrink-0" />
                      <span className="truncate">
                        {batchProposal?.repoOwner
                          ? `${batchProposal.repoOwner}/${batchProposal.repoName}`
                          : singleProposal?.repoOwner
                          ? `${singleProposal.repoOwner}/${singleProposal.repoName}`
                          : 'Repository'}{' '}
                        : {batchProposal?.targetBranch || singleProposal?.targetBranch}
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-text-muted font-mono text-[11px] mb-1.5">
                      Fix Branch Name
                    </label>
                    <input
                      type="text"
                      value={branchName}
                      onChange={e => setBranchName(e.target.value)}
                      required
                      className="w-full px-3 py-2 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-text-muted font-mono text-[11px] mb-1.5">Pull Request Title</label>
                  <input
                    type="text"
                    value={prTitle}
                    onChange={e => setPrTitle(e.target.value)}
                    required
                    className="w-full px-3 py-2 bg-surface border border-border rounded-lg text-text-primary font-sans text-xs focus:outline-none focus:border-border"
                  />
                </div>

                <div>
                  <label className="block text-text-muted font-mono text-[11px] mb-1.5">
                    Pull Request Description (Markdown)
                  </label>
                  <textarea
                    rows={4}
                    value={prDescription}
                    onChange={e => setPrDescription(e.target.value)}
                    className="w-full px-3 py-2 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border leading-relaxed"
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
                        <span>Opening Pull Request...</span>
                      </>
                    ) : (
                      <>
                        <RiGitPullRequestLine className="w-3.5 h-3.5" />
                        <span>
                          {totalFixesCount > 1
                            ? `Open Batch Pull Request (${totalFixesCount} Fixes)`
                            : 'Open Pull Request'}
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
