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
} from '@remixicon/react'
import { scanApi, githubApi, type SecurityFixProposal, type FindingItem } from '../../services/api'
import { useToast } from '../../context/ToastContext'
import { CodeBlock } from '../atoms/CodeBlock'
import { Button } from '../atoms/Button'

interface FixPrModalProps {
  isOpen: boolean
  onClose: () => void
  scanId: string
  finding: FindingItem | null
  onPrCreated?: (findingId: string, prNumber: number, prUrl: string) => void
}

export const FixPrModal: React.FC<FixPrModalProps> = ({
  isOpen,
  onClose,
  scanId,
  finding,
  onPrCreated,
}) => {
  const { success, error, info } = useToast()

  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [proposal, setProposal] = useState<SecurityFixProposal | null>(null)
  const [activeTab, setActiveTab] = useState<'diff' | 'edit' | 'context'>('diff')

  // Editable replacement snippet state
  const [replacementSnippet, setReplacementSnippet] = useState('')

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

  // Fetch fix proposal when modal opens
  useEffect(() => {
    if (!isOpen || !finding || !scanId) {
      setProposal(null)
      setCreatedPr(null)
      return
    }

    let isMounted = true
    setIsLoading(true)
    setCreatedPr(null)

    scanApi
      .generateFix(scanId, finding.id)
      .then(res => {
        if (!isMounted) return
        setProposal(res.proposal)
        setReplacementSnippet(res.proposal.replacementSnippet)
        setBranchName(res.proposal.suggestedBranch)
        setPrTitle(res.proposal.prTitle)
        setPrDescription(res.proposal.prDescription)
      })
      .catch(err => {
        if (!isMounted) return
        const msg = err instanceof Error ? err.message : 'Failed to generate remediation proposal'
        error(msg, 'Error')
      })
      .finally(() => {
        if (isMounted) setIsLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [isOpen, finding, scanId, error])

  if (!isOpen || !finding) return null

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
    if (!proposal) return

    if (!ghStatus.connected && !inputToken.trim()) {
      error('Please connect your GitHub authorization first.', 'Authorization Required')
      return
    }

    setIsSubmitting(true)

    try {
      const res = await scanApi.createPr(scanId, finding.id, {
        githubToken: inputToken.trim() || undefined,
        targetBranch: proposal.targetBranch,
        branchName: branchName.trim(),
        filePath: proposal.filePath,
        searchSnippet: proposal.searchSnippet,
        replacementSnippet: replacementSnippet.trim() || proposal.replacementSnippet,
        commitMessage: proposal.commitMessage,
        prTitle: prTitle.trim(),
        prDescription: prDescription.trim(),
      })

      setCreatedPr(res.result)
      onPrCreated?.(finding.id, res.result.prNumber, res.result.prUrl)
      success(`Pull Request #${res.result.prNumber} opened on GitHub`, 'PR Opened')
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs overflow-y-auto font-sans">
      <div className="relative w-full max-w-3xl bg-surface border border-border rounded-xl shadow-2xl overflow-hidden my-8 flex flex-col max-h-[90vh] text-text-primary">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-muted/30">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 rounded-lg bg-surface border border-border-subtle text-text-primary shrink-0">
              <RiGitPullRequestLine className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-medium text-text-primary truncate">
                Remediate Finding
              </h3>
              <p className="text-xs text-text-muted font-mono mt-0.5 truncate">
                {finding.filePath}:{finding.line} &bull; {finding.ruleName}
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
            <div className="py-20 flex flex-col items-center justify-center space-y-3">
              <div className="w-5 h-5 border-2 border-border border-t-text-primary rounded-full animate-spin" />
              <p className="text-xs font-mono text-text-muted">
                Generating remediation patch...
              </p>
            </div>
          ) : !proposal ? (
            <div className="py-16 text-center space-y-3">
              <RiAlertLine className="w-6 h-6 text-danger mx-auto" />
              <p className="text-xs text-text-secondary font-mono">Unable to generate fix proposal for this finding.</p>
              <Button variant="secondary" size="sm" onClick={onClose}>
                Close
              </Button>
            </div>
          ) : createdPr ? (
            /* Success State - Clean & Unboxed */
            <div className="py-14 flex flex-col items-center justify-center text-center space-y-4">
              <RiCheckLine className="w-8 h-8 text-emerald-500 shrink-0" />
              <div className="space-y-1 max-w-sm">
                <h4 className="text-sm font-medium text-text-primary">
                  Pull request #{createdPr.prNumber} opened
                </h4>
                <p className="text-xs text-text-muted">
                  Branch <span className="font-mono text-text-secondary">{createdPr.branch}</span> has been pushed to GitHub.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-3">
                <a
                  href={createdPr.prUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-hover text-text-primary font-mono text-xs border border-border transition-colors cursor-pointer"
                >
                  <span>View on GitHub</span>
                  <RiExternalLinkLine className="w-3.5 h-3.5" />
                </a>

                {isMerged ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-emerald-400 font-mono text-xs">
                    <RiCheckLine className="w-3.5 h-3.5" />
                    <span>Merged into {proposal.targetBranch}</span>
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={handleMergePr}
                    disabled={isMerging}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {isMerging ? (
                      <>
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        <span>Merging...</span>
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
                <div className="flex items-center justify-between p-3 rounded-lg bg-surface-muted/30 border border-border">
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
                    <span className="text-[10px] font-mono text-text-muted">Required to open PR</span>
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

              {/* Remediation Explanation */}
              {proposal.explanation && (
                <div className="bg-surface-muted/20 border border-border-subtle rounded-lg p-3.5 space-y-1">
                  <span className="font-mono text-[11px] text-text-muted">Explanation</span>
                  <p className="text-text-secondary leading-relaxed font-sans">{proposal.explanation}</p>
                </div>
              )}

              {/* Code Diff & Editable Patch Section */}
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
                    onClick={() => handleCopyCode(replacementSnippet || proposal.replacementSnippet)}
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
                        <span>Original Code</span>
                        <span className="text-[10px] text-rose-400 font-semibold">Before</span>
                      </div>
                      <pre className="p-3 text-rose-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed flex-1">
                        {proposal.searchSnippet}
                      </pre>
                    </div>

                    {/* After / Fixed Code */}
                    <div className="bg-surface border border-emerald-500/20 rounded-lg overflow-hidden flex flex-col">
                      <div className="px-3 py-1.5 bg-emerald-500/[0.06] border-b border-emerald-500/20 text-emerald-300 font-mono text-[11px] flex items-center justify-between">
                        <span>Proposed Patch</span>
                        <span className="text-[10px] text-emerald-400 font-semibold">After</span>
                      </div>
                      <pre className="p-3 text-emerald-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed flex-1">
                        {replacementSnippet}
                      </pre>
                    </div>
                  </div>
                )}

                {activeTab === 'edit' && (
                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between text-[11px] font-mono text-text-muted">
                      <span>Editable Patch Replacement:</span>
                      <button
                        type="button"
                        onClick={() => setReplacementSnippet(proposal.replacementSnippet)}
                        className="text-text-secondary hover:text-text-primary underline cursor-pointer"
                      >
                        Reset to default patch
                      </button>
                    </div>
                    <textarea
                      rows={6}
                      value={replacementSnippet}
                      onChange={e => setReplacementSnippet(e.target.value)}
                      className="w-full p-3 bg-surface border border-border rounded-lg text-text-primary font-mono text-xs focus:outline-none focus:border-border leading-relaxed selection:bg-rose-500/20"
                      placeholder="Write or customize replacement code snippet..."
                    />
                  </div>
                )}

                {activeTab === 'context' && (
                  <div className="pt-1">
                    <CodeBlock
                      code={proposal.fixedContext}
                      language="javascript"
                      variant="bordered"
                      filePath={proposal.filePath}
                    />
                  </div>
                )}
              </div>

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
                        {proposal.repoOwner ? `${proposal.repoOwner}/${proposal.repoName}` : 'Repository'} :{' '}
                        {proposal.targetBranch}
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
                    Pull Request Description
                  </label>
                  <textarea
                    rows={3}
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
                    disabled={isSubmitting || (!ghStatus.connected && !inputToken.trim()) || !proposal.canCreatePr}
                    className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-medium transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                  >
                    {isSubmitting ? (
                      <>
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        <span>Opening PR...</span>
                      </>
                    ) : (
                      <>
                        <RiGitPullRequestLine className="w-3.5 h-3.5" />
                        <span>Open Pull Request</span>
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
