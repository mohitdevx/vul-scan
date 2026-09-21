import React, { useState, useEffect } from 'react'
import {
  RiCloseLine,
  RiGitPullRequestLine,
  RiGitBranchLine,
  RiCheckLine,
  RiFileCopyLine,
  RiExternalLinkLine,
  RiLoader4Line,
  RiShieldCheckLine,
  RiEyeLine,
  RiEyeOffLine,
  RiCodeBoxLine,
  RiAlertLine,
  RiGithubFill,
  RiGitMergeLine,
} from '@remixicon/react'
import { scanApi, githubApi, type SecurityFixProposal, type FindingItem } from '../../services/api'
import { useToast } from '../../context/ToastContext'

interface FixPrModalProps {
  isOpen: boolean
  onClose: () => void
  scanId: string
  finding: FindingItem | null
}

export const FixPrModal: React.FC<FixPrModalProps> = ({
  isOpen,
  onClose,
  scanId,
  finding,
}) => {
  const { success, error, info } = useToast()

  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [proposal, setProposal] = useState<SecurityFixProposal | null>(null)
  const [activeTab, setActiveTab] = useState<'diff' | 'preview'>('diff')

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

    // Check current connection status
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

    // Check if OAuth URL is configured
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
        success(`GitHub authorized as @${event.data.username}! You can now open PRs with 1-click.`, 'Connected')
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

  // Fetch AI-generated fix when modal opens
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
        setBranchName(res.proposal.suggestedBranch)
        setPrTitle(res.proposal.prTitle)
        setPrDescription(res.proposal.prDescription)
      })
      .catch(err => {
        if (!isMounted) return
        const msg = err instanceof Error ? err.message : 'Failed to generate AI fix'
        error(msg, 'Fix Generation Error')
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
    success('Copied to clipboard', 'Success')
  }

  // Authorize GitHub account once
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
      success(`GitHub authorized as @${res.username}! You can now open PRs with 1-click.`, 'Connected')
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
      info('GitHub authorization disconnected', 'Disconnected')
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
        replacementSnippet: proposal.replacementSnippet,
        commitMessage: proposal.commitMessage,
        prTitle: prTitle.trim(),
        prDescription: prDescription.trim(),
      })

      setCreatedPr(res.result)
      success(`Pull Request #${res.result.prNumber} created on GitHub!`, 'PR Opened')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create Pull Request'
      error(msg, 'PR Creation Error')
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
      success(`Pull Request #${createdPr.prNumber} merged successfully into target branch!`, 'Merged')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to merge Pull Request'
      error(msg, 'Merge Error')
    } finally {
      setIsMerging(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-[#09090b] border border-[#27272a] rounded-2xl shadow-2xl overflow-hidden my-8 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#27272a] bg-[#121215]/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <RiGitPullRequestLine className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                <span>AI Automated Remediation & GitHub Pull Request</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                  qwen2.5-coder:3b
                </span>
              </h3>
              <p className="text-xs text-zinc-400 font-mono mt-0.5 truncate max-w-xl">
                {finding.filePath}:{finding.line} &bull; {finding.ruleName}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            <RiCloseLine className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {isLoading ? (
            <div className="py-20 flex flex-col items-center justify-center space-y-4">
              <RiLoader4Line className="w-8 h-8 text-zinc-400 animate-spin" />
              <div className="text-center">
                <p className="text-sm text-zinc-200 font-medium">Synthesizing Security Remediation</p>
                <p className="text-xs text-zinc-500 mt-1">
                  Local AI engine is analyzing taint flow and generating a hardened patch...
                </p>
              </div>
            </div>
          ) : !proposal ? (
            <div className="py-16 text-center space-y-3">
              <RiAlertLine className="w-8 h-8 text-rose-400 mx-auto" />
              <p className="text-sm text-zinc-300">Unable to generate fix proposal for this finding.</p>
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg font-mono text-xs cursor-pointer"
              >
                Close
              </button>
            </div>
          ) : createdPr ? (
            /* Success State */
            <div className="py-10 px-6 text-center space-y-5 bg-emerald-950/10 border border-emerald-500/20 rounded-xl">
              <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto">
                <RiCheckLine className="w-6 h-6" />
              </div>
              <div>
                <h4 className="text-base font-semibold text-zinc-100">Pull Request Opened Successfully!</h4>
                <p className="text-xs text-zinc-400 mt-1 max-w-md mx-auto">
                  A new branch was pushed and a Pull Request with the AI security fix was created on GitHub.
                </p>
              </div>

              <div className="inline-flex items-center gap-2 p-3 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 font-mono text-xs">
                <RiGitBranchLine className="w-4 h-4 text-zinc-500" />
                <span>Branch: {createdPr.branch}</span>
                <span className="text-zinc-600">&bull;</span>
                <span className="text-emerald-400 font-semibold">PR #{createdPr.prNumber}</span>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <a
                  href={createdPr.prUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs transition-colors cursor-pointer border border-zinc-700"
                >
                  <span>View on GitHub</span>
                  <RiExternalLinkLine className="w-4 h-4" />
                </a>

                {isMerged ? (
                  <div className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500/20 text-emerald-300 font-medium text-xs border border-emerald-500/30">
                    <RiCheckLine className="w-4 h-4" />
                    <span>Merged into {proposal.targetBranch}</span>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={handleMergePr}
                    disabled={isMerging}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {isMerging ? (
                      <>
                        <RiLoader4Line className="w-4 h-4 animate-spin" />
                        <span>Merging PR...</span>
                      </>
                    ) : (
                      <>
                        <RiGitMergeLine className="w-4 h-4" />
                        <span>Merge Pull Request</span>
                      </>
                    )}
                  </button>
                )}

                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-400 text-xs transition-colors cursor-pointer border border-zinc-800"
                >
                  Done
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* GitHub Authorization Banner - The "Butter Experience" */}
              {isCheckingAuth ? (
                <div className="p-3.5 rounded-xl bg-[#121215] border border-[#27272a] flex items-center gap-2 text-zinc-400">
                  <RiLoader4Line className="w-4 h-4 animate-spin text-zinc-500" />
                  <span>Checking GitHub authorization...</span>
                </div>
              ) : ghStatus.connected ? (
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-[#121215] border border-emerald-500/20">
                  <div className="flex items-center gap-3">
                    {ghStatus.avatarUrl ? (
                      <img
                        src={ghStatus.avatarUrl}
                        alt={ghStatus.username || 'GitHub User'}
                        className="w-7 h-7 rounded-full border border-zinc-700"
                      />
                    ) : (
                      <div className="w-7 h-7 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-zinc-300">
                        <RiGithubFill className="w-4 h-4" />
                      </div>
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-zinc-200">
                          Authorized as @{ghStatus.username}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          Active &bull; 1-Click PR Enabled
                        </span>
                      </div>
                      <p className="text-[11px] text-zinc-500 mt-0.5">
                        Pull requests will be automatically branched, pushed, and opened via this account without asking for tokens.
                      </p>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleDisconnectGitHub}
                    className="text-[11px] font-mono text-zinc-500 hover:text-rose-400 underline transition-colors cursor-pointer"
                  >
                    Disconnect
                  </button>
                </div>
              ) : (
                /* One-time GitHub Authorization setup */
                <div className="p-5 rounded-xl bg-[#121215] border border-[#27272a] space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-zinc-200 font-medium">
                      <RiGithubFill className="w-4 h-4 text-zinc-300" />
                      <span>One-Time GitHub Authorization</span>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-500">Authorize once &bull; Works seamlessly forever</span>
                  </div>

                  <p className="text-zinc-400 text-xs leading-relaxed">
                    Authorize your GitHub account once to enable instant, zero-prompt Pull Request creation directly to your repositories.
                  </p>

                  {/* Primary OAuth Button */}
                  {oauthConfig.configured ? (
                    <div className="pt-1">
                      <button
                        type="button"
                        onClick={handleOpenOAuthPopup}
                        className="w-full flex items-center justify-center gap-2.5 px-5 py-3 rounded-xl bg-zinc-100 hover:bg-white text-zinc-900 font-semibold text-xs transition-colors shadow-md cursor-pointer"
                      >
                        <RiGithubFill className="w-4 h-4" />
                        <span>Authorize on GitHub &rarr;</span>
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <div className="relative flex-1">
                          <input
                            type={showToken ? 'text' : 'password'}
                            value={inputToken}
                            onChange={e => setInputToken(e.target.value)}
                            placeholder="Paste your GitHub Personal Access Token (with repo scope)..."
                            className="w-full pl-3 pr-9 py-2 bg-[#09090b] border border-[#27272a] rounded-lg text-zinc-200 font-mono text-xs focus:outline-none focus:border-zinc-500"
                          />
                          <button
                            type="button"
                            onClick={() => setShowToken(!showToken)}
                            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                          >
                            {showToken ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                          </button>
                        </div>

                        <button
                          type="button"
                          onClick={handleAuthorizeGitHub}
                          disabled={isConnectingGh || !inputToken.trim()}
                          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-medium text-xs transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isConnectingGh ? (
                            <>
                              <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              <span>Linking...</span>
                            </>
                          ) : (
                            <span>Authorize Account</span>
                          )}
                        </button>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-zinc-500">
                        <span className="text-zinc-500">
                          To enable the native OAuth button, set <code className="text-zinc-400">GITHUB_CLIENT_ID</code> in backend/.env
                        </span>
                        <a
                          href="https://github.com/settings/tokens/new?scopes=repo&description=VulnScan%20AI%20PR%20Bot"
                          target="_blank"
                          rel="noreferrer"
                          className="text-zinc-400 hover:text-zinc-200 underline decoration-zinc-700"
                        >
                          Generate token &rarr;
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Security Advisory Rationale */}
              <div className="bg-[#121215] border border-[#27272a] rounded-xl p-4 space-y-2">
                <div className="flex items-center gap-2 text-zinc-300 font-medium">
                  <RiShieldCheckLine className="w-4 h-4 text-emerald-400" />
                  <span className="tracking-wide">AI Remediation Rationale</span>
                </div>
                <p className="text-zinc-400 leading-relaxed font-sans">{proposal.explanation}</p>
              </div>

              {/* Code Diff Section */}
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-0">
                  <div className="flex items-center gap-6">
                    <button
                      type="button"
                      onClick={() => setActiveTab('diff')}
                      className={`pb-2 text-xs font-mono transition-all cursor-pointer border-b-2 -mb-px ${
                        activeTab === 'diff'
                          ? 'border-zinc-100 text-zinc-100 font-semibold'
                          : 'border-transparent text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      Side-by-Side Diff
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab('preview')}
                      className={`pb-2 text-xs font-mono transition-all cursor-pointer border-b-2 -mb-px ${
                        activeTab === 'preview'
                          ? 'border-zinc-100 text-zinc-100 font-semibold'
                          : 'border-transparent text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      Context Preview
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleCopyCode(proposal.replacementSnippet)}
                    className="inline-flex items-center gap-1.5 text-zinc-400 hover:text-zinc-200 font-mono text-[11px] cursor-pointer"
                  >
                    {copied ? (
                      <>
                        <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <RiFileCopyLine className="w-3.5 h-3.5" />
                        <span>Copy Replacement</span>
                      </>
                    )}
                  </button>
                </div>

                {activeTab === 'diff' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* Before / Vulnerable Code */}
                    <div className="bg-[#121215] border border-rose-500/30 rounded-xl overflow-hidden">
                      <div className="px-3.5 py-2 bg-rose-500/10 border-b border-rose-500/20 text-rose-400 font-mono text-[11px] font-medium flex items-center justify-between">
                        <span>Original Vulnerable Code</span>
                        <span className="text-[10px] uppercase tracking-wider">Before</span>
                      </div>
                      <pre className="p-4 text-rose-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                        {proposal.searchSnippet}
                      </pre>
                    </div>

                    {/* After / Fixed Code */}
                    <div className="bg-[#121215] border border-emerald-500/30 rounded-xl overflow-hidden">
                      <div className="px-3.5 py-2 bg-emerald-500/10 border-b border-emerald-500/20 text-emerald-400 font-mono text-[11px] font-medium flex items-center justify-between">
                        <span>Sanitized Secure Replacement</span>
                        <span className="text-[10px] uppercase tracking-wider">After</span>
                      </div>
                      <pre className="p-4 text-emerald-200/90 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                        {proposal.replacementSnippet}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <div className="bg-[#121215] border border-[#27272a] rounded-xl overflow-hidden">
                    <div className="px-3.5 py-2 bg-[#151518] border-b border-[#27272a] text-zinc-400 font-mono text-[11px] flex items-center gap-2">
                      <RiCodeBoxLine className="w-3.5 h-3.5 text-zinc-500" />
                      <span>{proposal.filePath} (Full Function Preview)</span>
                    </div>
                    <pre className="p-4 text-zinc-300 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed">
                      {proposal.fixedContext}
                    </pre>
                  </div>
                )}
              </div>

              {/* PR Submission Form */}
              <form onSubmit={handleCreatePr} className="space-y-4 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-zinc-400 font-mono text-[11px] mb-1.5">
                      Target Repository & Base Branch
                    </label>
                    <div className="flex items-center gap-2 px-3 py-2 bg-[#121215] border border-[#27272a] rounded-lg text-zinc-300 font-mono text-xs">
                      <RiGitBranchLine className="w-4 h-4 text-zinc-500" />
                      <span className="truncate">
                        {proposal.repoOwner ? `${proposal.repoOwner}/${proposal.repoName}` : 'Repository'} :{' '}
                        {proposal.targetBranch}
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-zinc-400 font-mono text-[11px] mb-1.5">
                      New Fix Branch Name
                    </label>
                    <input
                      type="text"
                      value={branchName}
                      onChange={e => setBranchName(e.target.value)}
                      required
                      className="w-full px-3 py-2 bg-[#121215] border border-[#27272a] rounded-lg text-zinc-200 font-mono text-xs focus:outline-none focus:border-zinc-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-zinc-400 font-mono text-[11px] mb-1.5">Pull Request Title</label>
                  <input
                    type="text"
                    value={prTitle}
                    onChange={e => setPrTitle(e.target.value)}
                    required
                    className="w-full px-3 py-2 bg-[#121215] border border-[#27272a] rounded-lg text-zinc-200 font-sans text-xs focus:outline-none focus:border-zinc-500"
                  />
                </div>

                <div>
                  <label className="block text-zinc-400 font-mono text-[11px] mb-1.5">
                    Pull Request Description (Markdown)
                  </label>
                  <textarea
                    rows={4}
                    value={prDescription}
                    onChange={e => setPrDescription(e.target.value)}
                    className="w-full px-3 py-2 bg-[#121215] border border-[#27272a] rounded-lg text-zinc-200 font-mono text-xs focus:outline-none focus:border-zinc-500 leading-relaxed"
                  />
                </div>

                {/* Submit button footer */}
                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    disabled={isSubmitting}
                    className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg font-medium text-xs transition-colors cursor-pointer"
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={isSubmitting || (!ghStatus.connected && !inputToken.trim()) || !proposal.canCreatePr}
                    className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                  >
                    {isSubmitting ? (
                      <>
                        <RiLoader4Line className="w-4 h-4 animate-spin" />
                        <span>Pushing branch & opening PR...</span>
                      </>
                    ) : (
                      <>
                        <RiGitPullRequestLine className="w-4 h-4" />
                        <span>Send Pull Request</span>
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
