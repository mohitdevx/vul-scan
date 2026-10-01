import React, { useState, useMemo } from 'react'
import {
  RiServerLine,
  RiAlertLine,
  RiDownloadLine,
  RiPlayFill,
  RiFileCopyLine,
  RiCheckLine,
  RiLockLine,
  RiLockUnlockLine,
  RiSparklingLine,
  RiTerminalBoxLine,
  RiInformationLine,
} from '@remixicon/react'
import {
  scanApi,
  type ApiAuditResponse,
  type DiscoveredEndpointItem,
  type ApiFindingItem,
  type McpTransaction,
  type ScanLogEntry,
} from '../../services/api'
import { useToast } from '../../context/ToastContext'
import { CodeBlock } from '../atoms/CodeBlock'
import { Button } from '../atoms/Button'

interface ApiTestingPanelProps {
  scanId: string
  repoUrl: string
  branch: string
}

export const ApiTestingPanel: React.FC<ApiTestingPanelProps> = ({ scanId, repoUrl, branch }) => {
  const toast = useToast()
  const [loading, setLoading] = useState(false)
  const [auditData, setAuditData] = useState<ApiAuditResponse | null>(null)
  const [targetBaseUrl, setTargetBaseUrl] = useState('http://localhost:3000')
  const [selectedMethod, setSelectedMethod] = useState<string>('ALL')
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'endpoints' | 'vulnerabilities' | 'mcp_console' | 'rules'>('endpoints')
  const [selectedEndpoint, setSelectedEndpoint] = useState<DiscoveredEndpointItem | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<ApiFindingItem | null>(null)
  const [selectedTransaction, setSelectedTransaction] = useState<McpTransaction | null>(null)
  const [copiedMcp, setCopiedMcp] = useState(false)
  const [copiedTransaction, setCopiedTransaction] = useState(false)

  const handleRunAudit = async () => {
    try {
      setLoading(true)
      const res = await scanApi.runApiAudit(scanId, {
        repoUrl,
        branch,
        targetBaseUrl,
      })
      setAuditData(res)
      if (res.endpoints.length > 0) {
        setSelectedEndpoint(res.endpoints[0])
      }
      if (res.findings.length > 0) {
        setSelectedFinding(res.findings[0])
      }
      if (res.mcpBundle?.transactions && res.mcpBundle.transactions.length > 0) {
        setSelectedTransaction(res.mcpBundle.transactions[0])
      }
      toast.success(
        `Discovered ${res.totalEndpoints} endpoints across ${res.totalFilesScanned} files with ${res.findings.length} security alerts.`
      )
    } catch (err: any) {
      toast.error(err.message || 'Failed to complete API security audit')
    } finally {
      setLoading(false)
    }
  }

  const handleExportRequestly = (format: 'rules' | 'mcp' = 'rules') => {
    const url = scanApi.getRequestlyExportUrl(scanId, format, targetBaseUrl)
    window.open(url, '_blank')
  }

  const handleCopyMcpConfig = () => {
    if (!auditData?.mcpBundle?.vscodeMcpConfig) return
    navigator.clipboard.writeText(JSON.stringify(auditData.mcpBundle.vscodeMcpConfig, null, 2))
    setCopiedMcp(true)
    setTimeout(() => setCopiedMcp(false), 2000)
    toast.success('Requestly MCP config copied to clipboard.')
  }

  const handleCopyTransactionJson = () => {
    if (!selectedTransaction) return
    navigator.clipboard.writeText(JSON.stringify(selectedTransaction, null, 2))
    setCopiedTransaction(true)
    setTimeout(() => setCopiedTransaction(false), 2000)
    toast.success('JSON-RPC transaction copied.')
  }

  const filteredEndpoints = useMemo(() => {
    return (auditData?.endpoints || []).filter((ep) => {
      if (selectedMethod !== 'ALL' && ep.method !== selectedMethod) return false
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        return ep.path.toLowerCase().includes(q) || ep.filePath.toLowerCase().includes(q)
      }
      return true
    })
  }, [auditData, selectedMethod, searchQuery])

  const filteredFindings = useMemo(() => {
    return (auditData?.findings || []).filter((f) => {
      if (selectedCategory !== 'ALL' && !f.category.toLowerCase().includes(selectedCategory.toLowerCase())) {
        return false
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        return (
          f.path.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q) ||
          f.cwe.toLowerCase().includes(q)
        )
      }
      return true
    })
  }, [auditData, selectedCategory, searchQuery])

  return (
    <div className="space-y-6 font-sans">
      {/* Top Header & Trigger Control */}
      <div className="p-5 rounded-lg bg-surface border border-border-subtle flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <RiServerLine className="w-4 h-4 text-text-primary" />
            <h3 className="text-sm font-semibold text-text-primary tracking-tight">
              API Security Testing &amp; Requestly MCP Engine
            </h3>
            <span className="px-2 py-0.5 text-[10px] font-mono font-medium bg-surface-muted text-text-secondary rounded border border-border-subtle">
              OWASP 2023 + @requestly/mcp
            </span>
          </div>
          <p className="text-xs text-text-muted">
            AST route tree crawler + AI logic auditor for Express, Fastify, Next.js, Koa, NestJS, and Hono. Generates local Requestly stdio rules &amp; MCP payloads.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 bg-canvas px-2.5 py-1 rounded border border-border-subtle text-xs font-mono">
            <span className="text-text-muted text-[11px]">Base:</span>
            <input
              type="text"
              value={targetBaseUrl}
              onChange={(e) => setTargetBaseUrl(e.target.value)}
              className="bg-transparent border-none outline-none text-text-primary text-xs w-44 font-mono"
              placeholder="http://localhost:3000"
            />
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={handleRunAudit}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs font-mono"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-canvas border-t-text-primary rounded-full animate-spin" />
                <span>Crawling Routes...</span>
              </>
            ) : (
              <>
                <RiPlayFill className="w-3.5 h-3.5" />
                <span>Run API Audit</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Deprecation Notice & Local MCP Architecture Clarification */}
      <div className="p-3.5 rounded-lg bg-surface border border-border-subtle flex items-start gap-3 text-xs">
        <RiInformationLine className="w-4 h-4 text-text-muted shrink-0 mt-0.5" />
        <div className="space-y-1 flex-1 text-text-muted">
          <p className="font-medium text-text-secondary">
            Requestly Architecture Note:
          </p>
          <p className="leading-relaxed text-[11px]">
            Requestly has deprecated legacy public cloud API keys in favor of local <code className="font-mono bg-canvas px-1 py-0.5 rounded text-text-primary">@requestly/mcp</code> stdio protocol and offline workspace exports. This engine runs 100% locally with zero cloud API keys required.
          </p>
        </div>
      </div>

      {!auditData && !loading && (
        <div className="p-12 rounded-lg bg-surface/50 border border-border-subtle text-center space-y-3">
          <div className="w-10 h-10 rounded-lg bg-surface-muted border border-border-subtle text-text-muted flex items-center justify-center mx-auto">
            <RiTerminalBoxLine className="w-5 h-5" />
          </div>
          <div className="max-w-md mx-auto space-y-1">
            <h4 className="text-xs font-semibold text-text-primary">No API Audit Initiated</h4>
            <p className="text-xs text-text-muted leading-relaxed">
              Launch the audit to crawl backend route declarations, inspect parameter schemas, test OWASP API vulnerabilities, and generate Requestly MCP interception suites.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={handleRunAudit} className="text-xs font-mono">
            Execute Route Crawler
          </Button>
        </div>
      )}

      {auditData && (
        <div className="space-y-6">
          {/* Key Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 font-mono text-xs">
            <div className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1">
              <span className="text-[10px] text-text-muted uppercase">Endpoints</span>
              <p className="text-lg font-bold text-text-primary">{auditData.totalEndpoints}</p>
              <span className="text-[10px] text-text-muted truncate block">{auditData.frameworks.join(', ') || 'Native HTTP'}</span>
            </div>
            <div className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1">
              <span className="text-[10px] text-text-muted uppercase">Files Scanned</span>
              <p className="text-lg font-bold text-text-primary">{auditData.totalFilesScanned}</p>
              <span className="text-[10px] text-text-muted">Route handlers</span>
            </div>
            <div className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1">
              <span className="text-[10px] text-text-muted uppercase">OWASP Flaws</span>
              <p className="text-lg font-bold text-rose-400">
                {auditData.summary.critical + auditData.summary.high + auditData.summary.medium}
              </p>
              <span className="text-[10px] text-rose-400/80">{auditData.summary.critical} Crit / {auditData.summary.high} High</span>
            </div>
            <div className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1">
              <span className="text-[10px] text-text-muted uppercase">Requestly Rules</span>
              <p className="text-lg font-bold text-emerald-400">
                {auditData.requestlySuite?.rules?.length || 0}
              </p>
              <span className="text-[10px] text-emerald-400/80">Offline JSON ready</span>
            </div>
            <div className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1">
              <span className="text-[10px] text-text-muted uppercase">MCP Stdio Tools</span>
              <p className="text-lg font-bold text-sky-400">
                {auditData.mcpBundle?.transactions?.length || 0}
              </p>
              <span className="text-[10px] text-sky-400/80">JSON-RPC Frames</span>
            </div>
          </div>

          {/* Live Scanner Log Console */}
          {auditData.logs && auditData.logs.length > 0 && (
            <div className="rounded-lg bg-canvas border border-border-subtle overflow-hidden text-xs font-mono">
              <div className="px-3.5 py-2 bg-surface/80 border-b border-border-subtle flex items-center justify-between">
                <div className="flex items-center gap-2 text-text-muted">
                  <RiTerminalBoxLine className="w-3.5 h-3.5" />
                  <span className="text-[11px] font-semibold text-text-secondary uppercase tracking-wider">
                    Crawler Execution Log Stream
                  </span>
                </div>
                <span className="text-[10px] text-text-muted">{auditData.logs.length} events</span>
              </div>
              <div className="p-3 space-y-1.5 max-h-40 overflow-y-auto custom-scrollbar">
                {auditData.logs.map((log: ScanLogEntry, idx: number) => (
                  <div key={idx} className="flex items-start gap-2 text-[11px] leading-relaxed">
                    <span className="text-text-muted shrink-0 text-[10px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span
                      className={`px-1 rounded text-[9px] uppercase font-bold shrink-0 ${
                        log.level === 'success'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : log.level === 'warn'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-surface-muted text-text-secondary border border-border-subtle'
                      }`}
                    >
                      {log.stage}
                    </span>
                    <span className="text-text-secondary">{log.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab Navigation */}
          <div className="flex flex-wrap items-center justify-between border-b border-border-subtle pb-2 gap-3">
            <div className="flex items-center gap-1">
              <button
                onClick={() => setActiveTab('endpoints')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all cursor-pointer ${
                  activeTab === 'endpoints'
                    ? 'bg-surface text-text-primary border border-border-subtle font-medium'
                    : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                Endpoints ({auditData.endpoints.length})
              </button>
              <button
                onClick={() => setActiveTab('vulnerabilities')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all cursor-pointer ${
                  activeTab === 'vulnerabilities'
                    ? 'bg-surface text-rose-400 border border-border-subtle font-medium'
                    : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                OWASP Flaws ({auditData.findings.length})
              </button>
              <button
                onClick={() => setActiveTab('mcp_console')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all cursor-pointer ${
                  activeTab === 'mcp_console'
                    ? 'bg-surface text-sky-400 border border-border-subtle font-medium'
                    : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                Requestly MCP Console
              </button>
              <button
                onClick={() => setActiveTab('rules')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all cursor-pointer ${
                  activeTab === 'rules'
                    ? 'bg-surface text-emerald-400 border border-border-subtle font-medium'
                    : 'text-text-muted hover:text-text-secondary'
                }`}
              >
                Interception Rules ({auditData.requestlySuite?.rules?.length || 0})
              </button>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleExportRequestly('rules')}
                className="text-xs font-mono flex items-center gap-1.5"
              >
                <RiDownloadLine className="w-3.5 h-3.5" />
                <span>Export Rules (.json)</span>
              </Button>
            </div>
          </div>

          {/* TAB 1: Endpoints */}
          {activeTab === 'endpoints' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* List */}
              <div className="lg:col-span-5 space-y-2.5">
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Filter path or file..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="flex-1 bg-canvas border border-border-subtle rounded px-2.5 py-1.5 text-xs font-mono text-text-primary outline-none focus:border-border"
                  />
                  <select
                    value={selectedMethod}
                    onChange={(e) => setSelectedMethod(e.target.value)}
                    className="bg-canvas border border-border-subtle rounded px-2 py-1.5 text-xs font-mono text-text-primary outline-none"
                  >
                    <option value="ALL">ALL</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="PATCH">PATCH</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>

                <div className="max-h-[480px] overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
                  {filteredEndpoints.map((ep) => {
                    const isSelected = selectedEndpoint?.id === ep.id
                    return (
                      <div
                        key={ep.id}
                        onClick={() => setSelectedEndpoint(ep)}
                        className={`p-2.5 rounded border transition-all cursor-pointer font-mono text-xs ${
                          isSelected
                            ? 'bg-surface border-text-primary/40'
                            : 'bg-surface/40 border-border-subtle hover:bg-surface hover:border-border'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <div className="flex items-center gap-1.5 truncate">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                ep.method === 'GET'
                                  ? 'bg-emerald-500/15 text-emerald-400'
                                  : ep.method === 'POST'
                                  ? 'bg-blue-500/15 text-blue-400'
                                  : ep.method === 'PUT' || ep.method === 'PATCH'
                                  ? 'bg-amber-500/15 text-amber-400'
                                  : 'bg-rose-500/15 text-rose-400'
                              }`}
                            >
                              {ep.method}
                            </span>
                            <span className="text-text-primary font-medium truncate">
                              {ep.path}
                            </span>
                          </div>

                          {ep.hasAuthGuard ? (
                            <span className="flex items-center gap-1 text-[9px] text-emerald-400 shrink-0">
                              <RiLockLine className="w-2.5 h-2.5" /> Auth
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[9px] text-amber-400 shrink-0">
                              <RiLockUnlockLine className="w-2.5 h-2.5" /> Public
                            </span>
                          )}
                        </div>

                        <div className="flex items-center justify-between text-[10px] text-text-muted">
                          <span className="truncate max-w-[220px]">{ep.filePath}:{ep.line}</span>
                          <span className="uppercase text-text-secondary">{ep.framework}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Detail */}
              <div className="lg:col-span-7">
                {selectedEndpoint ? (
                  <div className="p-4 rounded-lg bg-surface border border-border-subtle space-y-4 text-xs font-mono">
                    <div className="flex items-start justify-between gap-3 border-b border-border-subtle pb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="px-1.5 py-0.5 rounded text-[11px] font-bold bg-surface-muted text-text-primary border border-border-subtle">
                            {selectedEndpoint.method}
                          </span>
                          <span className="text-sm font-semibold text-text-primary">
                            {selectedEndpoint.path}
                          </span>
                        </div>
                        <p className="text-[11px] text-text-muted">
                          {selectedEndpoint.filePath}:{selectedEndpoint.line}
                        </p>
                      </div>

                      <span className="px-2 py-0.5 rounded bg-canvas border border-border-subtle text-[10px] text-text-secondary uppercase">
                        {selectedEndpoint.framework}
                      </span>
                    </div>

                    {/* Parameters */}
                    <div className="space-y-1.5">
                      <span className="text-[10px] uppercase font-semibold text-text-muted">
                        Parameters ({selectedEndpoint.params.length})
                      </span>
                      {selectedEndpoint.params.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {selectedEndpoint.params.map((p, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded bg-canvas border border-border-subtle text-text-secondary text-[11px] flex items-center gap-1"
                            >
                              <span className="text-[9px] uppercase text-text-muted font-bold">
                                {p.type}:
                              </span>
                              <span className="text-text-primary">{p.name}</span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[11px] text-text-muted italic">No extracted URL or body parameters</p>
                      )}
                    </div>

                    {/* Auth Status */}
                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-semibold text-text-muted">
                        Access Control &amp; Guards
                      </span>
                      {selectedEndpoint.hasAuthGuard ? (
                        <p className="text-emerald-400 text-[11px]">
                          ✓ Protected: {selectedEndpoint.authGuards.join(', ')}
                        </p>
                      ) : (
                        <p className="text-amber-400 text-[11px]">
                          ⚠ No explicit authentication middleware detected on handler
                        </p>
                      )}
                    </div>

                    {/* Handler Implementation */}
                    <div className="space-y-1.5">
                      <span className="text-[10px] uppercase font-semibold text-text-muted">
                        Handler Code
                      </span>
                      <CodeBlock
                        code={selectedEndpoint.handlerSnippet}
                        language="typescript"
                        variant="bordered"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="p-8 text-center text-xs font-mono text-text-muted">
                    Select an endpoint to inspect code and security attributes.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: OWASP Vulnerabilities */}
          {activeTab === 'vulnerabilities' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* List */}
              <div className="lg:col-span-5 space-y-2.5">
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Search findings..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="flex-1 bg-canvas border border-border-subtle rounded px-2.5 py-1.5 text-xs font-mono text-text-primary outline-none focus:border-border"
                  />
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="bg-canvas border border-border-subtle rounded px-2 py-1.5 text-xs font-mono text-text-primary outline-none"
                  >
                    <option value="ALL">ALL Categories</option>
                    <option value="BOLA">BOLA (API1)</option>
                    <option value="Authentication">Auth (API2)</option>
                    <option value="Property">Mass Assignment (API3)</option>
                    <option value="Resource">Rate Limit (API4)</option>
                  </select>
                </div>

                <div className="max-h-[480px] overflow-y-auto space-y-1.5 pr-1 custom-scrollbar font-mono text-xs">
                  {filteredFindings.map((f) => {
                    const isSelected = selectedFinding?.id === f.id
                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`p-2.5 rounded border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-surface border-rose-500/40'
                            : 'bg-surface/40 border-border-subtle hover:bg-surface hover:border-border'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                              f.severity === 'CRITICAL' || f.severity === 'HIGH'
                                ? 'bg-rose-500/15 text-rose-400'
                                : 'bg-amber-500/15 text-amber-400'
                            }`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-[10px] text-text-muted">{f.cwe}</span>
                        </div>
                        <h5 className="text-xs font-medium text-text-primary mb-1 line-clamp-1">
                          {f.title}
                        </h5>
                        <p className="text-[10px] text-text-muted truncate">
                          {f.method} {f.path}
                        </p>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Detail */}
              <div className="lg:col-span-7">
                {selectedFinding ? (
                  <div className="p-4 rounded-lg bg-surface border border-border-subtle space-y-4 text-xs font-mono">
                    <div className="border-b border-border-subtle pb-3 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/15 text-rose-400">
                          {selectedFinding.severity}
                        </span>
                        <span className="text-[10px] text-text-muted bg-canvas px-1.5 py-0.5 rounded border border-border-subtle">
                          {selectedFinding.cwe}
                        </span>
                        <span className="text-[11px] text-text-secondary">
                          {selectedFinding.category}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-text-primary">
                        {selectedFinding.title}
                      </h4>
                      <p className="text-[11px] text-text-muted">
                        Target: {selectedFinding.method} {selectedFinding.path}
                      </p>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-semibold text-text-muted">
                        Description
                      </span>
                      <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
                        {selectedFinding.description}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-canvas border border-border-subtle space-y-1">
                      <span className="text-[10px] uppercase font-semibold text-rose-400 flex items-center gap-1">
                        <RiAlertLine className="w-3 h-3" />
                        Exploit Scenario Narrative
                      </span>
                      <p className="text-[11px] text-text-muted leading-relaxed font-mono">
                        {selectedFinding.exploitScenario}
                      </p>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-semibold text-text-muted">
                        Remediation Advice
                      </span>
                      <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
                        {selectedFinding.remediation}
                      </p>
                    </div>

                    {selectedFinding.suggestedPatch && (
                      <div className="space-y-1.5">
                        <span className="text-[10px] uppercase font-semibold text-text-muted flex items-center gap-1">
                          <RiSparklingLine className="w-3 h-3 text-text-primary" />
                          Suggested Secure Code Patch
                        </span>
                        <CodeBlock
                          code={selectedFinding.suggestedPatch}
                          language="typescript"
                          variant="bordered"
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-8 text-center text-xs font-mono text-text-muted">
                    Select a vulnerability to inspect exploit narrative and remediation.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: Requestly MCP Console */}
          {activeTab === 'mcp_console' && (
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-lg bg-surface border border-border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-xs font-semibold text-text-primary">
                    Requestly MCP Stdio Protocol Handshake &amp; Tools Inspector
                  </h4>
                  <p className="text-[11px] text-text-muted mt-0.5">
                    Inspect JSON-RPC tool transactions executed with `@requestly/mcp` stdio server.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleCopyMcpConfig}
                    className="text-xs font-mono flex items-center gap-1.5"
                  >
                    {copiedMcp ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                    <span>{copiedMcp ? 'Copied' : 'Copy .vscode/mcp.json'}</span>
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                {/* Transaction List */}
                <div className="lg:col-span-5 space-y-1.5">
                  <span className="text-[10px] uppercase font-semibold text-text-muted block mb-1">
                    JSON-RPC Frame Log ({auditData.mcpBundle?.transactions?.length || 0})
                  </span>
                  <div className="max-h-[420px] overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
                    {(auditData.mcpBundle?.transactions || []).map((t: McpTransaction) => {
                      const isSelected = selectedTransaction?.id === t.id
                      return (
                        <div
                          key={t.id}
                          onClick={() => setSelectedTransaction(t)}
                          className={`p-2.5 rounded border transition-all cursor-pointer ${
                            isSelected
                              ? 'bg-surface border-sky-400/50'
                              : 'bg-surface/40 border-border-subtle hover:bg-surface hover:border-border'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-sky-500/15 text-sky-400">
                              {t.tool}
                            </span>
                            <span className="text-[10px] text-emerald-400">
                              {t.latencyMs}ms
                            </span>
                          </div>
                          <p className="text-[11px] text-text-primary truncate">
                            {t.requestPayload?.params?.arguments?.name || t.method}
                          </p>
                          <span className="text-[9px] text-text-muted block mt-0.5">
                            ID: {t.id}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Transaction Detail Payload */}
                <div className="lg:col-span-7">
                  {selectedTransaction ? (
                    <div className="p-4 rounded-lg bg-surface border border-border-subtle space-y-3">
                      <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-sky-500/15 text-sky-400">
                            {selectedTransaction.tool}
                          </span>
                          <span className="text-xs font-semibold text-text-primary">
                            Transaction Inspector
                          </span>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={handleCopyTransactionJson}
                          className="text-[10px] font-mono flex items-center gap-1"
                        >
                          {copiedTransaction ? <RiCheckLine className="w-3 h-3 text-emerald-400" /> : <RiFileCopyLine className="w-3 h-3" />}
                          <span>{copiedTransaction ? 'Copied' : 'Copy Frame'}</span>
                        </Button>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] uppercase font-semibold text-text-muted">
                          Request Payload (JSON-RPC 2.0)
                        </span>
                        <CodeBlock
                          code={JSON.stringify(selectedTransaction.requestPayload, null, 2)}
                          language="json"
                          variant="bordered"
                        />
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] uppercase font-semibold text-text-muted">
                          MCP Server Response
                        </span>
                        <CodeBlock
                          code={JSON.stringify(selectedTransaction.responsePayload, null, 2)}
                          language="json"
                          variant="bordered"
                        />
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center text-xs text-text-muted">
                      Select a transaction frame to inspect JSON-RPC communication.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: Interception Rules */}
          {activeTab === 'rules' && (
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-lg bg-surface border border-border-subtle flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-text-primary">
                    Generated Requestly Interception Suites
                  </h4>
                  <p className="text-[11px] text-text-muted mt-0.5">
                    Import this JSON directly into Requestly Desktop / Extension to test IDOR parameter swaps and header mutations.
                  </p>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleExportRequestly('rules')}
                  className="flex items-center gap-1.5 text-xs font-mono"
                >
                  <RiDownloadLine className="w-3.5 h-3.5" />
                  <span>Download requestly-rules.json</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {(auditData.requestlySuite?.rules || []).map((rule: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-surface border border-border-subtle space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-surface-muted text-text-secondary border border-border-subtle">
                        {rule.ruleType}
                      </span>
                      <span className="text-[10px] text-emerald-400">
                        {rule.status}
                      </span>
                    </div>
                    <h5 className="text-xs font-semibold text-text-primary truncate">{rule.name}</h5>
                    <p className="text-[11px] text-text-muted bg-canvas p-1.5 rounded border border-border-subtle truncate">
                      {rule.urlCondition?.value || rule.url}
                    </p>
                    <p className="text-[11px] text-text-secondary line-clamp-2 font-sans">
                      {rule.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
