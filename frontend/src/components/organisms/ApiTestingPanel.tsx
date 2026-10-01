import React, { useState } from 'react'
import {
  RiServerLine,
  RiShieldCheckLine,
  RiAlertLine,
  RiDownloadLine,
  RiPlayFill,
  RiFileCopyLine,
  RiCheckLine,
  RiLockLine,
  RiLockUnlockLine,
  RiSparklingLine,
} from '@remixicon/react'
import {
  scanApi,
  type ApiAuditResponse,
  type DiscoveredEndpointItem,
  type ApiFindingItem,
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
  const [activeTab, setActiveTab] = useState<'endpoints' | 'vulnerabilities' | 'requestly' | 'mcp'>('endpoints')
  const [selectedEndpoint, setSelectedEndpoint] = useState<DiscoveredEndpointItem | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<ApiFindingItem | null>(null)
  const [copiedMcp, setCopiedMcp] = useState(false)

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
      toast.success(
        `Discovered ${res.totalEndpoints} API endpoints across ${res.totalFilesScanned} files with ${res.findings.length} security alerts!`
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
    toast.success('Requestly MCP config copied to clipboard!')
  }

  const filteredEndpoints = (auditData?.endpoints || []).filter((ep) => {
    if (selectedMethod !== 'ALL' && ep.method !== selectedMethod) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      return ep.path.toLowerCase().includes(q) || ep.filePath.toLowerCase().includes(q)
    }
    return true
  })

  const filteredFindings = (auditData?.findings || []).filter((f) => {
    if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false
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

  return (
    <div className="space-y-6">
      {/* Header & Trigger Controls */}
      <div className="p-6 rounded-xl bg-surface-card border border-border-light/60 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <RiServerLine className="w-5 h-5 text-accent-primary" />
            <h3 className="text-base font-semibold text-text-primary">
              AI-Logical API Security & Interception Testing Engine
            </h3>
            <span className="px-2 py-0.5 text-[11px] font-medium bg-accent-primary/10 text-accent-primary rounded-full border border-accent-primary/20">
              Requestly MCP Powered
            </span>
          </div>
          <p className="text-xs text-text-secondary">
            Discovers Express, Fastify, Next.js, Koa, NestJS, and Hono backend routes. Audits OWASP API Security Top 10 logic flaws and generates Requestly MCP test interception suites.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
          <div className="flex items-center gap-2 bg-surface-base px-3 py-1.5 rounded-lg border border-border-light text-xs">
            <span className="text-text-muted">Target Base:</span>
            <input
              type="text"
              value={targetBaseUrl}
              onChange={(e) => setTargetBaseUrl(e.target.value)}
              className="bg-transparent border-none outline-none text-text-primary text-xs w-48 font-mono"
              placeholder="http://localhost:3000"
            />
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={handleRunAudit}
            disabled={loading}
            className="flex items-center gap-2 shrink-0"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                <span>Auditing APIs...</span>
              </>
            ) : (
              <>
                <RiPlayFill className="w-4 h-4" />
                <span>Hunt & Test APIs</span>
              </>
            )}
          </Button>
        </div>
      </div>

      {!auditData && !loading && (
        <div className="p-12 rounded-xl bg-surface-card/40 border border-border-light/40 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-accent-primary/10 text-accent-primary flex items-center justify-center mx-auto">
            <RiServerLine className="w-6 h-6" />
          </div>
          <div className="max-w-md mx-auto space-y-1">
            <h4 className="text-sm font-medium text-text-primary">No API Audit Run Yet</h4>
            <p className="text-xs text-text-secondary leading-relaxed">
              Click &quot;Hunt &amp; Test APIs&quot; to inspect all backend route definitions, hunt IDOR/BOLA flaws, Broken Authentication, Mass Assignment, and build Requestly rule suites.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={handleRunAudit}>
            Launch AI API Audit
          </Button>
        </div>
      )}

      {auditData && (
        <div className="space-y-6">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 space-y-1">
              <span className="text-[11px] text-text-muted">Discovered Endpoints</span>
              <p className="text-2xl font-bold text-text-primary">{auditData.totalEndpoints}</p>
              <span className="text-[10px] text-accent-primary font-mono">{auditData.frameworks.join(', ')}</span>
            </div>
            <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 space-y-1">
              <span className="text-[11px] text-text-muted">Files Scanned</span>
              <p className="text-2xl font-bold text-text-primary">{auditData.totalFilesScanned}</p>
              <span className="text-[10px] text-text-secondary">routes & handlers</span>
            </div>
            <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 space-y-1">
              <span className="text-[11px] text-text-muted">Critical / High Flaws</span>
              <p className="text-2xl font-bold text-rose-400">
                {auditData.summary.critical + auditData.summary.high}
              </p>
              <span className="text-[10px] text-rose-400/80">Immediate attention</span>
            </div>
            <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 space-y-1">
              <span className="text-[11px] text-text-muted">Requestly Rules</span>
              <p className="text-2xl font-bold text-emerald-400">
                {auditData.requestlySuite?.totalRules || 0}
              </p>
              <span className="text-[10px] text-emerald-400/80">Interception suites</span>
            </div>
            <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 space-y-1">
              <span className="text-[11px] text-text-muted">MCP Tools Ready</span>
              <p className="text-2xl font-bold text-sky-400">
                {auditData.mcpBundle?.mcpTools?.length || 0}
              </p>
              <span className="text-[10px] text-sky-400/80">@requestly/mcp</span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex items-center justify-between border-b border-border-light/60 pb-2">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('endpoints')}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  activeTab === 'endpoints'
                    ? 'bg-accent-primary/15 text-accent-primary border border-accent-primary/30'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-card'
                }`}
              >
                Discovered Endpoints ({auditData.endpoints.length})
              </button>
              <button
                onClick={() => setActiveTab('vulnerabilities')}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  activeTab === 'vulnerabilities'
                    ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-card'
                }`}
              >
                API Vulnerabilities ({auditData.findings.length})
              </button>
              <button
                onClick={() => setActiveTab('requestly')}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  activeTab === 'requestly'
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-card'
                }`}
              >
                Requestly Rules ({auditData.requestlySuite?.totalRules || 0})
              </button>
              <button
                onClick={() => setActiveTab('mcp')}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  activeTab === 'mcp'
                    ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-card'
                }`}
              >
                Requestly MCP Server
              </button>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleExportRequestly('rules')}
                className="text-xs flex items-center gap-1.5"
              >
                <RiDownloadLine className="w-3.5 h-3.5" />
                <span>Export Requestly JSON</span>
              </Button>
            </div>
          </div>

          {/* TAB 1: Discovered Endpoints */}
          {activeTab === 'endpoints' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Endpoint List */}
              <div className="lg:col-span-5 space-y-3">
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type="text"
                      placeholder="Search routes or files..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-surface-card border border-border-light rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none focus:border-accent-primary"
                    />
                  </div>
                  <select
                    value={selectedMethod}
                    onChange={(e) => setSelectedMethod(e.target.value)}
                    className="bg-surface-card border border-border-light rounded-lg px-2.5 py-1.5 text-xs text-text-primary outline-none"
                  >
                    <option value="ALL">All Methods</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="PATCH">PATCH</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>

                <div className="max-h-[500px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                  {filteredEndpoints.map((ep) => {
                    const isSelected = selectedEndpoint?.id === ep.id
                    return (
                      <div
                        key={ep.id}
                        onClick={() => setSelectedEndpoint(ep)}
                        className={`p-3 rounded-lg border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-accent-primary/10 border-accent-primary/40'
                            : 'bg-surface-card/60 border-border-light/60 hover:bg-surface-card hover:border-border-light'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono ${
                                ep.method === 'GET'
                                  ? 'bg-emerald-500/20 text-emerald-400'
                                  : ep.method === 'POST'
                                  ? 'bg-blue-500/20 text-blue-400'
                                  : ep.method === 'PUT' || ep.method === 'PATCH'
                                  ? 'bg-amber-500/20 text-amber-400'
                                  : 'bg-rose-500/20 text-rose-400'
                              }`}
                            >
                              {ep.method}
                            </span>
                            <span className="text-xs font-mono font-medium text-text-primary truncate">
                              {ep.path}
                            </span>
                          </div>
                          {ep.hasAuthGuard ? (
                            <span className="flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                              <RiLockLine className="w-3 h-3" /> Auth
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                              <RiLockUnlockLine className="w-3 h-3" /> Public
                            </span>
                          )}
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-text-muted">
                          <span className="truncate max-w-[200px]">{ep.filePath}:{ep.line}</span>
                          <span className="text-[10px] uppercase font-mono px-1 rounded bg-surface-base text-text-secondary">
                            {ep.framework}
                          </span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Endpoint Details */}
              <div className="lg:col-span-7">
                {selectedEndpoint ? (
                  <div className="p-5 rounded-xl bg-surface-card border border-border-light/60 space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-bold font-mono bg-accent-primary/20 text-accent-primary">
                            {selectedEndpoint.method}
                          </span>
                          <h4 className="text-sm font-semibold font-mono text-text-primary">
                            {selectedEndpoint.path}
                          </h4>
                        </div>
                        <p className="text-xs text-text-muted font-mono">
                          {selectedEndpoint.filePath}:{selectedEndpoint.line}
                        </p>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="px-2 py-1 text-xs rounded bg-surface-base border border-border-light text-text-secondary font-mono">
                          Framework: {selectedEndpoint.framework}
                        </span>
                      </div>
                    </div>

                    {/* Parameters */}
                    <div className="space-y-2">
                      <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                        Parameters ({selectedEndpoint.params.length})
                      </h5>
                      {selectedEndpoint.params.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {selectedEndpoint.params.map((p, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 text-xs rounded bg-surface-base border border-border-light font-mono text-text-primary flex items-center gap-1.5"
                            >
                              <span className="text-[10px] uppercase text-text-muted font-bold">
                                {p.type}:
                              </span>
                              <span>{p.name}</span>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-text-muted italic">No extracted parameters</p>
                      )}
                    </div>

                    {/* Auth Guards */}
                    <div className="space-y-1.5">
                      <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                        Authentication &amp; Access Controls
                      </h5>
                      {selectedEndpoint.hasAuthGuard ? (
                        <div className="flex items-center gap-2 text-xs text-emerald-400">
                          <RiShieldCheckLine className="w-4 h-4 shrink-0" />
                          <span>Guards Detected: {selectedEndpoint.authGuards.join(', ')}</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 text-xs text-amber-400">
                          <RiAlertLine className="w-4 h-4 shrink-0" />
                          <span>No explicit authentication middleware guard detected on route handler</span>
                        </div>
                      )}
                    </div>

                    {/* Handler Code Snippet */}
                    <div className="space-y-2">
                      <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                        Route Handler Implementation
                      </h5>
                      <CodeBlock
                        code={selectedEndpoint.handlerSnippet}
                        language="typescript"
                        variant="bordered"
                      />
                    </div>
                  </div>
                ) : (
                  <div className="p-8 text-center text-xs text-text-muted">
                    Select an endpoint on the left to view handler code and security attributes.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: API Vulnerabilities */}
          {activeTab === 'vulnerabilities' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Finding List */}
              <div className="lg:col-span-5 space-y-3">
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type="text"
                      placeholder="Search vulnerabilities..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full bg-surface-card border border-border-light rounded-lg px-3 py-1.5 text-xs text-text-primary outline-none focus:border-accent-primary"
                    />
                  </div>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="bg-surface-card border border-border-light rounded-lg px-2.5 py-1.5 text-xs text-text-primary outline-none"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="API1:2023-BOLA">API1:2023 BOLA</option>
                    <option value="API2:2023-Broken-Authentication">API2:2023 Broken Auth</option>
                    <option value="API3:2023-Broken-Object-Property-Level-Authorization">API3:2023 Mass Assignment</option>
                    <option value="API4:2023-Unrestricted-Resource-Consumption">API4:2023 Rate Limit</option>
                  </select>
                </div>

                <div className="max-h-[500px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                  {filteredFindings.map((f) => {
                    const isSelected = selectedFinding?.id === f.id
                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`p-3 rounded-lg border transition-all cursor-pointer ${
                          isSelected
                            ? 'bg-rose-500/10 border-rose-500/40'
                            : 'bg-surface-card/60 border-border-light/60 hover:bg-surface-card hover:border-border-light'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              f.severity === 'CRITICAL' || f.severity === 'HIGH'
                                ? 'bg-rose-500/20 text-rose-400'
                                : 'bg-amber-500/20 text-amber-400'
                            }`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-[10px] font-mono text-text-muted">{f.category}</span>
                        </div>
                        <h5 className="text-xs font-medium text-text-primary mb-1 line-clamp-1">
                          {f.title}
                        </h5>
                        <p className="text-[11px] font-mono text-text-secondary truncate">
                          {f.method} {f.path}
                        </p>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Finding Details */}
              <div className="lg:col-span-7">
                {selectedFinding ? (
                  <div className="p-5 rounded-xl bg-surface-card border border-border-light/60 space-y-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400">
                          {selectedFinding.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-surface-base border border-border-light text-text-secondary">
                          {selectedFinding.cwe}
                        </span>
                        <span className="text-xs font-mono text-accent-primary">
                          {selectedFinding.category}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-text-primary">
                        {selectedFinding.title}
                      </h4>
                      <p className="text-xs font-mono text-text-muted">
                        Target: {selectedFinding.method} {selectedFinding.path}
                      </p>
                    </div>

                    <div className="space-y-1">
                      <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                        Vulnerability Description
                      </h5>
                      <p className="text-xs text-text-primary leading-relaxed">
                        {selectedFinding.description}
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-rose-500/[0.04] border border-rose-500/20 space-y-1 text-xs">
                      <h5 className="font-semibold text-rose-400 flex items-center gap-1.5">
                        <RiAlertLine className="w-3.5 h-3.5" />
                        Exploit Scenario Walkthrough
                      </h5>
                      <p className="text-text-secondary leading-relaxed font-mono text-[11px]">
                        {selectedFinding.exploitScenario}
                      </p>
                    </div>

                    <div className="space-y-1">
                      <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                        Remediation Guidance
                      </h5>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {selectedFinding.remediation}
                      </p>
                    </div>

                    {selectedFinding.suggestedPatch && (
                      <div className="space-y-2">
                        <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                          <RiSparklingLine className="w-3.5 h-3.5 text-accent-primary" />
                          Suggested Secure Patch
                        </h5>
                        <CodeBlock
                          code={selectedFinding.suggestedPatch}
                          language="typescript"
                          variant="bordered"
                        />
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-8 text-center text-xs text-text-muted">
                    Select a vulnerability on the left to view exploit scenario and suggested patch.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: Requestly Rules */}
          {activeTab === 'requestly' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-text-primary">
                    Generated Requestly Interception Suites
                  </h4>
                  <p className="text-xs text-text-muted">
                    Import this JSON directly into Requestly extension or desktop app to run automated security tampering and payload injection tests.
                  </p>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleExportRequestly('rules')}
                  className="flex items-center gap-1.5"
                >
                  <RiDownloadLine className="w-3.5 h-3.5" />
                  <span>Download Rules (.json)</span>
                </Button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(auditData.requestlySuite?.rules || []).map((rule: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg bg-surface-card border border-border-light/60 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-accent-primary/15 text-accent-primary">
                        {rule.ruleType}
                      </span>
                      <span className="text-[10px] text-text-muted font-mono">
                        {rule.status === 'ACTIVE' ? '✓ ACTIVE' : 'INACTIVE'}
                      </span>
                    </div>
                    <h5 className="text-xs font-semibold text-text-primary">{rule.name}</h5>
                    <p className="text-xs font-mono text-text-secondary bg-surface-base p-2 rounded truncate">
                      {rule.pairs?.[0]?.source?.key || rule.url}
                    </p>
                    <p className="text-[11px] text-text-muted line-clamp-2">
                      {rule.description}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Requestly MCP Server */}
          {activeTab === 'mcp' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-surface-card border border-border-light/60 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-text-primary">
                    Requestly MCP Server Setup (`@requestly/mcp`)
                  </h4>
                  <p className="text-xs text-text-muted">
                    Configure your AI Agent (Cursor, Claude Desktop, Antigravity) to communicate directly with Requestly MCP server.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleCopyMcpConfig}
                    className="flex items-center gap-1.5"
                  >
                    {copiedMcp ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-400" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                    <span>{copiedMcp ? 'Copied' : 'Copy Config'}</span>
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => handleExportRequestly('mcp')}
                    className="flex items-center gap-1.5"
                  >
                    <RiDownloadLine className="w-3.5 h-3.5" />
                    <span>Download .vscode/mcp.json</span>
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <h5 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                  MCP Server Configuration JSON
                </h5>
                <CodeBlock
                  code={JSON.stringify(auditData.mcpBundle?.vscodeMcpConfig || {}, null, 2)}
                  language="json"
                  variant="bordered"
                />
              </div>

              <div className="p-4 rounded-lg bg-surface-card border border-border-light/60 space-y-2 text-xs">
                <h5 className="font-semibold text-text-primary">How to use Requestly MCP Server:</h5>
                <ol className="list-decimal list-inside space-y-1 text-text-secondary leading-relaxed">
                  <li>Install official Requestly MCP package: <code className="font-mono bg-surface-base px-1.5 py-0.5 rounded text-accent-primary">npm install -g @requestly/mcp</code></li>
                  <li>Paste the config into your <code className="font-mono bg-surface-base px-1.5 py-0.5 rounded">.vscode/mcp.json</code> or Claude Desktop MCP settings.</li>
                  <li>Your AI agent can now invoke <code className="font-mono bg-surface-base px-1.5 py-0.5 rounded text-text-primary">create_rule</code>, <code className="font-mono bg-surface-base px-1.5 py-0.5 rounded text-text-primary">create_group</code>, and test endpoints live with custom interception payloads.</li>
                </ol>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
