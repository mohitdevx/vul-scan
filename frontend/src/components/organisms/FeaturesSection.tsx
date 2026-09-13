import { useState, type FC, type ElementType } from 'react'
import {
  RiCodeSSlashLine,
  RiTerminalBoxLine,
  RiShieldKeyholeLine,
  RiCookieLine,
  RiAlertLine,
  RiCheckLine,
} from '@remixicon/react'
import { CodeBlock } from '../atoms/CodeBlock'

interface AnalyzerSpec {
  id: string
  cwe: string
  title: string
  shortScope: string
  severity: 'HIGH' | 'MEDIUM'
  icon: ElementType
  description: string
  sinks: string[]
  vulnerableSnippet: string
  vulnerableHighlight: string
  vulnerableLabel: string
  safeSnippet: string
  safeHighlight: string
  safeLabel: string
  remediation: string
}

const ANALYZERS: AnalyzerSpec[] = [
  {
    id: 'cmd-injection',
    cwe: 'CWE-78',
    title: 'Command Injection',
    shortScope: 'OS shell execution',
    severity: 'HIGH',
    icon: RiTerminalBoxLine,
    description:
      'Traverses the abstract syntax tree to identify dynamic command construction and unescaped parameter passing into OS execution primitives.',
    sinks: ['child_process.exec', 'execSync', 'spawn({ shell: true })', 'eval()'],
    vulnerableSnippet: `// Flagged: Dynamic argument concatenated into shell sink\nconst out = execSync("ping -c 1 " + req.query.host);`,
    vulnerableHighlight: `"ping -c 1 " + req.query.host`,
    vulnerableLabel: 'Unsanitized user parameter passed directly to system shell sink',
    safeSnippet: `// Remediated: Parameterized execution without shell wrapper\nexecFile("ping", ["-c", "1", req.query.host]);`,
    safeHighlight: `["-c", "1", req.query.host]`,
    safeLabel: 'Direct binary execution with isolated arguments array',
    remediation:
      'Use execFile or spawn with argument arrays instead of launching an intermediate system shell with dynamic strings.',
  },
  {
    id: 'xss',
    cwe: 'CWE-79',
    title: 'Cross-Site Scripting (XSS)',
    shortScope: 'DOM & template injection',
    severity: 'HIGH',
    icon: RiCodeSSlashLine,
    description:
      'Audits AST assignment expressions and JSX attributes to pinpoint unescaped variable flows terminating in DOM mutation sinks.',
    sinks: ['element.innerHTML', 'outerHTML', 'dangerouslySetInnerHTML', 'document.write'],
    vulnerableSnippet: `// Flagged: Raw unescaped user payload assigned to HTML sink\nelement.innerHTML = "<div>" + req.body.payload + "</div>";`,
    vulnerableHighlight: `innerHTML`,
    vulnerableLabel: 'Unescaped dynamic string written directly to innerHTML sink',
    safeSnippet: `// Remediated: Encoded text content node\nelement.textContent = req.body.payload;`,
    safeHighlight: `textContent`,
    safeLabel: 'Safe text node assignment preventing browser script execution',
    remediation:
      'Avoid raw HTML assignment sinks. Use textContent, standard JSX string children, or explicit contextual sanitizers.',
  },
  {
    id: 'auth-flow',
    cwe: 'CWE-287',
    title: 'Authentication Flow',
    shortScope: 'Token & route validation',
    severity: 'HIGH',
    icon: RiShieldKeyholeLine,
    description:
      'Detects missing algorithm whitelisting in token verification calls, insecure token decoding without signature checks, and missing auth gates.',
    sinks: ['jwt.verify()', 'jwt.decode()', 'router.use()'],
    vulnerableSnippet: `// Flagged: Missing explicit algorithms whitelist enforcement\njwt.verify(token, secret);`,
    vulnerableHighlight: `jwt.verify(token, secret)`,
    vulnerableLabel: 'Token verified without restricting allowed cryptographic algorithms',
    safeSnippet: `// Remediated: Strict algorithm constraint enforced\njwt.verify(token, secret, { algorithms: ["HS256"] });`,
    safeHighlight: `{ algorithms: ["HS256"] }`,
    safeLabel: 'Explicit cryptographic algorithm whitelist enforced',
    remediation:
      'Always enforce an explicit algorithms array in verification calls and ensure all protected endpoints declare auth middleware.',
  },
  {
    id: 'session-mgmt',
    cwe: 'CWE-384',
    title: 'Session Management',
    shortScope: 'Cookie flags & fixation',
    severity: 'MEDIUM',
    icon: RiCookieLine,
    description:
      'Validates cookie configuration flags and verifies session identifiers are regenerated upon privilege state transitions.',
    sinks: ['res.cookie()', 'express-session', 'req.session.regenerate()'],
    vulnerableSnippet: `// Flagged: Session cookie issued without protective flags\nres.cookie("sid", sessionId);`,
    vulnerableHighlight: `res.cookie("sid", sessionId)`,
    vulnerableLabel: 'Missing httpOnly, secure, and sameSite cookie attributes',
    safeSnippet: `// Remediated: Hardened cookie flags enforced\nres.cookie("sid", sessionId, { httpOnly: true, secure: true });`,
    safeHighlight: `{ httpOnly: true, secure: true }`,
    safeLabel: 'Hardened cookie transport flags preventing session theft and hijacking',
    remediation:
      'Always set httpOnly, secure, and sameSite attributes on session cookies, and regenerate session IDs on successful login.',
  },
]

export const FeaturesSection: FC = () => {
  const [activeId, setActiveId] = useState<string>(ANALYZERS[0].id)
  const activeAnalyzer = ANALYZERS.find(a => a.id === activeId) ?? ANALYZERS[0]
  const ActiveIcon = activeAnalyzer.icon

  return (
    <section id="analyzers" className="py-24 md:py-32 bg-zinc-950">
      <div className="max-w-5xl mx-auto px-4 sm:px-6">
        {/* Section Header */}
        <div className="text-left mb-10">
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight text-zinc-100 mb-2">
            Vulnerability Analyzers
          </h2>
          <p className="text-sm text-zinc-400 max-w-2xl leading-relaxed">
            Deterministic AST pattern rulesets covering critical vulnerability classes in application source code.
          </p>
        </div>

        {/* Clean Underline Tab Navigation without scrollbar */}
        <div className="flex items-center gap-1 sm:gap-2 overflow-x-auto border-b border-zinc-800/80 mb-8 no-scrollbar">
          {ANALYZERS.map(item => {
            const ItemIcon = item.icon
            const isActive = item.id === activeId

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveId(item.id)}
                className={`flex items-center gap-2 px-3 sm:px-4 py-3 text-xs sm:text-sm font-medium transition-colors whitespace-nowrap cursor-pointer -mb-px border-b-2 ${
                  isActive
                    ? 'text-zinc-100 border-zinc-100 font-semibold'
                    : 'text-zinc-400 border-transparent hover:text-zinc-200 hover:border-zinc-700'
                }`}
              >
                <ItemIcon className="w-4 h-4 shrink-0" />
                <span>{item.title}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded transition-colors ${
                    isActive
                      ? 'bg-zinc-800 text-zinc-200'
                      : 'bg-zinc-900 text-zinc-500'
                  }`}
                >
                  {item.cwe}
                </span>
              </button>
            )
          })}
        </div>

        {/* Unified Inspection Console with Locked Height (Never Expands or Contracts) */}
        <div className="rounded-xl border border-zinc-800 bg-[#0c0c0f] shadow-2xl shadow-black/70 overflow-hidden text-left min-h-[380px] lg:h-[380px]">
          <div className="grid grid-cols-1 lg:grid-cols-12 h-full">
            {/* Left Info Panel */}
            <div className="lg:col-span-5 p-6 sm:p-7 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-zinc-800/80 h-full">
              <div className="space-y-3.5">
                {/* Meta header */}
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-zinc-850 flex items-center justify-center text-zinc-200 shrink-0">
                      <ActiveIcon className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-sm sm:text-base font-semibold text-zinc-100">
                        {activeAnalyzer.title}
                      </h3>
                      <span className="text-[11px] font-mono text-zinc-400">
                        rule/{activeAnalyzer.id}
                      </span>
                    </div>
                  </div>

                  <span
                    className={`text-[9.5px] font-mono px-2 py-0.5 rounded uppercase tracking-wider ${
                      activeAnalyzer.severity === 'HIGH'
                        ? 'text-rose-400 bg-rose-500/10 border border-rose-500/20'
                        : 'text-amber-400 bg-amber-500/10 border border-amber-500/20'
                    }`}
                  >
                    {activeAnalyzer.severity}
                  </span>
                </div>

                {/* Description with fixed minimum height */}
                <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed min-h-[44px]">
                  {activeAnalyzer.description}
                </p>

                {/* Monitored Sinks with fixed height */}
                <div>
                  <div className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-400 mb-1.5">
                    Monitored AST Sinks
                  </div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[11px] min-h-[28px] items-center">
                    {activeAnalyzer.sinks.map(sink => (
                      <span
                        key={sink}
                        className="bg-zinc-950 px-2 py-0.5 rounded text-sky-300 border border-zinc-800/80 font-mono"
                      >
                        {sink}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Remediation Note with fixed minimum height */}
              <div className="pt-3.5 border-t border-zinc-850 text-xs text-zinc-400 leading-relaxed min-h-[52px] flex items-center">
                <p>
                  <span className="font-semibold text-zinc-200 font-mono text-[11px]">Remediation: </span>
                  {activeAnalyzer.remediation}
                </p>
              </div>
            </div>

            {/* Right Diagnostic Code Panel with Syntax Highlighting and Tight Diff Layout */}
            <div className="lg:col-span-7 p-6 sm:p-7 bg-zinc-950/60 flex flex-col justify-center gap-3.5 h-full">
              {/* Flagged Pattern */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-1.5 text-rose-400 font-sans font-medium">
                    <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                    <span>Flagged Unsafe AST Pattern</span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-500">Vulnerable Sink</span>
                </div>
                <CodeBlock
                  code={activeAnalyzer.vulnerableSnippet}
                  highlightToken={activeAnalyzer.vulnerableHighlight}
                  highlightType="unsafe"
                  startLine={37}
                />
                <div className="text-[11px] text-zinc-400 font-sans">
                  {activeAnalyzer.vulnerableLabel}
                </div>
              </div>

              {/* Clean Subtle Diff Divider */}
              <div className="flex items-center gap-2 text-zinc-600 select-none py-0.5">
                <div className="h-px bg-zinc-800/90 flex-1" />
                <span className="text-[9.5px] font-mono uppercase tracking-widest text-zinc-500">
                  Remediation Diff
                </span>
                <div className="h-px bg-zinc-800/90 flex-1" />
              </div>

              {/* Remediated Pattern */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-sans font-medium">
                    <RiCheckLine className="w-3.5 h-3.5 shrink-0" />
                    <span>Hardened Implementation</span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-500">Remediated AST</span>
                </div>
                <CodeBlock
                  code={activeAnalyzer.safeSnippet}
                  highlightToken={activeAnalyzer.safeHighlight}
                  highlightType="safe"
                  startLine={40}
                />
                <div className="text-[11px] text-zinc-400 font-sans">
                  {activeAnalyzer.safeLabel}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
