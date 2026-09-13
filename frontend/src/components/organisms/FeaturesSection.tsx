import { useState, type FC, type ElementType } from 'react'
import {
  RiCodeSSlashLine,
  RiTerminalBoxLine,
  RiShieldKeyholeLine,
  RiCookieLine,
  RiAlertLine,
  RiCheckLine,
} from '@remixicon/react'

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
  vulnerableLabel: string
  safeSnippet: string
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
    vulnerableLabel: 'Unsanitized user input passed to system shell',
    safeSnippet: `// Remediated: Parameterized execution without shell wrapper\nexecFile("ping", ["-c", "1", req.query.host]);`,
    safeLabel: 'Direct binary execution with argument isolation',
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
    vulnerableLabel: 'Unescaped dynamic string written to innerHTML',
    safeSnippet: `// Remediated: Encoded text content node\nelement.textContent = req.body.payload;`,
    safeLabel: 'Safe text node assignment preventing script execution',
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
    vulnerableSnippet: `// Flagged: Missing explicit algorithms whitelist enforcement\njwt.verify(token, secret); // vulnerable to "none" algorithm`,
    vulnerableLabel: 'Token verified without restricting allowed algorithms',
    safeSnippet: `// Remediated: Strict algorithm constraint enforced\njwt.verify(token, secret, { algorithms: ["HS256"] });`,
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
    vulnerableLabel: 'Missing httpOnly, secure, and sameSite cookie attributes',
    safeSnippet: `// Remediated: Fully hardened cookie flags\nres.cookie("sid", sessionId, {\n  httpOnly: true,\n  secure: true,\n  sameSite: "strict",\n});`,
    safeLabel: 'Hardened cookie transport flags preventing theft and CSRF',
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

        {/* Clean Underline Tab Navigation */}
        <div className="flex items-center gap-1 sm:gap-2 overflow-x-auto border-b border-zinc-800/80 mb-8 scrollbar-none">
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
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                    isActive ? 'bg-zinc-800 text-zinc-200' : 'bg-zinc-900 text-zinc-500'
                  }`}
                >
                  {item.cwe}
                </span>
              </button>
            )
          })}
        </div>

        {/* Unified Inspection Console */}
        <div className="rounded-xl border border-zinc-800 bg-[#0c0c0f] shadow-2xl shadow-black/70 overflow-hidden text-left">
          <div className="grid grid-cols-1 lg:grid-cols-12">
            {/* Left Info Panel */}
            <div className="lg:col-span-5 p-6 sm:p-7 flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-zinc-800/80">
              <div className="space-y-4">
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
                        ? 'text-rose-400 bg-rose-500/10'
                        : 'text-amber-400 bg-amber-500/10'
                    }`}
                  >
                    {activeAnalyzer.severity}
                  </span>
                </div>

                {/* Description */}
                <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed pt-1">
                  {activeAnalyzer.description}
                </p>

                {/* Monitored Sinks */}
                <div className="pt-2">
                  <div className="text-[10.5px] font-mono uppercase tracking-wider text-zinc-400 mb-2">
                    Monitored AST Sinks
                  </div>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                    {activeAnalyzer.sinks.map(sink => (
                      <span
                        key={sink}
                        className="bg-zinc-950 px-2 py-0.5 rounded text-zinc-300 border border-zinc-800/60"
                      >
                        {sink}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Remediation Note */}
              <div className="pt-6 mt-6 border-t border-zinc-850 text-xs text-zinc-400 leading-relaxed">
                <span className="font-semibold text-zinc-300 font-mono text-[11px]">Remediation: </span>
                {activeAnalyzer.remediation}
              </div>
            </div>

            {/* Right Diagnostic Code Panel */}
            <div className="lg:col-span-7 p-6 sm:p-7 bg-zinc-950/60 flex flex-col justify-center space-y-4 font-mono text-xs">
              {/* Flagged Pattern */}
              <div>
                <div className="flex items-center gap-1.5 text-[11px] text-rose-400 mb-1.5 font-sans font-medium">
                  <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                  <span>Flagged Unsafe AST Pattern</span>
                </div>
                <div className="bg-zinc-950 rounded border border-zinc-850/80 p-3.5 text-zinc-300 overflow-x-auto whitespace-pre leading-relaxed">
                  {activeAnalyzer.vulnerableSnippet}
                </div>
                <div className="text-[11px] text-zinc-400 mt-1 font-sans">
                  {activeAnalyzer.vulnerableLabel}
                </div>
              </div>

              {/* Remediated Pattern */}
              <div>
                <div className="flex items-center gap-1.5 text-[11px] text-emerald-400 mb-1.5 font-sans font-medium">
                  <RiCheckLine className="w-3.5 h-3.5 shrink-0" />
                  <span>Hardened Implementation</span>
                </div>
                <div className="bg-zinc-950 rounded border border-zinc-850/80 p-3.5 text-zinc-300 overflow-x-auto whitespace-pre leading-relaxed">
                  {activeAnalyzer.safeSnippet}
                </div>
                <div className="text-[11px] text-zinc-400 mt-1 font-sans">
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
