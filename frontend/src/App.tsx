import { RiShieldCheckLine, RiGitBranchLine, RiTerminalBoxLine } from '@remixicon/react'

export default function App() {
  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col">
      <header className="border-b border-border bg-surface px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <RiShieldCheckLine className="w-6 h-6 text-primary" />
          <span className="font-semibold text-lg tracking-tight">VulnScan</span>
          <span className="text-xs font-mono uppercase bg-surface-muted text-text-secondary px-2 py-0.5 rounded border border-border-subtle">
            SAST Platform
          </span>
        </div>
        <div className="flex items-center gap-4 text-sm text-text-secondary">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-severity-clean"></span>
            System Ready
          </span>
        </div>
      </header>

      <main className="flex-1 max-w-5xl w-full mx-auto p-6 md:p-10 flex flex-col justify-center items-center text-center">
        <div className="w-12 h-12 rounded-lg bg-surface border border-border flex items-center justify-center mb-6">
          <RiGitBranchLine className="w-6 h-6 text-text-secondary" />
        </div>
        <h1 className="text-2xl md:text-3xl font-semibold tracking-tight text-text-primary mb-3">
          Repository Security & Vulnerability Analysis
        </h1>
        <p className="text-text-secondary max-w-xl text-sm md:text-base mb-8">
          Static code analysis engine to detect XSS, Command Injection, insecure API auth flows, and session management vulnerabilities across GitHub repositories.
        </p>
        <div className="bg-surface border border-border rounded-lg p-4 max-w-md w-full text-left font-mono text-xs text-text-secondary flex items-start gap-2">
          <RiTerminalBoxLine className="w-4 h-4 text-primary shrink-0 mt-0.5" />
          <span>Environment setup initialized. Ready for analyzer modules.</span>
        </div>
      </main>

      <footer className="border-t border-border bg-surface px-6 py-3 text-xs text-text-muted text-center">
        VulnScan SAST Engine &bull; Professional Code Security Scanner
      </footer>
    </div>
  )
}
