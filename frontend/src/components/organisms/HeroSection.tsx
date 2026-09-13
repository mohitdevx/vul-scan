import { useState, type FC } from 'react'
import {
  RiArrowRightLine,
  RiGithubLine,
} from '@remixicon/react'
import { Button } from '../atoms/Button'
import { Input } from '../atoms/Input'
import { TerminalWindow } from '../molecules/TerminalWindow'

interface HeroSectionProps {
  onGetStarted: (repoUrl?: string) => void
  onExplore: () => void
}

export const HeroSection: FC<HeroSectionProps> = ({
  onGetStarted,
  onExplore,
}) => {
  const [repoUrl, setRepoUrl] = useState('')

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault()
    onGetStarted(repoUrl.trim())
  }

  return (
    <section className="py-20 md:py-28 bg-zinc-950">
      <div className="max-w-5xl mx-auto px-4 sm:px-6">
        {/* Confident, clean headline */}
        <div className="text-center max-w-3xl mx-auto">
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-semibold tracking-tight text-zinc-100 mb-5 leading-tight">
            Source code security analysis for GitHub repositories
          </h1>

          <p className="text-sm sm:text-base text-zinc-400 max-w-xl mx-auto mb-10 leading-relaxed">
            Scan repositories to detect Cross-Site Scripting, Command Injection, broken
            API authentication flows, and session management vulnerabilities.
          </p>

          {/* High-impact repository scan input box */}
          <form
            onSubmit={handleQuickScan}
            className="max-w-lg mx-auto flex flex-col sm:flex-row items-center gap-2 mb-10"
          >
            <div className="w-full relative">
              <Input
                type="text"
                placeholder="https://github.com/owner/repository"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
                icon={<RiGithubLine className="w-4 h-4 text-zinc-500" />}
              />
            </div>
            <Button
              type="submit"
              variant="primary"
              size="md"
              className="w-full sm:w-auto shrink-0"
              icon={<RiArrowRightLine className="w-4 h-4" />}
            >
              Scan Repo
            </Button>
          </form>

          <div className="flex items-center justify-center gap-4 text-xs text-zinc-500">
            <span>JavaScript &bull; TypeScript &bull; Node.js</span>
            <span>&bull;</span>
            <button
              type="button"
              onClick={onExplore}
              className="text-zinc-400 hover:text-zinc-200 underline underline-offset-4 cursor-pointer"
            >
              View all analyzers
            </button>
          </div>
        </div>

        {/* Side-by-Side Terminal Showcase: Info text on left, Rotated compact terminal on right */}
        <div className="mt-28 sm:mt-36 grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-12 items-center text-left">
          {/* Left Column: Technical Context & Highlights */}
          <div className="lg:col-span-5 space-y-5">
            <h2 className="text-xl sm:text-2xl font-semibold text-zinc-100 tracking-tight leading-snug">
              Precise vulnerability inspection with exact line mapping
            </h2>

            <p className="text-sm text-zinc-400 leading-relaxed">
              Vulscan traverses syntax trees to identify unsanitized execution sinks,
              unescaped templates, and insecure session states directly in your repository.
            </p>

            <div className="space-y-2.5 pt-1 text-xs font-mono text-zinc-400">
              <div className="flex items-center gap-3">
                <span className="text-zinc-500 select-none">01</span>
                <span className="text-zinc-300">Command & shell injection sinks</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-zinc-500 select-none">02</span>
                <span className="text-zinc-300">DOM and innerHTML template XSS</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-zinc-500 select-none">03</span>
                <span className="text-zinc-300">Session fixation and token verification</span>
              </div>
            </div>
          </div>

          {/* Right Column: Rotated Terminal Window with Ambient Depth Blur */}
          <div className="lg:col-span-7 relative">
            {/* Soft backdrop blur layer behind the floating terminal */}
            <div
              aria-hidden="true"
              className="pointer-events-none absolute -inset-3 rounded-2xl bg-zinc-900/60 blur-2xl -z-10"
            />

            {/* Rotated compact terminal window */}
            <div className="transform lg:-rotate-2 hover:rotate-0 transition-transform duration-300 ease-out">
              <TerminalWindow
                title="express-auth-service — branch: main"
                badge="3 findings"
              >
                {/* Target Metadata Bar */}
                <div className="flex items-center justify-between pb-2.5 mb-3 border-b border-zinc-800/80 text-[11px] text-zinc-400">
                  <span>
                    Target: <strong className="text-zinc-200 font-semibold">express-auth-service</strong>
                  </span>
                  <span className="text-zinc-500 font-mono">42 files indexed (48ms)</span>
                </div>

                {/* Compact Findings (2 concise, high-impact AST diagnostics) */}
                <div className="space-y-3">
                  {/* Finding 1: Command Injection */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <span className="text-rose-400 font-semibold text-[9.5px] uppercase tracking-wider bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20">
                          HIGH
                        </span>
                        <span className="text-zinc-200 font-medium">Command Injection (CWE-78)</span>
                      </div>
                      <span className="text-zinc-500 text-[10px]">src/exec.ts:38</span>
                    </div>
                    <div className="bg-zinc-950/90 rounded border border-zinc-850 p-2 text-[11px] text-zinc-300">
                      <span className="text-zinc-500">38 | </span>
                      execSync(<span className="text-rose-300">`ping -c 1 ${'{'}host{'}'}`</span>)
                      <div className="text-rose-400/90 text-[10px] pl-4 mt-0.5">
                        ^ unsanitized parameter in shell sink
                      </div>
                    </div>
                  </div>

                  {/* Finding 2: Cross-Site Scripting */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex items-center gap-1.5">
                        <span className="text-rose-400 font-semibold text-[9.5px] uppercase tracking-wider bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20">
                          HIGH
                        </span>
                        <span className="text-zinc-200 font-medium">Cross-Site Scripting (CWE-79)</span>
                      </div>
                      <span className="text-zinc-500 text-[10px]">src/render.ts:84</span>
                    </div>
                    <div className="bg-zinc-950/90 rounded border border-zinc-850 p-2 text-[11px] text-zinc-300">
                      <span className="text-zinc-500">84 | </span>
                      el.<span className="text-rose-300">innerHTML</span> = req.body.template
                      <div className="text-rose-400/90 text-[10px] pl-4 mt-0.5">
                        ^ unescaped raw HTML sink
                      </div>
                    </div>
                  </div>
                </div>

                {/* Compact Status Bar */}
                <div className="mt-3 pt-2.5 border-t border-zinc-800/80 flex items-center justify-between text-[10.5px] text-zinc-400">
                  <span>AST scan complete &bull; 0 false positives</span>
                  <span className="text-zinc-500 font-mono">142ms</span>
                </div>
              </TerminalWindow>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

