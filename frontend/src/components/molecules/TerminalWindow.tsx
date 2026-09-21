import { type FC, type ReactNode } from 'react'

interface TerminalWindowProps {
  title?: string
  badge?: string
  children?: ReactNode
  className?: string
}

export const TerminalWindow: FC<TerminalWindowProps> = ({
  title = 'express-auth-service',
  badge,
  children,
  className = '',
}) => {
  return (
    <div
      className={`rounded-xl border border-zinc-800/90 bg-[#0c0c0f]/95 backdrop-blur-md shadow-2xl shadow-black/80 overflow-hidden text-left font-mono ${className}`}
    >
      {/* Terminal Title Bar / Window Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#111116] border-b border-zinc-800/80 select-none">
        {/* macOS Traffic Light Buttons */}
        <div className="flex items-center gap-1.5 w-16">
          <span
            className="w-2.5 h-2.5 rounded-full bg-[#ff5f56] border border-[#e0443e]/40 inline-block"
            title="Close"
          />
          <span
            className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e] border border-[#dea123]/40 inline-block"
            title="Minimize"
          />
          <span
            className="w-2.5 h-2.5 rounded-full bg-[#27c93f] border border-[#1aab29]/40 inline-block"
            title="Maximize"
          />
        </div>

        {/* Window Title */}
        <div className="text-[11px] text-zinc-400 font-medium truncate px-2 text-center flex-1">
          {title}
        </div>

        {/* Right Badge / Status */}
        <div className="flex items-center justify-end w-24">
          {badge && (
            <span className="text-[10px] text-zinc-400 bg-zinc-850/80 px-2 py-0.5 rounded border border-zinc-750/70 shrink-0">
              {badge}
            </span>
          )}
        </div>
      </div>

      {/* Terminal Body */}
      <div className="p-4 text-[12px] leading-relaxed text-zinc-300 overflow-x-auto no-scrollbar">
        {children}
      </div>
    </div>
  )
}
