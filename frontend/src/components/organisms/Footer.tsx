import { type FC } from 'react'
import { Logo } from '../atoms/Logo'

export const Footer: FC = () => {
  return (
    <footer className="border-t border-zinc-800/80 bg-zinc-950 px-4 sm:px-8 py-6 mt-auto">
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-zinc-500">
        <div className="flex items-center gap-2">
          <Logo showWordmark size="sm" />
          <span>&bull;</span>
          <span>Repository Vulnerability Scanner</span>
        </div>

        <div className="flex items-center gap-6">
          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            className="hover:text-zinc-300 transition-colors"
          >
            GitHub
          </a>
        </div>
      </div>
    </footer>
  )
}
