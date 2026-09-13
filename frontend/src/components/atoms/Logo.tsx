import React from 'react'

export interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | number
  showWordmark?: boolean
  className?: string
}

export const Logo: React.FC<LogoProps> = ({
  size = 'md',
  showWordmark = false,
  className = '',
}) => {
  const pixelSize =
    typeof size === 'number'
      ? size
      : size === 'sm'
      ? 18
      : size === 'lg'
      ? 26
      : 22

  return (
    <div className={`inline-flex items-center gap-2 select-none ${className}`}>
      {/* Diagnostic Scan Reticle Glyph */}
      <svg
        width={pixelSize}
        height={pixelSize}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="shrink-0"
        aria-hidden="true"
      >
        {/* 4 Viewfinder Scan Brackets */}
        <path
          d="M7 13V7H13"
          className="stroke-zinc-100"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M25 13V7H19"
          className="stroke-zinc-100"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M25 19V25H19"
          className="stroke-zinc-100"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M7 19V25H13"
          className="stroke-zinc-100"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        {/* Precision Laser Reticle Crosshair */}
        <path
          d="M16 10V22"
          className="stroke-zinc-500"
          strokeWidth="1.3"
          strokeLinecap="round"
        />
        <path
          d="M10 16H22"
          className="stroke-zinc-500"
          strokeWidth="1.3"
          strokeLinecap="round"
        />
        {/* Focal Diagnostic Node */}
        <path
          d="M16 13.5L18.5 16L16 18.5L13.5 16L16 13.5Z"
          className="fill-white"
        />
      </svg>

      {showWordmark && (
        <span className="text-sm tracking-tight font-sans">
          <span className="font-semibold text-zinc-100">vul</span>
          <span className="font-normal text-zinc-400">scan</span>
        </span>
      )}
    </div>
  )
}
