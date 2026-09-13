import React from 'react'

export interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'primary' | 'critical' | 'high' | 'medium' | 'low' | 'clean'
  size?: 'sm' | 'md'
  className?: string
}

const variantClasses = {
  default: 'bg-zinc-900 text-zinc-400 border-zinc-800',
  primary: 'bg-zinc-800 text-zinc-200 border-zinc-700',
  critical: 'bg-zinc-900 text-red-400 border-zinc-800',
  high: 'bg-zinc-900 text-orange-400 border-zinc-800',
  medium: 'bg-zinc-900 text-amber-400 border-zinc-800',
  low: 'bg-zinc-900 text-zinc-300 border-zinc-800',
  clean: 'bg-zinc-900 text-emerald-400 border-zinc-800',
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'sm',
  className = '',
}) => {
  return (
    <span
      className={`inline-flex items-center rounded border font-mono tracking-wider font-medium select-none ${
        size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'
      } ${variantClasses[variant]} ${className}`}
    >
      {children}
    </span>
  )
}
