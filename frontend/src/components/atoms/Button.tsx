import React from 'react'
import { Spinner } from './Spinner'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger'
  size?: 'sm' | 'md' | 'lg'
  isLoading?: boolean
  loadingText?: string
  icon?: React.ReactNode
}

const variantClasses = {
  primary:
    'bg-white text-zinc-950 hover:bg-zinc-200 border border-white font-medium shadow-sm',
  secondary:
    'bg-zinc-900 text-zinc-200 hover:bg-zinc-800 hover:text-white border border-zinc-800',
  outline:
    'bg-transparent text-zinc-300 hover:text-white hover:bg-zinc-900 border border-zinc-800',
  ghost:
    'bg-transparent text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/60 border border-transparent',
  danger:
    'bg-red-950 text-red-200 hover:bg-red-900 border border-red-800',
}

const sizeClasses = {
  sm: 'px-2.5 py-1.5 text-xs gap-1.5',
  md: 'px-3.5 py-2 text-sm gap-2',
  lg: 'px-4.5 py-2.5 text-sm gap-2',
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  loadingText,
  icon,
  disabled,
  className = '',
  ...props
}) => {
  const isDisabled = disabled || isLoading

  return (
    <button
      disabled={isDisabled}
      className={`inline-flex items-center justify-center rounded-md transition-colors duration-150 select-none cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
      {...props}
    >
      {isLoading ? (
        <>
          <Spinner size={size === 'lg' ? 'md' : 'sm'} />
          <span>{loadingText || children}</span>
        </>
      ) : (
        <>
          {icon && <span className="shrink-0">{icon}</span>}
          <span>{children}</span>
        </>
      )}
    </button>
  )
}
