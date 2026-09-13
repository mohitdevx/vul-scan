import React, { forwardRef } from 'react'

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  hasError?: boolean
  icon?: React.ReactNode
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ hasError, icon, className = '', ...props }, ref) => {
    return (
      <div className="relative w-full">
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
            {icon}
          </div>
        )}
        <input
          ref={ref}
          className={`w-full rounded-md bg-zinc-900/80 border text-zinc-100 placeholder:text-zinc-600 text-sm font-sans px-3 py-2 transition-colors duration-150 outline-none ${
            icon ? 'pl-9' : ''
          } ${
            hasError
              ? 'border-red-800 focus:border-red-600 text-red-100'
              : 'border-zinc-800 focus:border-zinc-500'
          } ${className}`}
          {...props}
        />
      </div>
    )
  }
)

Input.displayName = 'Input'
