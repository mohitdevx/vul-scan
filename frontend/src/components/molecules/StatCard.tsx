import React from 'react'

export interface StatCardProps {
  value: string
  label: string
  description?: string
  icon?: React.ReactNode
}

export const StatCard: React.FC<StatCardProps> = ({ value, label, description, icon }) => {
  return (
    <div className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-5 flex flex-col justify-between text-left">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-zinc-500 uppercase tracking-wider font-mono">
          {label}
        </span>
        {icon && <div className="text-zinc-500">{icon}</div>}
      </div>
      <div>
        <div className="text-2xl lg:text-3xl font-semibold tracking-tight text-zinc-100 font-sans">
          {value}
        </div>
        {description && (
          <p className="text-xs text-zinc-400 mt-1">{description}</p>
        )}
      </div>
    </div>
  )
}
