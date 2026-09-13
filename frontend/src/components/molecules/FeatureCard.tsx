import React from 'react'
import { Badge } from '../atoms/Badge'

export interface FeatureCardProps {
  title: string
  description: string
  badgeText?: string
  icon: React.ReactNode
}

export const FeatureCard: React.FC<FeatureCardProps> = ({
  title,
  description,
  badgeText,
  icon,
}) => {
  return (
    <div className="bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-6 flex flex-col justify-between transition-colors duration-150 text-left">
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="w-8 h-8 rounded bg-zinc-800/80 border border-zinc-700/60 flex items-center justify-center text-zinc-300">
            {icon}
          </div>
          {badgeText && (
            <Badge variant="default" size="sm">
              {badgeText}
            </Badge>
          )}
        </div>
        <h3 className="text-sm font-semibold text-zinc-100 tracking-tight mb-2">
          {title}
        </h3>
        <p className="text-xs text-zinc-400 leading-relaxed">
          {description}
        </p>
      </div>
    </div>
  )
}
