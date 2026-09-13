import React from 'react'
import { RiArrowLeftLine, RiLogoutBoxRLine } from '@remixicon/react'
import { Button } from '../components/atoms/Button'
import { useAuth } from '../context/AuthContext'

interface DashboardPageProps {
  onNavigate: (view: 'home' | 'dashboard') => void
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const { user, logout } = useAuth()

  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
      <header className="border-b border-border bg-surface px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onNavigate('home')}
            icon={<RiArrowLeftLine className="w-4 h-4" />}
          >
            Back to Home
          </Button>
          {user && (
            <span className="text-xs text-text-secondary font-mono border-l border-border pl-3">
              {user.email} &bull; {user.orgName}
            </span>
          )}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={logout}
          icon={<RiLogoutBoxRLine className="w-4 h-4" />}
        >
          Sign Out
        </Button>
      </header>

      <main className="flex-1 flex flex-col items-center justify-center p-8">
        <h1 className="text-4xl font-mono uppercase tracking-widest text-text-primary">
          dashboard
        </h1>
      </main>
    </div>
  )
}
