import {
  RiLogoutBoxRLine,
  RiDashboardLine,
  RiUser3Line,
} from '@remixicon/react'
import { Button } from '../atoms/Button'
import { Logo } from '../atoms/Logo'
import { useAuth } from '../../context/AuthContext'

interface NavbarProps {
  onOpenAuth: (mode: 'login' | 'signup') => void
  onNavigate: (view: 'home' | 'dashboard') => void
  currentView: 'home' | 'dashboard'
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenAuth,
  onNavigate,
  currentView,
}) => {
  const { user, isAuthenticated, logout } = useAuth()

  return (
    <header className="border-b border-zinc-800/80 bg-zinc-950 px-4 sm:px-8 py-3.5 sticky top-0 z-40">
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <div
          onClick={() => onNavigate('home')}
          className="cursor-pointer select-none"
        >
          <Logo showWordmark size="md" />
        </div>


        {/* Right Actions */}
        <div className="flex items-center gap-2.5">
          {isAuthenticated && user ? (
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() =>
                  onNavigate(currentView === 'dashboard' ? 'home' : 'dashboard')
                }
                className="flex items-center gap-1.5 text-xs font-medium text-zinc-400 hover:text-zinc-100 px-3 py-1.5 rounded-md hover:bg-zinc-900 border border-zinc-800 transition-colors cursor-pointer"
              >
                <RiDashboardLine className="w-3.5 h-3.5" />
                <span>{currentView === 'dashboard' ? 'Home' : 'Dashboard'}</span>
              </button>
              <div className="hidden sm:flex items-center gap-2 text-xs text-zinc-400 pl-1">
                <div className="w-6 h-6 rounded-full bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-300 text-xs">
                  <RiUser3Line className="w-3 h-3" />
                </div>
                <span className="text-zinc-300">{user.firstName}</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={logout}
                title="Log out"
                aria-label="Log out"
                icon={<RiLogoutBoxRLine className="w-3.5 h-3.5" />}
              />
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onOpenAuth('login')}
              >
                Sign in
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => onOpenAuth('signup')}
              >
                Get Started
              </Button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
