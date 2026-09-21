import React, { useState, useRef, useEffect } from 'react'
import {
  RiDashboardLine,
  RiLogoutBoxRLine,
  RiUser3Line,
  RiArrowDownSLine,
  RiShieldCheckLine,
} from '@remixicon/react'
import { Logo } from '../atoms/Logo'
import { Button } from '../atoms/Button'
import { useAuth } from '../../context/AuthContext'
import { useConfirm } from '../../context/ConfirmContext'

interface NavbarProps {
  onOpenAuth?: (mode: 'login' | 'signup') => void
  onNavigate: (view: 'home' | 'dashboard' | 'profile') => void
  currentView?: 'home' | 'dashboard' | 'report' | 'profile'
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenAuth,
  onNavigate,
  currentView,
}) => {
  const { user, isAuthenticated, logout } = useAuth()
  const { confirm } = useConfirm()

  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const closeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleMouseEnter = () => {
    if (closeTimeoutRef.current) {
      clearTimeout(closeTimeoutRef.current)
      closeTimeoutRef.current = null
    }
    setMenuOpen(true)
  }

  const handleMouseLeave = () => {
    closeTimeoutRef.current = setTimeout(() => {
      setMenuOpen(false)
    }, 200)
  }

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      if (closeTimeoutRef.current) {
        clearTimeout(closeTimeoutRef.current)
      }
    }
  }, [])

  const handleLogout = async () => {
    setMenuOpen(false)
    const confirmed = await confirm({
      title: 'Sign Out Confirmation',
      description: 'Are you sure you want to sign out of your VulScan account?',
      confirmLabel: 'Sign Out',
      cancelLabel: 'Cancel',
      variant: 'danger',
    })

    if (confirmed) {
      await logout()
      onNavigate('home')
    }
  }

  const handleOpenProfile = () => {
    setMenuOpen(false)
    onNavigate('profile')
  }

  const initials = user
    ? `${user.firstName?.charAt(0) || ''}${user.lastName?.charAt(0) || ''}`.toUpperCase() || 'U'
    : 'U'

  const displayName = user
    ? user.firstName
      ? `${user.firstName}${user.lastName ? ' ' + user.lastName : ''}`
      : user.email.split('@')[0]
    : 'User'

  return (
    <header className="bg-surface/90 backdrop-blur-md px-4 sm:px-8 py-2 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand */}
        <div
          onClick={() => onNavigate(isAuthenticated ? 'dashboard' : 'home')}
          className="cursor-pointer select-none transition-opacity hover:opacity-90 flex items-center gap-3"
        >
            <Logo showWordmark size="md" />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-3">
            {isAuthenticated && user ? (
              <div className="flex items-center gap-3">
                {/* Dashboard Nav Button */}
                <button
                  type="button"
                  onClick={() => onNavigate('dashboard')}
                  className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                    currentView === 'dashboard'
                      ? 'bg-surface-muted text-text-primary border-border'
                      : 'text-text-secondary hover:text-text-primary hover:bg-surface-muted/50 border-transparent hover:border-border-subtle'
                  }`}
                >
                  <RiDashboardLine className="w-3.5 h-3.5" />
                  <span>Dashboard</span>
                </button>

                {/* Profile Circle & Dropdown on Hover/Click */}
                <div
                  ref={menuRef}
                  className="relative"
                  onMouseEnter={handleMouseEnter}
                  onMouseLeave={handleMouseLeave}
                >
                  <button
                    type="button"
                    onClick={() => setMenuOpen(prev => !prev)}
                    className="flex items-center gap-2 p-1 pl-1.5 pr-2.5 rounded-full bg-surface-muted/70 hover:bg-surface-muted border border-border-subtle hover:border-border transition-all cursor-pointer select-none group"
                    aria-expanded={menuOpen}
                    aria-haspopup="true"
                  >
                    {/* Profile Circle */}
                    <div className="w-7 h-7 rounded-full bg-surface border border-border flex items-center justify-center text-text-primary text-xs font-medium tracking-tight shadow-inner group-hover:border-text-muted transition-colors">
                      {initials}
                    </div>

                    {/* Only Username */}
                    <span className="text-xs font-medium text-text-primary tracking-tight max-w-[120px] truncate">
                      {displayName}
                    </span>

                    <RiArrowDownSLine
                      className={`w-3.5 h-3.5 text-text-muted group-hover:text-text-secondary transition-transform duration-200 ${
                        menuOpen ? 'rotate-180' : ''
                      }`}
                    />
                  </button>

                  {/* Dropdown Menu */}
                  {menuOpen && (
                    <div className="absolute right-0 mt-2 w-56 rounded-2xl bg-surface border border-border shadow-2xl shadow-black/80 py-1.5 z-50 animate-in fade-in zoom-in-95 duration-150 text-left">
                      {/* User Info Header */}
                      <div className="px-3.5 py-2.5 border-b border-border-subtle flex items-center gap-3">
                        <div className="w-9 h-9 rounded-full bg-surface-muted border border-border flex items-center justify-center text-text-primary text-xs font-medium shrink-0">
                          {initials}
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-medium text-text-primary truncate">
                            {displayName}
                          </p>
                          <p className="text-[11px] text-text-muted truncate font-mono">
                            {user.email}
                          </p>
                        </div>
                      </div>

                      {/* Menu Actions */}
                      <div className="p-1 space-y-0.5">
                        <button
                          type="button"
                          onClick={handleOpenProfile}
                          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors cursor-pointer text-left"
                        >
                          <RiUser3Line className="w-3.5 h-3.5 text-text-muted" />
                          <span>View / Edit Profile</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => {
                            setMenuOpen(false)
                            onNavigate('dashboard')
                          }}
                          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors cursor-pointer text-left"
                        >
                          <RiShieldCheckLine className="w-3.5 h-3.5 text-text-muted" />
                          <span>Security Dashboard</span>
                        </button>
                      </div>

                      {/* Logout Action */}
                      <div className="p-1 border-t border-border-subtle mt-1">
                        <button
                          type="button"
                          onClick={handleLogout}
                          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-danger hover:text-danger hover:bg-surface-hover transition-colors cursor-pointer text-left"
                        >
                          <RiLogoutBoxRLine className="w-3.5 h-3.5 text-danger" />
                          <span>Sign Out</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onOpenAuth?.('login')}
                >
                  Sign in
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => onOpenAuth?.('signup')}
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
