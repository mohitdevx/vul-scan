import { useState, useEffect, useCallback } from 'react'
import { ToastProvider } from './context/ToastContext'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ConfirmProvider } from './context/ConfirmContext'
import { HomePage } from './pages/HomePage'
import { DashboardPage } from './pages/DashboardPage'
import { ReportPage } from './pages/ReportPage'
import { ProfilePage } from './pages/ProfilePage'
import { GitHubCallbackPage } from './pages/GitHubCallbackPage'
import { AuthModal } from './components/organisms/AuthModal'

function AppContent() {
  const getInitialState = (): { view: 'home' | 'dashboard' | 'report' | 'github-callback' | 'profile'; scanId: string | null } => {
    const path = window.location.pathname
    const token = localStorage.getItem('vulnscan_token')
    if (path.startsWith('/github/callback')) {
      return { view: 'github-callback', scanId: null }
    }
    if (path.startsWith('/profile')) {
      return { view: 'profile', scanId: null }
    }
    if (path.startsWith('/report/')) {
      const id = path.replace('/report/', '').trim()
      return { view: 'report', scanId: id || null }
    }
    if (path.startsWith('/dashboard') || (path === '/' && token)) {
      return { view: 'dashboard', scanId: null }
    }
    return { view: 'home', scanId: null }
  }

  const [initial] = useState(getInitialState)
  const [currentView, setCurrentView] = useState<'home' | 'dashboard' | 'report' | 'github-callback' | 'profile'>(initial.view)
  const [inspectingScanId, setInspectingScanId] = useState<string | null>(initial.scanId)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login')
  const [pendingScanRepo, setPendingScanRepo] = useState<string>('')
  const { isAuthenticated, isLoading: authLoading } = useAuth()

  // Auto redirect authenticated users away from home page directly to dashboard
  useEffect(() => {
    if (!authLoading && isAuthenticated && currentView === 'home' && window.location.pathname === '/') {
      navigateToView('dashboard')
    }
  }, [authLoading, isAuthenticated, currentView])

  const handleOpenAuth = useCallback((mode: 'login' | 'signup') => {
    setAuthMode(mode)
    setAuthModalOpen(true)
  }, [])

  const navigateToView = useCallback((view: 'home' | 'dashboard' | 'report' | 'profile', scanId?: string) => {
    let targetPath = '/'
    if (view === 'dashboard') {
      targetPath = '/dashboard'
      setInspectingScanId(null)
    } else if (view === 'profile') {
      targetPath = '/profile'
      setInspectingScanId(null)
    } else if (view === 'report' && scanId) {
      targetPath = `/report/${scanId}`
      setInspectingScanId(scanId)
    } else {
      setInspectingScanId(null)
    }

    if (window.location.pathname !== targetPath) {
      window.history.pushState(null, '', targetPath)
    }
    setCurrentView(view)
  }, [])

  const handleNavigate = useCallback(
    (view: 'home' | 'dashboard' | 'report' | 'profile') => {
      if ((view === 'dashboard' || view === 'report' || view === 'profile') && !isAuthenticated) {
        handleOpenAuth('login')
        return
      }
      navigateToView(view)
    },
    [isAuthenticated, handleOpenAuth, navigateToView]
  )

  const handleInspectScan = useCallback((scanId: string) => {
    navigateToView('report', scanId)
  }, [navigateToView])

  const handleStartScan = useCallback(
    (repoUrl?: string) => {
      const url = (repoUrl || '').trim()
      if (url) {
        setPendingScanRepo(url)
      }

      if (isAuthenticated) {
        navigateToView('dashboard')
      } else {
        handleOpenAuth('signup')
      }
    },
    [isAuthenticated, handleOpenAuth, navigateToView]
  )

  const handleAuthSuccess = useCallback(() => {
    navigateToView('dashboard')
  }, [navigateToView])

  // Sync browser back/forward buttons with current view
  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname
      if (path.startsWith('/report/')) {
        const id = path.replace('/report/', '').trim()
        if (!isAuthenticated) {
          window.history.replaceState(null, '', '/')
          setCurrentView('home')
          handleOpenAuth('login')
        } else {
          setInspectingScanId(id)
          setCurrentView('report')
        }
      } else if (path.startsWith('/profile')) {
        if (!isAuthenticated) {
          window.history.replaceState(null, '', '/')
          setCurrentView('home')
          handleOpenAuth('login')
        } else {
          setInspectingScanId(null)
          setCurrentView('profile')
        }
      } else if (path.startsWith('/dashboard')) {
        if (!isAuthenticated) {
          window.history.replaceState(null, '', '/')
          setCurrentView('home')
          handleOpenAuth('login')
        } else {
          setInspectingScanId(null)
          setCurrentView('dashboard')
        }
      } else {
        setInspectingScanId(null)
        setCurrentView('home')
      }
    }

    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [isAuthenticated, handleOpenAuth])

  // Guard initial route on load if opened directly without authentication
  useEffect(() => {
    if (!authLoading && (window.location.pathname.startsWith('/dashboard') || window.location.pathname.startsWith('/report/') || window.location.pathname.startsWith('/profile')) && !isAuthenticated) {
      window.history.replaceState(null, '', '/')
      setCurrentView('home')
      setInspectingScanId(null)
      handleOpenAuth('login')
    }
  }, [authLoading, isAuthenticated, handleOpenAuth])

  return (
    <>
      <div className="transition-opacity duration-200">
        {currentView === 'home' && (
          <HomePage
            onOpenAuth={handleOpenAuth}
            onNavigate={handleNavigate}
            onStartScan={handleStartScan}
          />
        )}

        {currentView === 'dashboard' && (
          <DashboardPage
            onNavigate={handleNavigate}
            onInspectScan={scan => handleInspectScan(scan.id)}
            initialScanRepo={pendingScanRepo}
            onClearInitialScan={() => setPendingScanRepo('')}
          />
        )}

        {currentView === 'profile' && (
          <ProfilePage
            onNavigate={handleNavigate}
          />
        )}

        {currentView === 'report' && inspectingScanId && (
          <ReportPage
            scanId={inspectingScanId}
            onBack={() => navigateToView('dashboard')}
            onNavigate={handleNavigate}
          />
        )}

        {currentView === 'github-callback' && (
          <GitHubCallbackPage onDone={() => navigateToView('dashboard')} />
        )}
      </div>

      <AuthModal
        isOpen={authModalOpen}
        initialMode={authMode}
        onClose={() => setAuthModalOpen(false)}
        onSuccess={handleAuthSuccess}
      />
    </>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <ConfirmProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </ConfirmProvider>
    </ToastProvider>
  )
}
