import { useState, useEffect, useCallback } from 'react'
import { ToastProvider } from './context/ToastContext'
import { AuthProvider, useAuth } from './context/AuthContext'
import { HomePage } from './pages/HomePage'
import { DashboardPage } from './pages/DashboardPage'
import { AuthModal } from './components/organisms/AuthModal'

function AppContent() {
  const getInitialView = (): 'home' | 'dashboard' => {
    return window.location.pathname.startsWith('/dashboard') ? 'dashboard' : 'home'
  }

  const [currentView, setCurrentView] = useState<'home' | 'dashboard'>(getInitialView)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login')
  const [pendingScanRepo, setPendingScanRepo] = useState<string>('')
  const { isAuthenticated, isLoading: authLoading } = useAuth()

  const handleOpenAuth = useCallback((mode: 'login' | 'signup') => {
    setAuthMode(mode)
    setAuthModalOpen(true)
  }, [])

  const navigateToView = useCallback((view: 'home' | 'dashboard') => {
    const targetPath = view === 'dashboard' ? '/dashboard' : '/'
    if (window.location.pathname !== targetPath) {
      window.history.pushState(null, '', targetPath)
    }
    setCurrentView(view)
  }, [])

  const handleNavigate = useCallback(
    (view: 'home' | 'dashboard') => {
      if (view === 'dashboard' && !isAuthenticated) {
        handleOpenAuth('login')
        return
      }
      navigateToView(view)
    },
    [isAuthenticated, handleOpenAuth, navigateToView]
  )

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
      const isDash = window.location.pathname.startsWith('/dashboard')
      if (isDash && !isAuthenticated) {
        window.history.replaceState(null, '', '/')
        setCurrentView('home')
        handleOpenAuth('login')
      } else {
        setCurrentView(isDash ? 'dashboard' : 'home')
      }
    }

    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [isAuthenticated, handleOpenAuth])

  // Guard initial route on load if opened directly at /dashboard
  useEffect(() => {
    if (!authLoading && window.location.pathname.startsWith('/dashboard') && !isAuthenticated) {
      window.history.replaceState(null, '', '/')
      setCurrentView('home')
      handleOpenAuth('login')
    }
  }, [authLoading, isAuthenticated, handleOpenAuth])

  return (
    <>
      {currentView === 'home' ? (
        <HomePage
          onOpenAuth={handleOpenAuth}
          onNavigate={handleNavigate}
          onStartScan={handleStartScan}
        />
      ) : (
        <DashboardPage
          onNavigate={handleNavigate}
          initialScanRepo={pendingScanRepo}
          onClearInitialScan={() => setPendingScanRepo('')}
        />
      )}

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
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ToastProvider>
  )
}
