import { useState } from 'react'
import { ToastProvider } from './context/ToastContext'
import { AuthProvider, useAuth } from './context/AuthContext'
import { HomePage } from './pages/HomePage'
import { DashboardPage } from './pages/DashboardPage'
import { AuthModal } from './components/organisms/AuthModal'

function AppContent() {
  const [currentView, setCurrentView] = useState<'home' | 'dashboard'>('home')
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login')
  const { isAuthenticated } = useAuth()

  const handleOpenAuth = (mode: 'login' | 'signup') => {
    setAuthMode(mode)
    setAuthModalOpen(true)
  }

  const handleNavigate = (view: 'home' | 'dashboard') => {
    if (view === 'dashboard' && !isAuthenticated) {
      handleOpenAuth('login')
      return
    }
    setCurrentView(view)
  }

  const handleAuthSuccess = () => {
    setCurrentView('dashboard')
  }

  return (
    <>
      {currentView === 'home' ? (
        <HomePage
          onOpenAuth={handleOpenAuth}
          onNavigate={handleNavigate}
        />
      ) : (
        <DashboardPage onNavigate={handleNavigate} />
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
