import React from 'react'
import { Navbar } from '../components/organisms/Navbar'
import { HeroSection } from '../components/organisms/HeroSection'
import { FeaturesSection } from '../components/organisms/FeaturesSection'
import { Footer } from '../components/organisms/Footer'

interface HomePageProps {
  onOpenAuth: (mode: 'login' | 'signup') => void
  onNavigate: (view: 'home' | 'dashboard' | 'profile') => void
  onStartScan: (repoUrl?: string) => void
}

export const HomePage: React.FC<HomePageProps> = ({
  onOpenAuth,
  onNavigate,
  onStartScan,
}) => {
  const handleScrollToCapabilities = () => {
    const el = document.getElementById('analyzers')
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    }
  }

  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
      <Navbar
        onOpenAuth={onOpenAuth}
        onNavigate={onNavigate}
        currentView="home"
      />
      <main className="flex-1">
        <HeroSection
          onGetStarted={onStartScan}
          onExplore={handleScrollToCapabilities}
        />
        <FeaturesSection />
      </main>
      <Footer />
    </div>
  )
}
