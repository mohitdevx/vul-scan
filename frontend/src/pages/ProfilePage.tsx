import React, { useState, useEffect } from 'react'
import {
  RiArrowLeftLine,
  RiUserLine,
  RiLockPasswordLine,
  RiBuildingLine,
  RiMailLine,
  RiShieldCheckLine,
  RiCalendarLine,
  RiCheckLine,
} from '@remixicon/react'
import { Navbar } from '../components/organisms/Navbar'
import { Button } from '../components/atoms/Button'
import { Spinner } from '../components/atoms/Spinner'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'

interface ProfilePageProps {
  onNavigate: (view: 'home' | 'dashboard' | 'profile') => void
}

export const ProfilePage: React.FC<ProfilePageProps> = ({ onNavigate }) => {
  const { user, updateProfile, isActionLoading } = useAuth()
  const { error } = useToast()

  // Profile Form States
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [orgName, setOrgName] = useState('')

  // Password States
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  // Active Tab
  const [activeTab, setActiveTab] = useState<'general' | 'security'>('general')

  useEffect(() => {
    if (user) {
      setFirstName(user.firstName || '')
      setLastName(user.lastName || '')
      setOrgName(user.orgName || '')
    }
  }, [user])

  const initials = user
    ? `${user.firstName?.charAt(0) || ''}${user.lastName?.charAt(0) || ''}`.toUpperCase() || 'U'
    : 'U'

  const formattedDate = user?.createdAt
    ? new Date(user.createdAt).toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      })
    : 'Active'

  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!firstName.trim()) {
      error('First name cannot be empty.', 'Validation Error')
      return
    }

    await updateProfile({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      orgName: orgName.trim(),
    })
  }

  const handleSavePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!currentPassword) {
      error('Please enter your current password.', 'Validation Error')
      return
    }
    if (newPassword.length < 6) {
      error('New password must be at least 6 characters.', 'Validation Error')
      return
    }
    if (newPassword !== confirmPassword) {
      error('New passwords do not match.', 'Validation Error')
      return
    }

    const success = await updateProfile({
      currentPassword,
      newPassword,
    })

    if (success) {
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    }
  }

  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col font-sans">
      <Navbar onNavigate={onNavigate} currentView="profile" />

      <main className="flex-1 max-w-4xl w-full mx-auto px-4 sm:px-8 py-8 space-y-8">
        {/* Back Button & Breadcrumb */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="inline-flex items-center gap-1.5 text-xs font-mono text-text-muted hover:text-text-primary transition-colors cursor-pointer"
          >
            <RiArrowLeftLine className="w-4 h-4" />
            <span>Back to Dashboard</span>
          </button>
        </div>

        {/* Profile Header Card */}
        <section className="p-6 sm:p-8 rounded-2xl bg-surface border border-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
          <div className="flex items-center gap-5">
            {/* Large Avatar Circle */}
            <div className="w-16 h-16 rounded-full bg-surface-muted border border-border flex items-center justify-center text-text-primary text-xl font-semibold tracking-tight shrink-0 shadow-inner">
              {initials}
            </div>

            <div className="space-y-1">
              <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-text-primary">
                {user ? `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'User Account' : 'Account'}
              </h1>
              <div className="flex flex-wrap items-center gap-3 text-xs text-text-secondary font-mono">
                <span className="flex items-center gap-1">
                  <RiMailLine className="w-3.5 h-3.5 text-text-muted" />
                  {user?.email}
                </span>
                <span>•</span>
                <span className="flex items-center gap-1">
                  <RiBuildingLine className="w-3.5 h-3.5 text-text-muted" />
                  {user?.orgName || 'Personal'}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-text-muted bg-surface-muted/60 px-3 py-1.5 rounded-lg border border-border-subtle self-start sm:self-auto">
            <RiCalendarLine className="w-3.5 h-3.5" />
            <span>Member since {formattedDate}</span>
          </div>
        </section>

        {/* Clean Underline Tabs Switcher */}
        <section className="space-y-6">
          <div className="flex items-center gap-6 border-b border-border">
            <button
              type="button"
              onClick={() => setActiveTab('general')}
              className={`flex items-center gap-2 pb-3 text-xs font-mono font-medium transition-all cursor-pointer border-b-2 -mb-px ${
                activeTab === 'general'
                  ? 'border-text-primary text-text-primary font-semibold'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              }`}
            >
              <RiUserLine className="w-3.5 h-3.5" />
              <span>General Information</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('security')}
              className={`flex items-center gap-2 pb-3 text-xs font-mono font-medium transition-all cursor-pointer border-b-2 -mb-px ${
                activeTab === 'security'
                  ? 'border-text-primary text-text-primary font-semibold'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              }`}
            >
              <RiLockPasswordLine className="w-3.5 h-3.5" />
              <span>Password & Security</span>
            </button>
          </div>

          {/* Tab 1: General Info */}
          {activeTab === 'general' && (
            <form onSubmit={handleSaveGeneral} className="p-6 rounded-2xl bg-surface border border-border space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                {/* First Name */}
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    First Name
                  </label>
                  <input
                    type="text"
                    value={firstName}
                    onChange={e => setFirstName(e.target.value)}
                    required
                    className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors"
                    placeholder="First name"
                  />
                </div>

                {/* Last Name */}
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    Last Name
                  </label>
                  <input
                    type="text"
                    value={lastName}
                    onChange={e => setLastName(e.target.value)}
                    className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors"
                    placeholder="Last name"
                  />
                </div>
              </div>

              {/* Email Address */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    Email Address
                  </label>
                  <span className="text-[10px] font-mono text-text-muted">Primary login identifier</span>
                </div>
                <input
                  type="email"
                  value={user?.email || ''}
                  disabled
                  className="w-full bg-surface-muted/50 border border-border-subtle rounded-xl px-3.5 py-2.5 text-xs text-text-muted cursor-not-allowed outline-none font-mono"
                />
              </div>

              {/* Organization */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-text-secondary font-mono">
                  Organization / Team Name
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={e => setOrgName(e.target.value)}
                  className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors"
                  placeholder="e.g. Acme Security Corp"
                />
              </div>

              <div className="pt-2 flex justify-end">
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={isActionLoading}
                  icon={isActionLoading ? <Spinner size="sm" /> : <RiCheckLine className="w-3.5 h-3.5" />}
                >
                  {isActionLoading ? 'Saving...' : 'Save Changes'}
                </Button>
              </div>
            </form>
          )}

          {/* Tab 2: Security & Password */}
          {activeTab === 'security' && (
            <form onSubmit={handleSavePassword} className="p-6 rounded-2xl bg-surface border border-border space-y-6">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-text-primary">Change Password</h3>
                <p className="text-xs text-text-secondary">
                  Ensure your account uses a strong, unique password with at least 6 characters.
                </p>
              </div>

              <div className="space-y-4 max-w-md">
                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    Current Password
                  </label>
                  <input
                    type="password"
                    value={currentPassword}
                    onChange={e => setCurrentPassword(e.target.value)}
                    required
                    className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors font-mono"
                    placeholder="Enter current password"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    New Password
                  </label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    required
                    minLength={6}
                    className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors font-mono"
                    placeholder="At least 6 characters"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-text-secondary font-mono">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    required
                    className="w-full bg-surface-muted border border-border-subtle focus:border-border rounded-xl px-3.5 py-2.5 text-xs text-text-primary placeholder-text-muted outline-none transition-colors font-mono"
                    placeholder="Confirm new password"
                  />
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={isActionLoading}
                  icon={isActionLoading ? <Spinner size="sm" /> : <RiShieldCheckLine className="w-3.5 h-3.5" />}
                >
                  {isActionLoading ? 'Updating...' : 'Update Password'}
                </Button>
              </div>
            </form>
          )}
        </section>
      </main>
    </div>
  )
}
