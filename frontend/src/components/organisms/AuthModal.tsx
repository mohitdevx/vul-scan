import { useState, useEffect, type FC } from 'react'
import {
  RiCloseLine,
  RiMailLine,
  RiLockLine,
  RiUserLine,
  RiBuildingLine,
} from '@remixicon/react'
import { Button } from '../atoms/Button'
import { Logo } from '../atoms/Logo'
import { FormField } from '../molecules/FormField'
import { useAuth } from '../../context/AuthContext'

export interface AuthModalProps {
  isOpen: boolean
  initialMode?: 'login' | 'signup'
  onClose: () => void
  onSuccess?: () => void
}

export const AuthModal: FC<AuthModalProps> = ({
  isOpen,
  initialMode = 'login',
  onClose,
  onSuccess,
}) => {
  const [mode, setMode] = useState<'login' | 'signup'>(initialMode)
  const { login, signup, isActionLoading } = useAuth()

  // Form states
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [orgName, setOrgName] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    setMode(initialMode)
    setErrors({})
  }, [initialMode, isOpen])

  if (!isOpen) return null

  const validate = (): boolean => {
    const errs: Record<string, string> = {}

    if (!email.trim() || !/\S+@\S+\.\S+/.test(email)) {
      errs.email = 'Valid email is required'
    }

    if (!password) {
      errs.password = 'Password is required'
    } else if (password.length < 6) {
      errs.password = 'Password must be at least 6 characters'
    }

    if (mode === 'signup') {
      if (!firstName.trim()) errs.firstName = 'First name is required'
      if (!lastName.trim()) errs.lastName = 'Last name is required'
      if (!orgName.trim()) errs.orgName = 'Organization name is required'
      if (!confirmPassword) {
        errs.confirmPassword = 'Confirmation is required'
      } else if (password !== confirmPassword) {
        errs.confirmPassword = 'Passwords do not match'
      }
    }

    setErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return

    if (mode === 'login') {
      const ok = await login({ email, password })
      if (ok) {
        onClose()
        if (onSuccess) onSuccess()
      }
    } else {
      const ok = await signup({
        firstname: firstName,
        lastname: lastName,
        org_name: orgName,
        email,
        password,
        confirmPassword,
      })
      if (ok) {
        onClose()
        if (onSuccess) onSuccess()
      }
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6"
    >
      {/* Dimmed backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/80 backdrop-blur-[1px] transition-opacity duration-150"
      />

      {/* Aesthetic Modal Container */}
      <div className="relative w-full max-w-[420px] bg-zinc-950 border border-zinc-800 rounded-xl shadow-[0_20px_60px_rgba(0,0,0,0.9)] z-10 p-6 sm:p-7 text-left">
        {/* Header Row */}
        <div className="flex items-start justify-between mb-5">
          <div className="flex items-center gap-2.5">
            <Logo size={20} />
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-zinc-100">
                {mode === 'login' ? 'Sign in to vulscan' : 'Create an Account'}
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="text-zinc-500 hover:text-zinc-200 p-1 -mr-1 -mt-1 rounded transition-colors cursor-pointer"
          >
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>

        {/* Minimal Underline Tab Switcher */}
        <div className="flex border-b border-zinc-850 gap-6 mb-5">
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setErrors({})
            }}
            className={`pb-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer ${
              mode === 'login'
                ? 'border-white text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            Sign in
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('signup')
              setErrors({})
            }}
            className={`pb-2.5 text-xs font-medium border-b-2 transition-all cursor-pointer ${
              mode === 'signup'
                ? 'border-white text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            Create account
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-3.5">
          {mode === 'signup' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <FormField
                  label="First Name"
                  required
                  placeholder="First name"
                  value={firstName}
                  onChange={e => setFirstName(e.target.value)}
                  error={errors.firstName}
                  icon={<RiUserLine className="w-3.5 h-3.5" />}
                />
                <FormField
                  label="Last Name"
                  required
                  placeholder="Last name"
                  value={lastName}
                  onChange={e => setLastName(e.target.value)}
                  error={errors.lastName}
                  icon={<RiUserLine className="w-3.5 h-3.5" />}
                />
              </div>

              <FormField
                label="Organization"
                required
                placeholder="Company or org"
                value={orgName}
                onChange={e => setOrgName(e.target.value)}
                error={errors.orgName}
                icon={<RiBuildingLine className="w-3.5 h-3.5" />}
              />
            </>
          )}

          <FormField
            label="Email"
            type="email"
            required
            placeholder="name@company.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            error={errors.email}
            icon={<RiMailLine className="w-3.5 h-3.5" />}
          />

          <FormField
            label="Password"
            type="password"
            required
            placeholder="••••••••"
            value={password}
            onChange={e => setPassword(e.target.value)}
            error={errors.password}
            icon={<RiLockLine className="w-3.5 h-3.5" />}
          />

          {mode === 'signup' && (
            <FormField
              label="Confirm Password"
              type="password"
              required
              placeholder="••••••••"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              error={errors.confirmPassword}
              icon={<RiLockLine className="w-3.5 h-3.5" />}
            />
          )}

          {/* Submit Action */}
          <div className="pt-2">
            <Button
              type="submit"
              variant="primary"
              size="md"
              className="w-full h-9.5 text-xs font-medium"
              isLoading={isActionLoading}
              loadingText={mode === 'login' ? 'Signing in...' : 'Creating account...'}
            >
              {mode === 'login' ? 'Sign in' : 'Create account'}
            </Button>
          </div>

          <div className="text-center text-xs text-zinc-500 pt-1">
            {mode === 'login' ? (
              <span>
                Don&apos;t have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('signup')
                    setErrors({})
                  }}
                  className="text-zinc-300 hover:text-white transition-colors cursor-pointer"
                >
                  Create account
                </button>
              </span>
            ) : (
              <span>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('login')
                    setErrors({})
                  }}
                  className="text-zinc-300 hover:text-white transition-colors cursor-pointer"
                >
                  Sign in
                </button>
              </span>
            )}
          </div>
        </form>
      </div>
    </div>
  )
}
