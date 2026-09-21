import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authApi, type User, type SignupPayload, type LoginPayload } from '../services/api'
import { useToast } from './ToastContext'

interface AuthContextValue {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  isActionLoading: boolean
  login: (credentials: LoginPayload) => Promise<boolean>
  signup: (data: SignupPayload) => Promise<boolean>
  logout: () => Promise<void>
  updateProfile: (payload: {
    firstName?: string
    lastName?: string
    orgName?: string
    currentPassword?: string
    newPassword?: string
  }) => Promise<boolean>
  updateUser: (user: User) => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const saved = localStorage.getItem('vulnscan_user')
    if (saved) {
      try {
        return JSON.parse(saved)
      } catch {
        return null
      }
    }
    return null
  })
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem('vulnscan_token')
  )
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [isActionLoading, setIsActionLoading] = useState<boolean>(false)
  const toast = useToast()

  // Verify auth on mount
  useEffect(() => {
    let mounted = true

    async function verify() {
      const storedToken = localStorage.getItem('vulnscan_token')
      if (!storedToken) {
        if (mounted) setIsLoading(false)
        return
      }

      try {
        const res = await authApi.getMe()
        if (mounted) {
          setUser(res.user)
          localStorage.setItem('vulnscan_user', JSON.stringify(res.user))
        }
      } catch (_err) {
        if (mounted) {
          setUser(null)
          setToken(null)
          localStorage.removeItem('vulnscan_token')
          localStorage.removeItem('vulnscan_user')
        }
      } finally {
        if (mounted) setIsLoading(false)
      }
    }

    verify()

    return () => {
      mounted = false
    }
  }, [])

  const signup = useCallback(
    async (data: SignupPayload): Promise<boolean> => {
      setIsActionLoading(true)
      try {
        const res = await authApi.signup(data)
        setUser(res.user)
        setToken(res.token)
        localStorage.setItem('vulnscan_token', res.token)
        localStorage.setItem('vulnscan_user', JSON.stringify(res.user))
        toast.success(`Welcome to VulnScan, ${res.user.firstName}!`, 'Account Created')
        return true
      } catch (err: any) {
        toast.error(err.message || 'Failed to create account', 'Signup Error')
        return false
      } finally {
        setIsActionLoading(false)
      }
    },
    [toast]
  )

  const login = useCallback(
    async (credentials: LoginPayload): Promise<boolean> => {
      setIsActionLoading(true)
      try {
        const res = await authApi.login(credentials)
        setUser(res.user)
        setToken(res.token)
        localStorage.setItem('vulnscan_token', res.token)
        localStorage.setItem('vulnscan_user', JSON.stringify(res.user))
        toast.success(`Welcome back, ${res.user.firstName}!`, 'Authenticated')
        return true
      } catch (err: any) {
        toast.error(err.message || 'Invalid email or password', 'Login Failed')
        return false
      } finally {
        setIsActionLoading(false)
      }
    },
    [toast]
  )

  const logout = useCallback(async () => {
    setIsActionLoading(true)
    try {
      await authApi.logout().catch(() => {})
    } finally {
      setUser(null)
      setToken(null)
      localStorage.removeItem('vulnscan_token')
      localStorage.removeItem('vulnscan_user')
      setIsActionLoading(false)
      toast.info('You have been logged out.', 'Session Ended')
    }
  }, [toast])

  const updateProfile = useCallback(
    async (payload: {
      firstName?: string
      lastName?: string
      orgName?: string
      currentPassword?: string
      newPassword?: string
    }): Promise<boolean> => {
      setIsActionLoading(true)
      try {
        const res = await authApi.updateProfile(payload)
        setUser(res.user)
        localStorage.setItem('vulnscan_user', JSON.stringify(res.user))
        setIsActionLoading(false)
        toast.success('Your profile has been successfully updated.', 'Profile Updated')
        return true
      } catch (err: any) {
        setIsActionLoading(false)
        toast.error(err.message || 'Failed to update profile', 'Update Error')
        return false
      }
    },
    [toast]
  )

  const updateUser = useCallback((updatedUser: User) => {
    setUser(updatedUser)
    localStorage.setItem('vulnscan_user', JSON.stringify(updatedUser))
  }, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(user && token),
        isLoading,
        isActionLoading,
        login,
        signup,
        logout,
        updateProfile,
        updateUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
