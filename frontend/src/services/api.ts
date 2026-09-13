const API_BASE =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000'

export interface User {
  id: string
  firstName: string
  lastName: string
  orgName: string
  email: string
  createdAt: string
}

export interface AuthResponse {
  message: string
  token: string
  user: User
}

export interface SignupPayload {
  firstname: string
  lastname: string
  org_name: string
  email: string
  password: string
  confirmPassword: string
}

export interface LoginPayload {
  email: string
  password: string
}

class ApiError extends Error {
  status: number
  issues?: unknown[]

  constructor(message: string, status: number, issues?: unknown[]) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.issues = issues
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('vulnscan_token')

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }

  if (token) {
    ;(headers as Record<string, string>)['Authorization'] = `Bearer ${token}`
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new ApiError(
      data.message || data.error || `Request failed with status ${response.status}`,
      response.status,
      data.issues
    )
  }

  return data as T
}

export const authApi = {
  signup: (payload: SignupPayload) =>
    request<AuthResponse>('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  login: (payload: LoginPayload) =>
    request<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getMe: () => request<{ user: User }>('/api/auth/me'),

  logout: () =>
    request<{ message: string }>('/api/auth/logout', {
      method: 'POST',
    }),
}
