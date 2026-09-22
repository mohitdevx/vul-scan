const API_BASE =
  import.meta.env.VITE_API_BASE_URL || ''

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

export type AiVerdict = 'CONFIRMED_VULNERABILITY' | 'FALSE_POSITIVE' | 'SUSPICIOUS'

export interface AiTriageResult {
  verdict: AiVerdict
  confidence: number
  isFalsePositive: boolean
  reason: string
  remediation: string
  model: string
  sanitizerDetected?: boolean
  safeCastDetected?: boolean
  evaluatedAt: string
  analysis?: string
  dataFlow?: string
  securityImpact?: string
  untrustedSource?: string
}

export interface FindingItem {
  id: string
  ruleId: string
  ruleName: string
  cwe: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  filePath: string
  line: number
  column: number
  snippet: string
  sink: string
  message: string
  remediation: string
  aiAnalysis?: AiTriageResult
  pr?: {
    prNumber: number
    prUrl: string
    branch: string
    state?: string
  }
}

export interface ScanItem {
  id: string
  repoUrl: string
  repoName: string
  branch: string
  status: 'pending' | 'scanning' | 'completed' | 'failed'
  findingsCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  durationMs: number
  createdAt: string
  completedAt?: string
  findings?: FindingItem[]
}

export interface RepositoryItem {
  id: string
  name: string
  url: string
  defaultBranch: string
  createdAt: string
  updatedAt: string
  latestScan?: {
    id: string
    status: string
    findingsCount: number
    highCount: number
    mediumCount: number
    createdAt: string
  } | null
}

export interface DashboardStats {
  totalRepositories: number
  totalScans: number
  totalFindings: number
  highSeverity: number
  mediumSeverity: number
  cleanScans: number
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

  updateProfile: (payload: {
    firstName?: string
    lastName?: string
    orgName?: string
    currentPassword?: string
    newPassword?: string
  }) =>
    request<{ message: string; user: User }>('/api/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  logout: () =>
    request<{ message: string }>('/api/auth/logout', {
      method: 'POST',
    }),
}

export const repositoryApi = {
  list: () => request<{ repositories: RepositoryItem[] }>('/api/repositories'),

  add: (payload: { url: string; name?: string; defaultBranch?: string }) =>
    request<{ message: string; repository: RepositoryItem }>('/api/repositories', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  delete: (id: string) =>
    request<{ message: string; id: string }>(`/api/repositories/${id}`, {
      method: 'DELETE',
    }),
}

export const scanApi = {
  trigger: (payload: { repoUrl: string; branch?: string }) =>
    request<{ message: string; scan: ScanItem }>('/api/scan', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  list: () => request<{ scans: ScanItem[] }>('/api/scan'),

  getById: (id: string) => request<{ scan: ScanItem }>(`/api/scan/${id}`),

  getStats: () => request<{ stats: DashboardStats }>('/api/scan/stats'),

  getBranches: (url: string) =>
    request<{ branches: string[]; defaultBranch: string }>(
      `/api/scan/branches?url=${encodeURIComponent(url)}`
    ),

  delete: (id: string) =>
    request<{ message: string; id: string }>(`/api/scan/${id}`, {
      method: 'DELETE',
    }),

  deleteAll: () =>
    request<{ message: string; deletedCount: number }>('/api/scan', {
      method: 'DELETE',
    }),

  deleteFinding: (scanId: string, findingId: string) =>
    request<{ message: string; scan: ScanItem }>(`/api/scan/${scanId}/findings/${findingId}`, {
      method: 'DELETE',
    }),

  getRepoScans: (repoUrl?: string) =>
    request<{ scans: ScanItem[] }>(
      `/api/scan/repo-scans${repoUrl ? `?repoUrl=${encodeURIComponent(repoUrl)}` : ''}`
    ),

  getAiStatus: () =>
    request<{ available: boolean; model: string; error?: string }>('/api/scan/ai-status'),

  revalidateWithAi: (scanId: string) =>
    request<{ message: string; scan: ScanItem }>(`/api/scan/${scanId}/ai-revalidate`, {
      method: 'POST',
    }),

  generateFix: (scanId: string, findingId: string) =>
    request<{ message: string; proposal: SecurityFixProposal }>(
      `/api/scan/${scanId}/findings/${findingId}/generate-fix`,
      { method: 'POST' }
    ),

  createPr: (scanId: string, findingId: string, payload: CreatePrPayload) =>
    request<{ message: string; result: CreatePrResult }>(
      `/api/scan/${scanId}/findings/${findingId}/create-pr`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      }
    ),

  mergePr: (scanId: string, pullNumber: number) =>
    request<{ merged: boolean; message: string; sha: string }>(`/api/scan/${scanId}/merge-pr`, {
      method: 'POST',
      body: JSON.stringify({ pullNumber }),
    }),
}

export const githubApi = {
  getStatus: () =>
    request<{ connected: boolean; username: string | null; avatarUrl: string | null; warning?: string }>(
      '/api/github/status'
    ),

  getOAuthUrl: () =>
    request<{ configured: boolean; url?: string; clientId?: string; message?: string }>('/api/github/oauth/url'),

  handleOAuthCallback: (code: string) =>
    request<{ message: string; connected: boolean; username: string; avatarUrl: string }>(
      '/api/github/oauth/callback',
      {
        method: 'POST',
        body: JSON.stringify({ code }),
      }
    ),

  connect: (token: string) =>
    request<{ message: string; connected: boolean; username: string; avatarUrl: string }>('/api/github/connect', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),

  disconnect: () =>
    request<{ message: string; connected: boolean }>('/api/github/disconnect', {
      method: 'DELETE',
    }),
}

export interface SecurityFixProposal {
  findingId: string
  filePath: string
  targetBranch: string
  suggestedBranch: string
  searchSnippet: string
  replacementSnippet: string
  originalContext: string
  fixedContext: string
  explanation: string
  prTitle: string
  prDescription: string
  commitMessage: string
  canCreatePr: boolean
  repoOwner?: string
  repoName?: string
}

export interface CreatePrPayload {
  githubToken?: string
  targetBranch: string
  branchName: string
  filePath: string
  searchSnippet: string
  replacementSnippet: string
  commitMessage: string
  prTitle: string
  prDescription: string
}

export interface CreatePrResult {
  prUrl: string
  prNumber: number
  branch: string
  isFork: boolean
  state: string
  message: string
}

