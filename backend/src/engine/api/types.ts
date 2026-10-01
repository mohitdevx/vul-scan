export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD' | 'ALL'

export interface ApiParameter {
  name: string
  in: 'path' | 'query' | 'header' | 'body'
  required: boolean
  type?: string
  description?: string
}

export interface DiscoveredEndpoint {
  id: string
  method: HttpMethod
  path: string
  filePath: string
  line: number
  framework: 'express' | 'fastify' | 'nestjs' | 'nextjs' | 'koa' | 'hono' | 'generic'
  handlerName?: string
  authRequired: boolean
  authMiddlewares: string[]
  parameters: ApiParameter[]
  requestBodySchema?: string
  responseSummary?: string
  codeSnippet: string
  enclosingScopeCode: string
}

export interface EndpointDiscoveryResult {
  endpoints: DiscoveredEndpoint[]
  totalEndpoints: number
  frameworksDetected: string[]
  filesAnalyzed: number
  summary: {
    authenticatedCount: number
    publicCount: number
    methodCounts: Record<HttpMethod, number>
  }
}

export interface ScanLogEntry {
  timestamp: string
  level: 'info' | 'warn' | 'success' | 'debug' | 'error'
  stage: 'discovery' | 'ast_analysis' | 'ai_logic' | 'requestly_mcp'
  message: string
  details?: Record<string, any>
}

export interface McpTransaction {
  id: string
  tool: string
  method: string
  requestPayload: Record<string, any>
  responsePayload: Record<string, any>
  status: 'SUCCESS' | 'SIMULATED' | 'ERROR'
  latencyMs: number
  timestamp: string
}
