import { logger } from '../../utils/logger.js'
import { sendAiChatCompletion } from '../../services/aiClient.js'
import type { DiscoveredEndpoint } from './types.js'

export interface ApiVulnerabilityFinding {
  id: string
  endpointId: string
  method: string
  path: string
  filePath: string
  line: number
  category: string
  cwe: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  title: string
  description: string
  riskImpact: string
  remediationGuidance: string
  suggestedPatch?: {
    searchSnippet: string
    replacementSnippet: string
    explanation: string
  }
}

export interface ApiAuditResult {
  findings: ApiVulnerabilityFinding[]
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  scannedEndpointsCount: number
  owaspDistribution: Record<string, number>
}

/**
 * Parses LLM JSON output robustly
 */
function parseLlmAuditJson(rawText: string): any {
  let cleaned = rawText.trim()
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)
  if (codeBlockMatch && codeBlockMatch[1]) {
    cleaned = codeBlockMatch[1].trim()
  }

  const firstBracket = cleaned.indexOf('[')
  const lastBracket = cleaned.lastIndexOf(']')
  if (firstBracket !== -1 && lastBracket !== -1 && lastBracket > firstBracket) {
    cleaned = cleaned.substring(firstBracket, lastBracket + 1)
  }

  try {
    return JSON.parse(cleaned)
  } catch {
    const firstBrace = cleaned.indexOf('{')
    const lastBrace = cleaned.lastIndexOf('}')
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      return [JSON.parse(cleaned.substring(firstBrace, lastBrace + 1))]
    }
    return []
  }
}

/**
 * Deterministic semantic check for API vulnerabilities
 */
export function runDeterministicApiAudit(endpoint: DiscoveredEndpoint): ApiVulnerabilityFinding[] {
  const findings: ApiVulnerabilityFinding[] = []
  const scopeLower = endpoint.enclosingScopeCode.toLowerCase()

  // 1. Check for BOLA / IDOR: Path param :id accessed without tenant / userId check
  if (endpoint.path.includes(':') && (endpoint.method === 'GET' || endpoint.method === 'PUT' || endpoint.method === 'DELETE')) {
    const hasOwnershipCheck =
      scopeLower.includes('userid') ||
      scopeLower.includes('owner') ||
      scopeLower.includes('req.user.id') ||
      scopeLower.includes('accountid')

    if (!hasOwnershipCheck && !endpoint.path.includes('/public')) {
      findings.push({
        id: `API-BOLA-${endpoint.id}`,
        endpointId: endpoint.id,
        method: endpoint.method,
        path: endpoint.path,
        filePath: endpoint.filePath,
        line: endpoint.line,
        category: 'API1:2023 - Broken Object Level Authorization (BOLA)',
        cwe: 'CWE-284',
        severity: 'HIGH',
        title: `Broken Object Level Authorization on ${endpoint.method} ${endpoint.path}`,
        description: `The endpoint accesses record identifiers from route parameters without validating that the requesting user owns the object.`,
        riskImpact: `An attacker can access, modify, or delete resources belonging to arbitrary users by incrementing or guessing the resource ID.`,
        remediationGuidance: `Enforce object-level ownership checks by including req.user.id in the query criteria or authorization filter.`,
        suggestedPatch: {
          searchSnippet: endpoint.codeSnippet,
          replacementSnippet: `// Verify requesting user ownership\nif (resource.userId !== req.user?.id) return res.status(403).json({ error: 'Unauthorized access' });`,
          explanation: 'Enforced explicit object-level ownership verification against the authenticated user session.',
        },
      })
    }
  }

  // 2. Check for Missing Authentication on Non-Public Sensitive Endpoints
  const isSensitive =
    endpoint.path.includes('admin') ||
    endpoint.path.includes('user') ||
    endpoint.path.includes('account') ||
    endpoint.path.includes('payment') ||
    endpoint.path.includes('setting')

  const isPublicAuthRoute =
    endpoint.path.includes('login') ||
    endpoint.path.includes('register') ||
    endpoint.path.includes('signup') ||
    endpoint.path.includes('forgot') ||
    endpoint.path.includes('health')

  if (isSensitive && !isPublicAuthRoute && !endpoint.authRequired) {
    findings.push({
      id: `API-AUTH-${endpoint.id}`,
      endpointId: endpoint.id,
      method: endpoint.method,
      path: endpoint.path,
      filePath: endpoint.filePath,
      line: endpoint.line,
      category: 'API2:2023 - Broken Authentication',
      cwe: 'CWE-306',
      severity: 'CRITICAL',
      title: `Unauthenticated Sensitive Endpoint: ${endpoint.method} ${endpoint.path}`,
      description: `Sensitive business logic endpoint is mounted without authentication middleware or guard.`,
      riskImpact: `Unauthenticated external attackers can directly invoke privileged operations.`,
      remediationGuidance: `Attach standard JWT or session authentication middleware (e.g. verifyJwt / requireAuth) to this route handler.`,
      suggestedPatch: {
        searchSnippet: endpoint.codeSnippet,
        replacementSnippet: endpoint.codeSnippet.replace(
          /(router\.(?:get|post|put|delete|patch)\(['"][^'"]+['"])/,
          '$1, authenticate'
        ),
        explanation: 'Attached authenticate middleware to guard sensitive endpoint from unauthenticated access.',
      },
    })
  }

  // 3. Mass Assignment Check on Mutation Methods
  if (endpoint.method === 'POST' || endpoint.method === 'PUT' || endpoint.method === 'PATCH') {
    if (
      scopeLower.includes('.create(req.body)') ||
      scopeLower.includes('.update({ data: req.body') ||
      scopeLower.includes('.save(req.body)')
    ) {
      findings.push({
        id: `API-MASS-${endpoint.id}`,
        endpointId: endpoint.id,
        method: endpoint.method,
        path: endpoint.path,
        filePath: endpoint.filePath,
        line: endpoint.line,
        category: 'API3:2023 - Broken Object Property Level Authorization (Mass Assignment)',
        cwe: 'CWE-915',
        severity: 'HIGH',
        title: `Mass Assignment via Unfiltered req.body on ${endpoint.method} ${endpoint.path}`,
        description: `Unsanitized req.body is passed directly into persistent data mutation operations.`,
        riskImpact: `Attackers can overwrite sensitive model properties such as role, isAdmin, or passwordResetToken.`,
        remediationGuidance: `Validate and whitelist allowed properties using a strict schema (e.g. Zod or DTO projection).`,
      })
    }
  }

  return findings
}

/**
 * Runs deep AI logical security audit on discovered API endpoints
 */
export async function auditEndpointsWithAi(
  endpoints: DiscoveredEndpoint[]
): Promise<ApiAuditResult> {
  const allFindings: ApiVulnerabilityFinding[] = []

  for (const ep of endpoints) {
    // Run deterministic base checks
    const deterministicFindings = runDeterministicApiAudit(ep)
    allFindings.push(...deterministicFindings)

    // Run AI Logical Audit for deep business logic analysis
    try {
      const systemPrompt = `You are an elite API Security Architect specialized in OWASP API Security Top 10 (2023).
Analyze the provided backend API endpoint logic, parameters, and handler code for real business logic vulnerabilities:
- API1:2023 Broken Object Level Authorization (BOLA/IDOR)
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization (Mass Assignment & Excessive Data Exposure)
- API4:2023 Unrestricted Resource Consumption (Missing Rate Limiting, Unbounded Pagination)
- API5:2023 Broken Function Level Authorization (Privilege Escalation)
- API6:2023 Server-Side Request Forgery (SSRF)
- API7:2023 Security Misconfiguration
- API8:2023 Lack of Protection from Automated Threats
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs

Output ONLY valid JSON array matching this schema:
[
  {
    "category": "string (e.g. API1:2023 - Broken Object Level Authorization)",
    "cwe": "string (e.g. CWE-284)",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "title": "string",
    "description": "string",
    "riskImpact": "string",
    "remediationGuidance": "string",
    "suggestedPatch": {
      "searchSnippet": "string",
      "replacementSnippet": "string",
      "explanation": "string"
    }
  }
]
If the endpoint is completely secure and follows best practices, return [].`

      const userPrompt = `Endpoint: ${ep.method} ${ep.path}
Framework: ${ep.framework}
File: ${ep.filePath}:${ep.line}
Auth Required: ${ep.authRequired ? 'Yes' : 'No'}
Parameters: ${JSON.stringify(ep.parameters)}

Handler Code Context:
\`\`\`javascript
${ep.enclosingScopeCode}
\`\`\`

Perform the logical API security audit.`

      const rawResponse = await sendAiChatCompletion({
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.1,
        maxTokens: 1024,
        jsonMode: true,
        timeoutMs: 25000,
      })

      const aiFindings = parseLlmAuditJson(rawResponse)
      if (Array.isArray(aiFindings)) {
        for (const f of aiFindings) {
          if (f.category && f.severity && f.title) {
            allFindings.push({
              id: `API-AI-${ep.id}-${allFindings.length + 1}`,
              endpointId: ep.id,
              method: ep.method,
              path: ep.path,
              filePath: ep.filePath,
              line: ep.line,
              category: f.category,
              cwe: f.cwe || 'CWE-284',
              severity: f.severity,
              title: f.title,
              description: f.description || '',
              riskImpact: f.riskImpact || '',
              remediationGuidance: f.remediationGuidance || '',
              suggestedPatch: f.suggestedPatch,
            })
          }
        }
      }
    } catch (err: any) {
      logger.debug(`[ApiAuditor] AI audit skipped for ${ep.path}: ${err.message}`)
    }
  }

  // Deduplicate findings by title and endpointId
  const uniqueFindings: ApiVulnerabilityFinding[] = []
  const seenKeys = new Set<string>()

  for (const f of allFindings) {
    const key = `${f.endpointId}:${f.title}`
    if (!seenKeys.has(key)) {
      seenKeys.add(key)
      uniqueFindings.push(f)
    }
  }

  const owaspDistribution: Record<string, number> = {}
  let criticalCount = 0
  let highCount = 0
  let mediumCount = 0
  let lowCount = 0

  for (const f of uniqueFindings) {
    const cat = f.category.split(' - ')[0] || f.category
    owaspDistribution[cat] = (owaspDistribution[cat] || 0) + 1

    if (f.severity === 'CRITICAL') criticalCount++
    else if (f.severity === 'HIGH') highCount++
    else if (f.severity === 'MEDIUM') mediumCount++
    else if (f.severity === 'LOW') lowCount++
  }

  return {
    findings: uniqueFindings,
    totalFindings: uniqueFindings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    scannedEndpointsCount: endpoints.length,
    owaspDistribution,
  }
}

export async function auditDiscoveredEndpoints(
  endpoints: DiscoveredEndpoint[],
  options?: { aiAnalysis?: boolean }
): Promise<{
  findings: ApiVulnerabilityFinding[]
  summary: {
    totalFindings: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
    categories: Record<string, number>
  }
}> {
  const result = await auditEndpointsWithAi(endpoints)
  return {
    findings: result.findings,
    summary: {
      totalFindings: result.totalFindings,
      critical: result.criticalCount,
      high: result.highCount,
      medium: result.mediumCount,
      low: result.lowCount,
      info: 0,
      categories: result.owaspDistribution,
    },
  }
}
