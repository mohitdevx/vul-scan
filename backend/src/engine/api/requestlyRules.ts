import type { DiscoveredEndpoint } from './types.js'

export type RequestlyRuleType =
  | 'modify_headers'
  | 'modify_request'
  | 'modify_response'
  | 'redirect_request'
  | 'delay_request'

export interface RequestlyHeader {
  header: string
  value: string
  type: 'Request' | 'Response'
  operation: 'Set' | 'Remove'
}

export interface RequestlyRule {
  id: string
  name: string
  description: string
  ruleType: RequestlyRuleType
  status: 'Active' | 'Inactive'
  urlCondition: {
    operator: 'Equals' | 'Contains' | 'Matches (Regex)' | 'Wildcard'
    value: string
  }
  methodCondition?: string
  headers?: RequestlyHeader[]
  requestBodyMutation?: {
    type: 'JSON' | 'Raw'
    value: string
  }
  responseMock?: {
    statusCode: number
    responseBody: string
    headers?: Record<string, string>
  }
  delayMs?: number
  owaspCategory?: string
}

export interface RequestlyRuleGroup {
  name: string
  description: string
  rules: RequestlyRule[]
  generatedAt: string
  targetEndpointsCount: number
}

export function generateRequestlyRuleSuite(
  endpoints: DiscoveredEndpoint[],
  baseUrlOrOptions: string | { baseUrl?: string; ruleGroupName?: string } = 'http://localhost:3000',
  options?: { ruleGroupName?: string }
): RequestlyRuleGroup {
  let baseUrl = 'http://localhost:3000'
  let ruleGroupName = 'VulScan OWASP API Security Test Suite'

  if (typeof baseUrlOrOptions === 'string') {
    baseUrl = baseUrlOrOptions
    if (options?.ruleGroupName) {
      ruleGroupName = options.ruleGroupName
    }
  } else if (typeof baseUrlOrOptions === 'object' && baseUrlOrOptions !== null) {
    if (baseUrlOrOptions.baseUrl) baseUrl = baseUrlOrOptions.baseUrl
    if (baseUrlOrOptions.ruleGroupName) ruleGroupName = baseUrlOrOptions.ruleGroupName
  }

  const rules: RequestlyRule[] = []
  let ruleId = 1

  for (const ep of endpoints) {
    const urlPattern = `${baseUrl}${ep.path.replace(/:([a-zA-Z0-9_]+)/g, '*')}`

    // 1. BOLA / IDOR Authorization Bypass Test Rule
    if (ep.path.includes(':')) {
      rules.push({
        id: `rq-rule-${ruleId++}`,
        name: `[API1 BOLA Test] ${ep.method} ${ep.path}`,
        description: `Tests Object Level Authorization by swapping dynamic IDs on ${ep.path}`,
        ruleType: 'modify_request',
        status: 'Active',
        urlCondition: {
          operator: 'Wildcard',
          value: urlPattern,
        },
        methodCondition: ep.method,
        requestBodyMutation: {
          type: 'JSON',
          value: JSON.stringify({ userId: 'attacker_user_999', targetId: 'victim_resource_001' }, null, 2),
        },
        owaspCategory: 'API1:2023 - Broken Object Level Authorization',
      })
    }

    // 2. Broken Authentication / Token Tampering Test Rule
    if (ep.authRequired) {
      rules.push({
        id: `rq-rule-${ruleId++}`,
        name: `[API2 Auth Bypass Test] ${ep.method} ${ep.path}`,
        description: `Strips Authorization headers to verify server correctly returns 401/403`,
        ruleType: 'modify_headers',
        status: 'Active',
        urlCondition: {
          operator: 'Wildcard',
          value: urlPattern,
        },
        methodCondition: ep.method,
        headers: [
          { header: 'Authorization', value: '', type: 'Request', operation: 'Remove' },
          { header: 'X-Forwarded-For', value: '127.0.0.1', type: 'Request', operation: 'Set' },
        ],
        owaspCategory: 'API2:2023 - Broken Authentication',
      })
    }

    // 3. Mass Assignment / Excess Property Injection Rule
    if (ep.method === 'POST' || ep.method === 'PUT' || ep.method === 'PATCH') {
      rules.push({
        id: `rq-rule-${ruleId++}`,
        name: `[API3 Mass Assignment Test] ${ep.method} ${ep.path}`,
        description: `Injects elevated role and admin privileges into JSON request payload`,
        ruleType: 'modify_request',
        status: 'Active',
        urlCondition: {
          operator: 'Wildcard',
          value: urlPattern,
        },
        methodCondition: ep.method,
        requestBodyMutation: {
          type: 'JSON',
          value: JSON.stringify({ role: 'admin', isAdmin: true, verified: true }, null, 2),
        },
        owaspCategory: 'API3:2023 - Broken Object Property Level Authorization',
      })
    }

    // 4. Rate Limiting & Concurrency Throttling Test Rule
    rules.push({
      id: `rq-rule-${ruleId++}`,
      name: `[API4 Concurrency Simulation] ${ep.method} ${ep.path}`,
      description: `Injects artificial 350ms delay to test race conditions and concurrency resilience`,
      ruleType: 'delay_request',
      status: 'Inactive',
      urlCondition: {
        operator: 'Wildcard',
        value: urlPattern,
      },
      methodCondition: ep.method,
      delayMs: 350,
      owaspCategory: 'API4:2023 - Unrestricted Resource Consumption',
    })
  }

  return {
    name: `VulnScan API Security Test Suite (${endpoints.length} Endpoints)`,
    description: `Auto-generated Requestly rules for testing OWASP API Top 10 vulnerabilities against discovered backend routes.`,
    rules,
    generatedAt: new Date().toISOString(),
    targetEndpointsCount: endpoints.length,
  }
}
