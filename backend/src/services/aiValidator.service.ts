import { ChatOllama } from '@langchain/ollama'
import { config } from '../config/env.js'
import { logger } from '../utils/logger.js'
import type { Finding, AiTriageResult, AiVerdict } from '../engine/types.js'

let ollamaClient: ChatOllama | null = null

function getOllamaClient(): ChatOllama {
  if (!ollamaClient) {
    ollamaClient = new ChatOllama({
      model: config.aiModel,
      baseUrl: config.ollamaBaseUrl,
      temperature: 0,
      format: 'json',
    })
  }
  return ollamaClient
}

/**
 * Check if the Ollama local AI server is accessible
 */
export async function checkAiHealth(): Promise<{ available: boolean; model: string; error?: string }> {
  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 2000)

    const res = await fetch(`${config.ollamaBaseUrl}/api/tags`, {
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!res.ok) {
      return { available: false, model: config.aiModel, error: `HTTP ${res.status}` }
    }

    const data = (await res.json()) as { models?: Array<{ name: string }> }
    const models = data.models || []
    const hasModel = models.some(m => m.name === config.aiModel || m.name.startsWith(config.aiModel))

    return {
      available: true,
      model: config.aiModel,
      error: hasModel ? undefined : `Model '${config.aiModel}' not found in local Ollama repository.`,
    }
  } catch (err: any) {
    return {
      available: false,
      model: config.aiModel,
      error: err.message || 'Cannot connect to Ollama server',
    }
  }
}

/**
 * Extracts focused contextual code slice around the finding line
 * Includes top-level import statements to detect sanitizers (DOMPurify, validator, etc.)
 */
export function extractCodeContext(fileContent: string, line: number, windowRadius = 15): string {
  const allLines = fileContent.split('\n')
  const total = allLines.length

  // Collect top imports (first 25 lines) to capture sanitizer declarations
  const importLines: string[] = []
  for (let i = 0; i < Math.min(25, total); i++) {
    const text = allLines[i]
    if (/^\s*(import|const\s+.*=\s*require\(|let\s+.*=\s*require\()/.test(text)) {
      importLines.push(`L${i + 1}: ${text}`)
    }
  }

  // Calculate slice around the finding line
  const start = Math.max(0, line - 1 - windowRadius)
  const end = Math.min(total, line + windowRadius)
  const contextLines: string[] = []

  for (let i = start; i < end; i++) {
    const prefix = i + 1 === line ? `>>> L${i + 1} [SINK]: ` : `    L${i + 1}: `
    contextLines.push(prefix + allLines[i])
  }

  let result = ''
  if (importLines.length > 0 && start > 25) {
    result += `// --- Relevant File Imports ---\n${importLines.join('\n')}\n\n// --- Code Context around Finding ---\n`
  }
  result += contextLines.join('\n')
  return result
}

const AI_SAST_SYSTEM_PROMPT = `You are a high-precision Static Application Security Testing (SAST) AI Auditor.
Your job is to validate whether an AST scanner finding for Cross-Site Scripting (XSS) is a real vulnerability (TRUE_POSITIVE) or a SAFE implementation / FALSE POSITIVE.

AST scanners flag patterns purely based on syntax and often cause false positives.
You must read the surrounding code, imports, and business logic.

DETERMINATION RULES:
A finding is SAFE (false positive) if:
1. Sanitization exists: The variable is cleaned via DOMPurify.sanitize(), sanitizeHtml(), validator.escape(), encodeURIComponent(), or a custom sanitizer before reaching the sink.
2. Safe Type Cast: The variable is explicitly converted to a number using parseInt(), parseFloat(), Number(), Math.*, or boolean. Numbers and booleans cannot execute script payloads.
3. Safe Framework Rendering: The variable is rendered inside standard React JSX children (e.g. <div>{data}</div>) or Vue template interpolation, which auto-escapes HTML by default.
4. Static / Hardcoded Value: The variable comes strictly from a safe internal constant, literal, or non-user-controllable source.

A finding is VULNERABLE (true positive) if:
1. Untrusted user input (req.query, req.body, req.params, location.search, location.hash, cookie, form data) flows directly into dangerous sinks (innerHTML, outerHTML, eval, document.write, dangerouslySetInnerHTML) without prior sanitization or numeric conversion.
2. Reflected/Stored HTML: Untrusted input is concatenated into an HTML response body (res.send, res.write) without HTML entity escaping.

Respond ONLY with this exact JSON schema:
{
  "sanitizedOrSafe": boolean,
  "vulnerable": boolean,
  "hasSanitizer": boolean,
  "hasSafeTypeCast": boolean,
  "confidence": number,
  "reason": "Detailed explanation of why this code is safe or vulnerable based on the business logic",
  "remediation": "Clear remediation advice if vulnerable, or explanation of why it is already safe"
}`

/**
 * Validates a single AST finding with Qwen 2.5 Coder 1.5B
 */
export async function validateFindingWithAi(
  finding: Finding,
  fileContent: string
): Promise<AiTriageResult> {
  const modelName = config.aiModel
  const now = new Date().toISOString()

  try {
    const client = getOllamaClient()
    const contextCode = extractCodeContext(fileContent, finding.line, 16)

    const userPrompt = `Rule: ${finding.ruleName} (${finding.ruleId} / ${finding.cwe})
File: ${finding.filePath}
Line: ${finding.line}
Sink Detected by AST: ${finding.sink}

Code Context:
\`\`\`javascript
${contextCode}
\`\`\`

Analyze the code context above. Is this a confirmed vulnerability or a false positive? Output strictly JSON.`

    // Call Ollama with timeout protection
    const response = await Promise.race([
      client.invoke([
        ['system', AI_SAST_SYSTEM_PROMPT],
        ['user', userPrompt],
      ]),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI validation request timed out (15s)')), 15000)
      ),
    ])

    const text = typeof response.content === 'string' ? response.content : JSON.stringify(response.content)
    let parsed: any = null

    try {
      // Find JSON block if surrounded by markdown
      const jsonMatch = text.match(/\{[\s\S]*\}/)
      parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : JSON.parse(text)
    } catch (parseErr) {
      logger.warn(`[AiValidator] Failed to parse AI JSON response for ${finding.id}: ${text}`)
    }

    if (parsed) {
      const sanitizedOrSafe = Boolean(parsed.sanitizedOrSafe || parsed.hasSanitizer || parsed.hasSafeTypeCast)
      const vulnerable = Boolean(parsed.vulnerable) && !sanitizedOrSafe

      let verdict: AiVerdict = 'SUSPICIOUS'
      let isFalsePositive = false

      if (sanitizedOrSafe) {
        verdict = 'FALSE_POSITIVE'
        isFalsePositive = true
      } else if (vulnerable) {
        verdict = 'CONFIRMED_VULNERABILITY'
        isFalsePositive = false
      } else {
        verdict = 'SUSPICIOUS'
        isFalsePositive = false
      }

      const confidence = typeof parsed.confidence === 'number'
        ? (parsed.confidence > 1 ? parsed.confidence : Math.round(parsed.confidence * 100))
        : 90

      return {
        verdict,
        confidence,
        isFalsePositive,
        reason: parsed.reason || 'AI evaluated the business logic and flow.',
        remediation: parsed.remediation || finding.remediation,
        model: modelName,
        sanitizerDetected: Boolean(parsed.hasSanitizer),
        safeCastDetected: Boolean(parsed.hasSafeTypeCast),
        evaluatedAt: now,
      }
    }

    // Fallback if parsing failed
    return {
      verdict: 'SUSPICIOUS',
      confidence: 50,
      isFalsePositive: false,
      reason: 'AI model did not return structured verification. Retaining finding for manual review.',
      remediation: finding.remediation,
      model: modelName,
      evaluatedAt: now,
    }
  } catch (err: any) {
    logger.warn(`[AiValidator] Error during AI verification for ${finding.id}: ${err.message}`)
    return {
      verdict: 'SUSPICIOUS',
      confidence: 40,
      isFalsePositive: false,
      reason: `AI validation could not be completed (${err.message}). Retaining finding for manual review.`,
      remediation: finding.remediation,
      model: modelName,
      evaluatedAt: now,
    }
  }
}

/**
 * Validates a list of findings with controlled concurrency
 */
export async function validateFindingsBatch(
  findings: Finding[],
  filesMap: Map<string, string>,
  concurrency = 2
): Promise<Finding[]> {
  if (!config.aiValidationEnabled || findings.length === 0) {
    return findings
  }

  // Check health first to avoid waiting through timeouts if Ollama is down
  const health = await checkAiHealth()
  if (!health.available) {
    logger.warn(`[AiValidator] Ollama server is not accessible at ${config.ollamaBaseUrl}: ${health.error}. Skipping AI validation.`)
    return findings
  }

  logger.info(`[AiValidator] Starting AI validation for ${findings.length} findings using model '${config.aiModel}' (concurrency: ${concurrency})`)

  const enrichedFindings: Finding[] = [...findings]
  const queue = findings.map((finding, index) => ({ finding, index }))

  const workers = Array.from({ length: concurrency }, async () => {
    while (queue.length > 0) {
      const item = queue.shift()
      if (!item) break

      const { finding, index } = item
      const fileContent = filesMap.get(finding.filePath) || ''

      if (!fileContent) {
        logger.debug(`[AiValidator] No file content available for ${finding.filePath}, skipping AI triage`)
        continue
      }

      const triage = await validateFindingWithAi(finding, fileContent)
      enrichedFindings[index] = {
        ...finding,
        aiAnalysis: triage,
      }
      logger.info(
        `[AiValidator] Validated [${finding.id}] -> ${triage.verdict} (${triage.confidence}% confidence) - False Positive: ${triage.isFalsePositive}`
      )
    }
  })

  await Promise.all(workers)
  return enrichedFindings
}
