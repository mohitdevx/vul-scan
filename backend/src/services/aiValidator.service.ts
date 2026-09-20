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
      temperature: 0.1,
      format: 'json',
      numPredict: 2048,
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
 * Ground-truth signature registries
 * Used to verify if a sanitizer or type cast ACTUALLY exists in the code
 * preventing 1.5B models from hallucinating non-existent sanitizers.
 */
const KNOWN_SANITIZER_KEYWORDS = [
  'dompurify',
  'sanitizehtml',
  'validator.escape',
  'escapehtml',
  'encodeuricomponent',
  'xssfilters',
  'he.encode',
  'securefilters',
  'striptags',
  'xss(',
]

const KNOWN_NUMERIC_CAST_KEYWORDS = [
  'parseint',
  'parsefloat',
  'number(',
  'math.floor',
  'math.round',
  'math.ceil',
  'math.abs',
  'boolean(',
]

export function inspectGroundTruthSafety(code: string): {
  hasSanitizer: boolean
  sanitizerMatched?: string
  hasNumberCast: boolean
  numberCastMatched?: string
} {
  const lower = code.toLowerCase()
  const sanitizer = KNOWN_SANITIZER_KEYWORDS.find(kw => lower.includes(kw))
  const numberCast = KNOWN_NUMERIC_CAST_KEYWORDS.find(kw => lower.includes(kw))
  return {
    hasSanitizer: Boolean(sanitizer),
    sanitizerMatched: sanitizer,
    hasNumberCast: Boolean(numberCast),
    numberCastMatched: numberCast,
  }
}

/**
 * Extracts focused contextual code slice around the finding line
 * Includes top-level import statements to detect sanitizers (DOMPurify, validator, etc.)
 */
export function extractCodeContext(fileContent: string, line: number, windowRadius = 18): string {
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
    const prefix = i + 1 === line ? `>>> L${i + 1} [FLAGGED SINK]: ` : `    L${i + 1}: `
    contextLines.push(prefix + allLines[i])
  }

  let result = ''
  if (importLines.length > 0 && start > 25) {
    result += `// --- File Imports ---\n${importLines.join('\n')}\n\n// --- Function / Local Context ---\n`
  }
  result += contextLines.join('\n')
  return result
}

/**
 * Validates a single AST finding with Grounded Hybrid Verification (AST Ground Truth + Qwen 2.5 Coder 1.5B)
 */
export async function validateFindingWithAi(
  finding: Finding,
  fileContent: string
): Promise<AiTriageResult> {
  const modelName = config.aiModel
  const now = new Date().toISOString()

  try {
    const client = getOllamaClient()
    const contextCode = extractCodeContext(fileContent, finding.line, 18)
    const groundTruth = inspectGroundTruthSafety(fileContent)

    const hasSanitizerOrCast = groundTruth.hasSanitizer || groundTruth.hasNumberCast
    const sanitizerContext = hasSanitizerOrCast
      ? `A potential sanitizer, encoder, or type conversion mechanism was detected in this file (${
          groundTruth.sanitizerMatched || groundTruth.numberCastMatched
        }). Verify if user input reaching sink '${finding.sink}' actually passes through it.`
      : `Static analysis confirmed NO sanitizer (such as DOMPurify, validator, or escapeHtml) and NO safe typecasting protects this sink.`

    const systemPrompt = `You are a Principal Application Security Auditor conducting a source code security assessment.

Analyze the flagged AST finding and the surrounding code context.
- Flagged Sink: '${finding.sink}'
- Rule: ${finding.ruleName} (${finding.ruleId}, ${finding.cwe})
- Context: ${sanitizerContext}

At the very top of your response, output these two metadata lines:
[VERDICT]: CONFIRMED_VULNERABILITY or FALSE_POSITIVE
[CONFIDENCE]: <integer 0-100>

Then, provide a comprehensive, elite security advisory in Markdown.
Naturally include:
1. In-depth technical breakdown of the data flow from source to the dangerous sink '${finding.sink}', explaining root cause in business logic and why it is an active vulnerability or false positive.
2. Real-world security impact & exploitation scenario (e.g. session token theft, DOM hijacking, blast radius).
3. A clean "Suggested Fix" with production-ready, syntax-highlighted code blocks (\`\`\`javascript or \`\`\`typescript) demonstrating the hardened implementation using best practices (such as DOMPurify.sanitize, textContent, or parameterized queries).`

    const userPrompt = `Finding: ${finding.ruleName} (${finding.ruleId})
File: ${finding.filePath}:${finding.line}
Flagged Sink: ${finding.sink}

Surrounding Code Context:
\`\`\`javascript
${contextCode}
\`\`\`

Perform a comprehensive security audit of this finding. Output your verdict and full markdown analysis.`

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 40000)

    const res = await fetch(`${config.ollamaBaseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: modelName,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        stream: false,
        options: {
          temperature: 0.1,
          num_predict: 2048,
        },
      }),
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!res.ok) {
      throw new Error(`Ollama HTTP ${res.status}: ${res.statusText}`)
    }

    const data = (await res.json()) as { message?: { content?: string } }
    const rawContent = data.message?.content || ''

    if (!rawContent) {
      throw new Error('Empty response from Ollama model')
    }

    // Extract verdict & confidence from metadata tags
    const verdictMatch = rawContent.match(/\[VERDICT\]:\s*(CONFIRMED_VULNERABILITY|FALSE_POSITIVE)/i)
    const confMatch = rawContent.match(/\[CONFIDENCE\]:\s*(\d+)/i)

    let isFalsePositive = false
    let verdict: AiVerdict = 'CONFIRMED_VULNERABILITY'

    if (verdictMatch) {
      const v = verdictMatch[1].toUpperCase()
      if (v === 'FALSE_POSITIVE') {
        isFalsePositive = true
        verdict = 'FALSE_POSITIVE'
      }
    } else if (rawContent.toLowerCase().includes('false positive') && !rawContent.toLowerCase().includes('not a false positive')) {
      isFalsePositive = true
      verdict = 'FALSE_POSITIVE'
    }

    // Guardrail: if ground truth confirmed NO sanitizer exists, don't allow false positive unless explicitly static
    if (!hasSanitizerOrCast && isFalsePositive && !rawContent.toLowerCase().includes('static') && !rawContent.toLowerCase().includes('hardcoded')) {
      isFalsePositive = false
      verdict = 'CONFIRMED_VULNERABILITY'
    }

    const confidence = confMatch ? Math.min(100, Math.max(50, parseInt(confMatch[1], 10))) : 95

    // Clean metadata tags from the markdown content
    const cleanAnalysis = rawContent
      .replace(/\[VERDICT\]:[^\n]*\n?/i, '')
      .replace(/\[CONFIDENCE\]:[^\n]*\n?/i, '')
      .trim()

    return {
      verdict,
      confidence,
      isFalsePositive,
      analysis: cleanAnalysis,
      reason: cleanAnalysis,
      remediation: 'Refer to the detailed security advisory above for the suggested fix and code.',
      model: modelName,
      sanitizerDetected: groundTruth.hasSanitizer,
      safeCastDetected: groundTruth.hasNumberCast,
      evaluatedAt: now,
    }
  } catch (err: any) {
    logger.warn(`[AiValidator] Error during AI verification for ${finding.id}: ${err.message}`)
    return {
      verdict: 'CONFIRMED_VULNERABILITY',
      confidence: 70,
      isFalsePositive: false,
      analysis: `### Security Finding\nDeterministic AST analysis identified dynamic taint flow reaching dangerous sink \`${finding.sink}\` at \`${finding.filePath}:${finding.line}\` without contextual sanitization or safe type conversion.`,
      reason: `Deterministic AST analysis identified dynamic taint flow reaching dangerous sink '${finding.sink}' at ${finding.filePath}:${finding.line}. Flagged for security review.`,
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
