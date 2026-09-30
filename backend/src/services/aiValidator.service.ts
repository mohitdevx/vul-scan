import { config } from '../config/env.js'
import { logger } from '../utils/logger.js'
import { sendAiChatCompletion, checkAiHealth } from './aiClient.js'
import type { Finding, AiTriageResult, AiVerdict } from '../engine/types.js'

export { checkAiHealth }

/**
 * Ground-truth signature registries
 * Used to verify if a sanitizer or type cast ACTUALLY exists in the code context.
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
  'sqlstring',
  'mysql.escape',
  'escapeliteral',
  'escapeidentifier',
  'sqlescape',
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

const RELEVANT_IMPORT_REGEX = /(child_process|execa|shelljs|cross-spawn|ioredis|redis|pg|mysql|sqlite|prisma|knex|sequelize|mongoose|dompurify|validator|sanitize|escape|fs|http|express|fastify|koa)/i

/**
 * Extracts focused contextual code slice around the finding line
 * Captures relevant security/driver imports while skipping unrelated UI/CSS imports
 */
export function extractCodeContext(fileContent: string, line: number, windowRadius = 12): string {
  const allLines = fileContent.split('\n')
  const total = allLines.length

  // Collect only security/driver relevant imports from the top 30 lines
  const relevantImports: string[] = []
  for (let i = 0; i < Math.min(30, total); i++) {
    const text = allLines[i]
    if (
      /^\s*(import|const\s+.*=\s*require\(|let\s+.*=\s*require\(|var\s+.*=\s*require\()/.test(text) &&
      RELEVANT_IMPORT_REGEX.test(text)
    ) {
      relevantImports.push(`L${i + 1}: ${text}`)
    }
  }

  // Calculate slice around the candidate line
  const start = Math.max(0, line - 1 - windowRadius)
  const end = Math.min(total, line + windowRadius)
  const contextLines: string[] = []

  for (let i = start; i < end; i++) {
    const prefix = i + 1 === line ? `>>> L${i + 1} [CANDIDATE]: ` : `    L${i + 1}: `
    contextLines.push(prefix + allLines[i])
  }

  let result = ''
  if (relevantImports.length > 0 && start > 0) {
    result += `// --- Relevant Module Imports ---\n${relevantImports.join('\n')}\n\n// --- Function / Local Context ---\n`
  }
  result += contextLines.join('\n')
  return result
}

interface AiStructuredResponse {
  verdict: 'CONFIRMED_VULNERABILITY' | 'FALSE_POSITIVE'
  confidence: number
  sinkAnalysis: {
    technology: string
    isSinkApplicableToCwe: boolean
    sinkCapabilityExplanation: string
  }
  dataflowAnalysis: {
    isTainted: boolean
    isParameterizedOrSafe: boolean
    dataflowExplanation: string
  }
  technicalSummary: string
  securityImpact: string
  remediation: string
}

/**
 * Parses the raw AI response, supporting strict JSON as well as formatted markdown / fallback tags.
 */
function parseAiResponse(rawContent: string, finding: Finding): {
  verdict: AiVerdict
  confidence: number
  isFalsePositive: boolean
  technicalSummary: string
  securityImpact: string
  remediation: string
  analysis: string
} {
  // 1. Try JSON parsing
  try {
    const jsonMatch = rawContent.match(/\{[\s\S]*\}/)
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]) as Partial<AiStructuredResponse>
      if (parsed.verdict === 'CONFIRMED_VULNERABILITY' || parsed.verdict === 'FALSE_POSITIVE') {
        const isFp = parsed.verdict === 'FALSE_POSITIVE'
        const conf = typeof parsed.confidence === 'number' ? Math.min(100, Math.max(10, parsed.confidence)) : 90
        const techSummary = parsed.technicalSummary || parsed.sinkAnalysis?.sinkCapabilityExplanation || ''
        const impact = isFp ? 'None' : parsed.securityImpact || 'Potential unauthorized access or execution.'
        const rem = isFp ? 'None required.' : parsed.remediation || finding.remediation

        // For False Positives, generate a sleek, minimal 2-line summary to prevent report bloat
        const formattedAnalysis = isFp
          ? `### False Positive Assessment\n**Verdict**: \`FALSE_POSITIVE\` (${conf}% confidence)\n\n**Reason**: ${techSummary || 'Pattern collision or benign internal abstraction without an active external attack vector.'}`
          : [
              `### Vulnerability Assessment`,
              `**Verdict**: \`${parsed.verdict}\` (${conf}% confidence)`,
              '',
              `#### Technical Breakdown`,
              techSummary,
              '',
              `#### Security Impact`,
              impact,
              '',
              `#### Remediation`,
              rem,
            ].join('\n')

        return {
          verdict: parsed.verdict,
          confidence: conf,
          isFalsePositive: isFp,
          technicalSummary: techSummary,
          securityImpact: impact,
          remediation: rem,
          analysis: formattedAnalysis,
        }
      }
    }
  } catch {
    // Continue to fallback parsing
  }

  // 2. Fallback: Parse markdown tags or explicit verdict keywords
  const verdictMatch = rawContent.match(/\[VERDICT\]:\s*(CONFIRMED_VULNERABILITY|FALSE_POSITIVE)/i)
  const confMatch = rawContent.match(/\[CONFIDENCE\]:\s*(\d+)/i)

  let isFalsePositive = false
  let verdict: AiVerdict = 'CONFIRMED_VULNERABILITY'

  if (verdictMatch) {
    if (verdictMatch[1].toUpperCase() === 'FALSE_POSITIVE') {
      isFalsePositive = true
      verdict = 'FALSE_POSITIVE'
    }
  } else {
    const lower = rawContent.toLowerCase()
    const fpKeywords = ['false positive', 'not a vulnerability', 'not vulnerable', 'inapplicable', 'safe from']
    const cvKeywords = ['confirmed vulnerability', 'active vulnerability', 'exploitable', 'critical vulnerability']

    const fpCount = fpKeywords.filter(kw => lower.includes(kw)).length
    const cvCount = cvKeywords.filter(kw => lower.includes(kw)).length

    if (fpCount > cvCount) {
      isFalsePositive = true
      verdict = 'FALSE_POSITIVE'
    }
  }

  const confidence = confMatch ? Math.min(100, Math.max(50, parseInt(confMatch[1], 10))) : 85
  const cleanAnalysis = rawContent
    .replace(/\[VERDICT\]:[^\n]*\n?/gi, '')
    .replace(/\[CONFIDENCE\]:[^\n]*\n?/gi, '')
    .trim()

  return {
    verdict,
    confidence,
    isFalsePositive,
    technicalSummary: isFalsePositive ? (cleanAnalysis.split('\n')[0] || 'Pattern mismatch.') : cleanAnalysis,
    securityImpact: isFalsePositive ? 'None' : 'Potential exploitability.',
    remediation: isFalsePositive ? 'None required.' : finding.remediation,
    analysis: isFalsePositive
      ? `### False Positive Assessment\n**Verdict**: \`FALSE_POSITIVE\` (${confidence}% confidence)\n\n**Reason**: ${cleanAnalysis.split('\n')[0] || 'Benign code context.'}`
      : cleanAnalysis,
  }
}

/**
 * Validates a single candidate finding using an Impartial Multi-Stage AI Logical Engine.
 */
export async function validateFindingWithAi(
  finding: Finding,
  fileContent: string
): Promise<AiTriageResult> {
  const modelName = config.aiModel
  const now = new Date().toISOString()

  try {
    const contextCode = extractCodeContext(fileContent, finding.line, 12)
    const groundTruth = inspectGroundTruthSafety(fileContent)

    const systemPrompt = `You are a Principal Application Security Verification Engine.
Impartially verify candidate SAST findings. Zero confirmation bias.

EVALUATION RULES:
1. Technology Check: Verify if sink actually interprets the reported CWE (e.g. Redis is key-value cache, NOT SQL CWE-89. Internal class/harness spawn without shell:true is NOT CMDi CWE-78).
2. Taint Check: Does untrusted input from external network reach the sink?
3. Format: Be extremely concise. For FALSE_POSITIVE, use 1 short sentence.

Output strict JSON:
{
  "verdict": "CONFIRMED_VULNERABILITY" | "FALSE_POSITIVE",
  "confidence": <integer 0-100>,
  "technicalSummary": "<1 concise sentence for False Positive; 2 sentences for Confirmed>",
  "securityImpact": "<'None' for False Positive; 1 sentence for Confirmed>",
  "remediation": "<'None required' for False Positive; exact 1-line code fix for Confirmed>"
}`

    const userPrompt = `Finding: ${finding.ruleName} (${finding.cwe}) at ${finding.filePath}:${finding.line}
Sink: ${finding.sink}

Code:
\`\`\`javascript
${contextCode}
\`\`\`
Return JSON triage assessment.`

    const rawContent = await sendAiChatCompletion({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
      maxTokens: 256,
      timeoutMs: 20000,
    })

    if (!rawContent) {
      throw new Error('Empty response from AI verification engine')
    }

    const parsedResult = parseAiResponse(rawContent, finding)

    return {
      verdict: parsedResult.verdict,
      confidence: parsedResult.confidence,
      isFalsePositive: parsedResult.isFalsePositive,
      analysis: parsedResult.analysis,
      reason: parsedResult.technicalSummary,
      dataFlow: parsedResult.analysis,
      securityImpact: parsedResult.securityImpact,
      remediation: parsedResult.remediation,
      model: modelName,
      sanitizerDetected: groundTruth.hasSanitizer,
      safeCastDetected: groundTruth.hasNumberCast,
      evaluatedAt: now,
    }
  } catch (err: any) {
    logger.warn(`[AiValidator] AI verification encountered an error for ${finding.id}: ${err.message}`)
    return {
      verdict: 'CONFIRMED_VULNERABILITY',
      confidence: 70,
      isFalsePositive: false,
      analysis: `### Candidate Finding\nStatic analysis flagged dynamic pattern at \`${finding.filePath}:${finding.line}\` for sink \`${finding.sink}\`. Manual security verification recommended.`,
      reason: `Static analysis flagged sink '${finding.sink}' at ${finding.filePath}:${finding.line}. Flagged for review.`,
      remediation: finding.remediation,
      model: modelName,
      evaluatedAt: now,
    }
  }
}

/**
 * Validates findings in batch with controlled concurrency and priority ordering
 */
export async function validateFindingsBatch(
  findings: Finding[],
  filesMap: Map<string, string>,
  concurrency = 2
): Promise<Finding[]> {
  if (!config.aiValidationEnabled || findings.length === 0) {
    return findings
  }

  // Check health first to avoid waiting through timeouts if AI endpoint is unreachable
  const health = await checkAiHealth()
  if (!health.available) {
    logger.warn(`[AiValidator] AI endpoint is not accessible at ${config.aiBaseUrl}: ${health.error}. Skipping AI validation.`)
    return findings
  }

  const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
  const indexed = findings.map((finding, index) => ({
    finding,
    index,
    score: severityRank[finding.severity] || 0,
  }))

  // Prioritize CRITICAL and HIGH severity findings
  indexed.sort((a, b) => b.score - a.score)

  // Cap automatic initial scan AI triage to top 10 findings
  const toValidate = indexed.slice(0, 10)

  logger.info(
    `[AiValidator] Starting AI validation for ${toValidate.length}/${findings.length} findings using model '${config.aiModel}'`
  )

  const enrichedFindings: Finding[] = [...findings]
  const queue = [...toValidate]

  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
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
