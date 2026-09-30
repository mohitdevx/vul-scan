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

/**
 * Extracts focused contextual code slice around the finding line
 * Includes top-level import statements to capture module dependencies
 */
export function extractCodeContext(fileContent: string, line: number, windowRadius = 20): string {
  const allLines = fileContent.split('\n')
  const total = allLines.length

  // Collect top imports (first 30 lines) to capture framework / driver declarations
  const importLines: string[] = []
  for (let i = 0; i < Math.min(30, total); i++) {
    const text = allLines[i]
    if (/^\s*(import|const\s+.*=\s*require\(|let\s+.*=\s*require\(|var\s+.*=\s*require\()/.test(text)) {
      importLines.push(`L${i + 1}: ${text}`)
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
  if (importLines.length > 0 && start > 0) {
    result += `// --- Module Imports & Declarations ---\n${importLines.join('\n')}\n\n// --- Function / Local Context ---\n`
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
        const impact = parsed.securityImpact || (isFp ? 'No security impact (False Positive).' : 'Potential unauthorized data access or execution.')
        const rem = parsed.remediation || (isFp ? 'No code changes required.' : finding.remediation)

        const formattedAnalysis = [
          `### ${isFp ? 'False Positive Assessment' : 'Vulnerability Assessment'}`,
          `**Verdict**: \`${parsed.verdict}\` (Confidence: ${conf}%)`,
          '',
          `#### 1. Technology & Sink Context`,
          `- **Detected Technology**: ${parsed.sinkAnalysis?.technology || 'Identified via code context'}`,
          `- **CWE Applicability**: ${parsed.sinkAnalysis?.isSinkApplicableToCwe ? 'Applicable' : 'Inapplicable for this sink'}`,
          `- **Explanation**: ${parsed.sinkAnalysis?.sinkCapabilityExplanation || 'N/A'}`,
          '',
          `#### 2. Dataflow & Taint Evaluation`,
          `- **Tainted Input Reaches Sink**: ${parsed.dataflowAnalysis?.isTainted ? 'Yes' : 'No'}`,
          `- **Safe / Parameterized Execution**: ${parsed.dataflowAnalysis?.isParameterizedOrSafe ? 'Yes' : 'No'}`,
          `- **Details**: ${parsed.dataflowAnalysis?.dataflowExplanation || 'N/A'}`,
          '',
          `#### 3. Technical Summary`,
          techSummary,
          '',
          `#### 4. Security Impact`,
          impact,
          '',
          `#### 5. Recommended Action`,
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
    technicalSummary: cleanAnalysis,
    securityImpact: isFalsePositive ? 'No security impact.' : 'Potential exploitability.',
    remediation: isFalsePositive ? 'No remediation needed.' : finding.remediation,
    analysis: cleanAnalysis,
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
    const contextCode = extractCodeContext(fileContent, finding.line, 20)
    const groundTruth = inspectGroundTruthSafety(fileContent)

    const systemPrompt = `You are a Principal Application Security Verification Engine.
Your objective is to conduct an impartial, rigorous verification of candidate static analysis (SAST) findings.

### PRINCIPLES OF IMPARTIAL VERIFICATION:
1. **Zero Confirmation Bias**: Do NOT assume the finding is a vulnerability merely because an AST heuristic flagged it. Static analysis frequently triggers false positives due to pattern collisions.
2. **Technological & Semantic Grounding**:
   - Verify if the sink library/driver actually belongs to the vulnerability class.
   - For example:
     * Redis (\`ioredis\`, \`redis\`) is a key-value store using the binary-safe RESP protocol. Calling \`redisClient.get(key)\` is NOT SQL and CANNOT cause CWE-89 (SQL Injection).
     * Mongoose / MongoDB queries are NoSQL (CWE-943), not SQL (CWE-89).
     * Tagged templates in Prisma (\`prisma.$queryRaw\`...\`\`) or parameterized driver calls (\`client.query(sql, [params])\`) are cryptographically bound and immune to SQLi unless explicitly using unsafe/raw methods.
     * DOM sinks (\`innerHTML\`) in backend Node.js scripts or build tools that do not render in a web browser DOM are NOT exploitable CWE-79 XSS.
3. **Dataflow & Parameterization**:
   - Determine if dynamic untrusted user input is concatenated into an interpreter grammar, or if it is isolated safely via parameter bindings or safe type conversion (e.g. \`parseInt\`, \`Number\`).
4. **Feasibility of Exploitation**:
   - Can an attacker manipulate the grammar of an execution engine or extract unauthorized assets?

You MUST respond strictly with a valid JSON object matching this schema:
{
  "verdict": "CONFIRMED_VULNERABILITY" | "FALSE_POSITIVE",
  "confidence": <integer 0-100>,
  "sinkAnalysis": {
    "technology": "<Identified Library/Driver e.g. ioredis, pg, child_process, React>",
    "isSinkApplicableToCwe": <boolean>,
    "sinkCapabilityExplanation": "<Detailed explanation of why this sink can or cannot execute the reported CWE class>"
  },
  "dataflowAnalysis": {
    "isTainted": <boolean>,
    "isParameterizedOrSafe": <boolean>,
    "dataflowExplanation": "<Dataflow path and parameterization/sanitization evaluation>"
  },
  "technicalSummary": "<Technical explanation of why this is a true vulnerability or false positive>",
  "securityImpact": "<Exploitation blast radius if confirmed, or 'None' if false positive>",
  "remediation": "<Concrete, production-ready fix if confirmed, or 'None required' if false positive>"
}`

    const userPrompt = `Review Candidate Finding:
- Rule: ${finding.ruleName} (${finding.ruleId})
- Reported CWE: ${finding.cwe}
- Candidate Sink: ${finding.sink}
- Location: ${finding.filePath}:${finding.line}

Surrounding Code Context:
\`\`\`javascript
${contextCode}
\`\`\`

Evaluate this finding step-by-step and output your JSON verification assessment.`

    const rawContent = await sendAiChatCompletion({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
      maxTokens: 1024,
      timeoutMs: 25000,
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
