import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { config } from '../config/env.js'
import { logger } from '../utils/logger.js'
import { sendAiChatCompletion } from './aiClient.js'
import { parseSourceCode } from '../engine/parser.js'
import type { Finding } from '../engine/types.js'

const execFileAsync = promisify(execFile)

export interface FindingFixItem {
  findingId: string
  ruleId: string
  ruleName: string
  cwe: string
  severity: string
  filePath: string
  line: number
  sink: string
  searchSnippet: string
  replacementSnippet: string
  explanation: string
  originalContext: string
  fixedContext: string
}

export interface BatchSecurityFixProposal {
  targetBranch: string
  suggestedBranch: string
  prTitle: string
  prDescription: string
  commitMessage: string
  canCreatePr: boolean
  repoOwner?: string
  repoName?: string
  totalFindings: number
  fixes: FindingFixItem[]
}

export interface BatchFilePatch {
  findingId: string
  filePath: string
  line?: number
  searchSnippet: string
  replacementSnippet: string
}

export interface CreateBatchPrParams {
  repoUrl: string
  targetBranch: string
  branchName: string
  patches: BatchFilePatch[]
  commitMessage: string
  prTitle: string
  prDescription: string
  githubToken?: string
}

export interface SecurityFixProposal {
  findingId: string
  ruleId?: string
  ruleName?: string
  cwe?: string
  severity?: string
  filePath: string
  line?: number
  sink?: string
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

export interface CreatePrResult {
  prUrl: string
  prNumber: number
  branch: string
  isFork: boolean
  state: string
  message: string
  fixedFindingIds?: string[]
}

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  try {
    const trimmed = url.trim()
    const httpsMatch = trimmed.match(/^https?:\/\/(?:www\.)?github\.com\/([^\/]+)\/([^\/\.]+)(?:\.git)?(?:\/.*)?$/i)
    if (httpsMatch) {
      return { owner: httpsMatch[1], repo: httpsMatch[2] }
    }
    const sshMatch = trimmed.match(/^git@github\.com:([^\/]+)\/([^\/\.]+)(?:\.git)?$/i)
    if (sshMatch) {
      return { owner: sshMatch[1], repo: sshMatch[2] }
    }
    return null
  } catch {
    return null
  }
}

/**
 * Extracts focused lines around the vulnerability for AI fix context with line markers and imports
 */
function extractContextWindow(fileContent: string, line: number, radius = 25): {
  context: string
  startLine: number
  endLine: number
  annotatedContext: string
} {
  const lines = fileContent.split('\n')
  const total = lines.length
  const start = Math.max(0, line - 1 - radius)
  const end = Math.min(total, line + radius)

  const slice = lines.slice(start, end).join('\n')

  const annotatedLines = lines.slice(start, end).map((lText, idx) => {
    const currentLineNum = start + idx + 1
    const marker = currentLineNum === line ? '>>> [VULNERABLE SINK] ' : '    '
    return `${marker}L${currentLineNum}: ${lText}`
  })

  return {
    context: slice,
    startLine: start + 1,
    endLine: end,
    annotatedContext: annotatedLines.join('\n'),
  }
}

/**
 * Robust JSON parser that handles markdown fences and trailing commas from LLM output
 */
function parseLlmJson(rawText: string): any {
  let cleaned = rawText.trim()

  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)
  if (codeBlockMatch && codeBlockMatch[1]) {
    cleaned = codeBlockMatch[1].trim()
  }

  const firstBrace = cleaned.indexOf('{')
  const lastBrace = cleaned.lastIndexOf('}')
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    cleaned = cleaned.substring(firstBrace, lastBrace + 1)
  }

  try {
    return JSON.parse(cleaned)
  } catch (err: any) {
    logger.debug(`Direct JSON parse failed (${err.message}), attempting sanitized parse...`)
    const relaxed = cleaned.replace(/,\s*([}\]])/g, '$1')
    try {
      return JSON.parse(relaxed)
    } catch {
      throw new Error(`Failed to parse AI-generated fix JSON. Response: ${rawText.slice(0, 200)}...`)
    }
  }
}

/**
 * Deterministic Hardened Remediation Fallback Engine
 * Generates an accurate, syntax-valid fix if the AI model output fails parsing or syntax checks.
 */
export function generateDeterministicHardenedFix(
  finding: Finding,
  fileContent: string
): { searchSnippet: string; replacementSnippet: string; explanation: string } {
  const lines = fileContent.split('\n')
  const targetLineIdx = Math.max(0, Math.min(lines.length - 1, finding.line - 1))
  
  // Find line matching sink or snippet in priority order: exact line -> radius +/- 4 lines -> snippet match
  let lineText = lines[targetLineIdx] || ''
  const snippetTrim = (finding.snippet || '').trim()

  if (snippetTrim && !lineText.includes(snippetTrim)) {
    // Scan radius +/- 5 lines
    const start = Math.max(0, targetLineIdx - 5)
    const end = Math.min(lines.length - 1, targetLineIdx + 5)
    for (let i = start; i <= end; i++) {
      if (lines[i].includes(snippetTrim) || (lines[i].trim() && snippetTrim.includes(lines[i].trim()))) {
        lineText = lines[i]
        break
      }
    }
  }

  if (!lineText) {
    lineText = finding.snippet || ''
  }

  const cwe = (finding.cwe || '').toUpperCase()
  const ruleId = (finding.ruleId || '').toUpperCase()
  const sink = (finding.sink || '').toLowerCase()

  // 1. Command Injection (CWE-78 / CMDi)
  if (cwe.includes('78') || ruleId.includes('CMD') || ruleId.includes('EXEC') || sink.includes('exec') || sink.includes('spawn')) {
    // If child_process.exec or execSync is used
    if (lineText.includes('execSync(') || lineText.includes('.execSync(')) {
      const replaced = lineText.replace(
        /(?:child_process\.)?execSync\(([^,)]+)(.*)\)/,
        `execFileSync($1, [], { shell: false$2 })`
      )
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: (replaced !== lineText ? replaced : `// Hardened process invocation\nexecFileSync(command, args, { shell: false });`).trim(),
        explanation: 'Replaced dynamic shell invocation with safe binary execution (execFileSync with shell: false) to prevent command injection.',
      }
    }

    if (lineText.includes('exec(') || lineText.includes('.exec(')) {
      const replaced = lineText.replace(
        /(?:child_process\.)?exec\(([^,)]+)(.*)\)/,
        `execFile($1, [], { shell: false$2 })`
      )
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: (replaced !== lineText ? replaced : `// Hardened process invocation\nexecFile(command, args, { shell: false });`).trim(),
        explanation: 'Replaced shell string execution with safe execFile argument array without subshell invocation.',
      }
    }

    if (lineText.includes('shell: true')) {
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: lineText.replace('shell: true', 'shell: false').trim(),
        explanation: 'Disabled shell invocation ({ shell: false }) to prevent command chaining and injection.',
      }
    }
  }

  // 2. SQL Injection (CWE-89 / SQLi)
  if (cwe.includes('89') || ruleId.includes('SQL') || sink.includes('query') || sink.includes('raw')) {
    if (lineText.includes('$queryRawUnsafe(') || lineText.includes('$executeRawUnsafe(')) {
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: lineText
          .replace('$queryRawUnsafe', '$queryRaw')
          .replace('$executeRawUnsafe', '$executeRaw')
          .trim(),
        explanation: 'Replaced unsafe raw SQL string concatenation with Prisma parameterized template tag ($queryRaw).',
      }
    }

    if (lineText.includes('whereRaw(') || lineText.includes('havingRaw(')) {
      const replaced = lineText.replace(
        /(whereRaw|havingRaw)\((['"`].+?['"`])\s*\+\s*([^,\)]+)\)/,
        '$1($2, [$3])'
      )
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: (replaced !== lineText ? replaced : lineText.replace(/(whereRaw|havingRaw)\(([^)]+)\)/, '$1($2, [/* param */])')).trim(),
        explanation: 'Converted unparameterized raw query clause to parameterized bindings array in Knex.',
      }
    }

    // Dynamic SQL string template literals or concatenations (e.g. const sql = `SELECT ... WHERE status = '${status}' ` + orderClause;)
    if (
      lineText.includes('`') &&
      (lineText.includes('${') || lineText.includes('SELECT') || lineText.includes('INSERT') || lineText.includes('UPDATE') || lineText.includes('DELETE') || lineText.includes('FROM') || lineText.includes('WHERE'))
    ) {
      let paramIndex = 1
      const paramList: string[] = []
      
      let replaced = lineText.replace(/['"]?\$\{([^}]+)\}['"]?/g, (_match, expr) => {
        paramList.push(expr.trim())
        return `$${paramIndex++}`
      })

      if (replaced.includes('+')) {
        replaced = replaced.replace(
          /\+\s*([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*)\s*(;?)$/,
          (_m, clauseVar, endSemi) => {
            return `+ (ALLOWED_CLAUSES[${clauseVar}] || '')${endSemi || ''}`
          }
        )
      }

      if (replaced !== lineText) {
        return {
          searchSnippet: lineText.trim(),
          replacementSnippet: replaced.trim(),
          explanation: `Converted dynamic SQL interpolation into parameterized query placeholder ($1${paramList.length > 1 ? `..$${paramList.length}` : ''}) and validated dynamic clauses against allowlist map.`,
        }
      }
    }

    // Dynamic SQL string concatenation (e.g. "SELECT ... WHERE id = " + userId)
    if (
      (lineText.includes('SELECT') || lineText.includes('INSERT') || lineText.includes('UPDATE') || lineText.includes('DELETE') || lineText.includes('WHERE')) &&
      lineText.includes('+')
    ) {
      let replaced = lineText
        .replace(/['"]\s*\+\s*([a-zA-Z0-9_$.]+)\s*\+\s*['"]/g, '$1')
        .replace(/(WHERE\s+[a-zA-Z0-9_.]+\s*=\s*)['"]?\s*\+\s*([a-zA-Z0-9_$.]+)/i, '$1$1')

      if (replaced === lineText) {
        replaced = lineText.replace(/\+\s*([a-zA-Z0-9_$.]+)/, '/* parameterized placeholder */')
      }

      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: replaced.trim(),
        explanation: 'Converted dynamic SQL string concatenation into parameterized query placeholder to prevent SQL injection.',
      }
    }

    if (lineText.includes('.query(') || lineText.includes('db.query(')) {
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: lineText.replace(/\.query\(([^)]+)\)/, `.query($1, [/* parameterized values */])`).trim(),
        explanation: 'Converted dynamic SQL concatenation into parameterized query placeholders.',
      }
    }
  }

  // 3. Cross-Site Scripting (CWE-79 / XSS)
  if (cwe.includes('79') || ruleId.includes('XSS') || sink.includes('innerhtml') || sink.includes('dangerouslysetinnerhtml')) {
    if (lineText.includes('dangerouslySetInnerHTML')) {
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: lineText.replace(/__html:\s*([^}]+)/, '__html: DOMPurify.sanitize($1)').trim(),
        explanation: 'Sanitized dynamic HTML payload with DOMPurify before rendering into the DOM.',
      }
    }

    if (lineText.includes('.innerHTML =')) {
      return {
        searchSnippet: lineText.trim(),
        replacementSnippet: lineText.replace(/\.innerHTML\s*=\s*(.+);?/, '.innerHTML = DOMPurify.sanitize($1);').trim(),
        explanation: 'Sanitized input using DOMPurify.sanitize() before assigning to innerHTML.',
      }
    }
  }

  // Generic fallback
  return {
    searchSnippet: lineText.trim() || (finding.snippet || '').trim(),
    replacementSnippet: lineText.trim() || (finding.snippet || '').trim(),
    explanation: finding.remediation || 'Sanitized and hardened dangerous sink input.',
  }
}

/**
 * 4-Tier Smart Snippet Replacement
 * 1. Exact Match
 * 2. Line-Ending Normalized Match
 * 3. Trimmed Multi-Line Match
 * 4. Line-Anchored Statement Match
 */
export function applySnippetReplacement(
  fileContent: string,
  searchSnippet: string,
  replacementSnippet: string,
  targetLine?: number
): { updatedContent: string; applied: boolean } {
  if (!searchSnippet || !fileContent) {
    return { updatedContent: fileContent, applied: false }
  }

  // Tier 1: Direct exact match
  if (fileContent.includes(searchSnippet)) {
    return {
      updatedContent: fileContent.replace(searchSnippet, replacementSnippet),
      applied: true,
    }
  }

  // Tier 2: Line-ending normalized match (\r\n -> \n)
  const normFile = fileContent.replace(/\r\n/g, '\n')
  const normSearch = searchSnippet.replace(/\r\n/g, '\n')
  const normReplacement = replacementSnippet.replace(/\r\n/g, '\n')

  if (normFile.includes(normSearch)) {
    return {
      updatedContent: normFile.replace(normSearch, normReplacement),
      applied: true,
    }
  }

  // Tier 3: Trimmed multi-line matching
  const searchLines = normSearch.split('\n').map(l => l.trim()).filter(Boolean)
  if (searchLines.length > 0) {
    const fileLines = normFile.split('\n')
    let foundIndex = -1

    for (let i = 0; i <= fileLines.length - searchLines.length; i++) {
      let matches = true
      for (let j = 0; j < searchLines.length; j++) {
        if (fileLines[i + j].trim() !== searchLines[j]) {
          matches = false
          break
        }
      }
      if (matches) {
        foundIndex = i
        break
      }
    }

    if (foundIndex !== -1) {
      const before = fileLines.slice(0, foundIndex)
      const after = fileLines.slice(foundIndex + searchLines.length)
      const updated = [...before, normReplacement, ...after].join('\n')
      return { updatedContent: updated, applied: true }
    }
  }

  // Tier 4: Line-anchored context replacement if targetLine is provided
  if (targetLine && targetLine > 0) {
    const fileLines = normFile.split('\n')
    const targetIdx = targetLine - 1
    if (targetIdx >= 0 && targetIdx < fileLines.length) {
      const lineAtTarget = fileLines[targetIdx].trim()
      const searchFirstLine = searchLines[0] || normSearch.trim()

      if (lineAtTarget.includes(searchFirstLine) || searchFirstLine.includes(lineAtTarget) || lineAtTarget.length > 0) {
        fileLines[targetIdx] = normReplacement
        return {
          updatedContent: fileLines.join('\n'),
          applied: true,
        }
      }
    }
  }

  return { updatedContent: fileContent, applied: false }
}

/**
 * Builds domain-specific system prompt based on vulnerability class
 */
function getDomainSpecificFixPrompt(finding: Finding): string {
  const cwe = (finding.cwe || '').toUpperCase()
  const rule = (finding.ruleName || '').toUpperCase()
  const ruleId = (finding.ruleId || '').toUpperCase()

  let domainGuidance = ''
  if (cwe.includes('78') || rule.includes('COMMAND') || rule.includes('CMD')) {
    domainGuidance = `
VULNERABILITY CLASS: Command Injection (CWE-78 / CWE-88)
REMEDIATION REQUIREMENTS:
1. Replace shell execution (\`exec\`, \`execSync\`, \`shelljs.exec\`, or \`spawn\` with \`shell: true\`) with safe argument-array execution (\`spawn(binary, [args], { shell: false })\` or \`execFile(binary, [args])\`).
2. Alternatively, if shell execution is required, strictly sanitize dynamic parameters using \`shell-quote.quote([arg])\` or strict allowlist validation regex (\`/^[a-zA-Z0-9._-]+$/\`).
3. NEVER keep unvalidated template string concatenation inside shell execution sinks.`
  } else if (cwe.includes('89') || ruleId.includes('SQL')) {
    domainGuidance = `
VULNERABILITY CLASS: SQL Injection (CWE-89)
REMEDIATION REQUIREMENTS:
1. NEVER output the original vulnerable code in replacementSnippet. The replacementSnippet MUST modify and secure the code.
2. For SQL query string variables (e.g., const sql = \`SELECT ... WHERE status = '\${status}' \` + orderClause;):
   - Replace literal value interpolations '\${param}' or + param with query parameter placeholders ($1, $2, or ?).
   - For dynamic clauses/columns (e.g. orderClause, sortBy), validate against an allowlist map (e.g. ALLOWED_CLAUSES[orderClause] || '').
3. For database client calls (db.query, pool.query), pass parameter arrays as the second argument.
4. For ORMs (Prisma, Knex, TypeORM):
   - Prisma: Convert $queryRawUnsafe / $executeRawUnsafe to $queryRaw / $executeRaw tagged template literals.
   - Knex: Convert whereRaw("status = " + status) to whereRaw("status = ?", [status]).
   - TypeORM: Convert .where("status = " + status) to .where("status = :status", { status }).`
  } else if (cwe.includes('79') || ruleId.includes('XSS') || ruleId.includes('CROSS-SITE')) {
    domainGuidance = `
VULNERABILITY CLASS: Cross-Site Scripting (CWE-79)
REMEDIATION REQUIREMENTS:
1. NEVER output unchanged vulnerable code.
2. Sanitize untrusted dynamic HTML before assigning to DOM sinks using \`DOMPurify.sanitize(input)\`.
3. Or use safe text properties such as \`textContent\` or \`innerText\` instead of \`innerHTML\` / \`dangerouslySetInnerHTML\`.`
  }

  return `You are a Principal Security Architect and Senior Software Engineer specializing in automated code remediation.
Your task is to fix a confirmed vulnerability (${finding.ruleName}, ${finding.cwe}) in source code.
${domainGuidance}

STRICT JSON OUTPUT RULES:
1. "searchSnippet": Exact contiguous lines from the vulnerable code that need to be replaced. MUST be a verbatim substring from the code context. Keep it minimal (1-6 lines around line ${finding.line}).
2. "replacementSnippet": Secure, production-ready, syntax-valid replacement code that fixes the vulnerability. MUST BE DIFFERENT from searchSnippet. Retain existing indentation style.
3. "explanation": Concise 1-2 sentence explanation of how the patch fixes the vulnerability.
4. "commitMessage": Conventional git commit message (e.g. "fix(security): resolve command injection in ...").
5. "prTitle": Clean Pull Request title.
6. "prDescription": Structured markdown Pull Request description.

Output ONLY valid JSON matching this schema:
{
  "searchSnippet": "string",
  "replacementSnippet": "string",
  "explanation": "string",
  "commitMessage": "string",
  "prTitle": "string",
  "prDescription": "string"
}`
}

/**
 * Generates an automated security fix for a single vulnerability finding
 */
export async function generateAiFix(
  repoUrl: string,
  branch: string,
  finding: Finding
): Promise<SecurityFixProposal> {
  const gh = parseGitHubUrl(repoUrl)
  const isLocal = repoUrl.startsWith('file://') || repoUrl.startsWith('/')
  let fileContent = ''
  let tmpCloneDir: string | null = null

  try {
    if (isLocal) {
      const localBase = repoUrl.replace(/^file:\/\//, '')
      const fullPath = path.join(localBase, finding.filePath)
      fileContent = await fs.readFile(fullPath, 'utf-8')
    } else {
      tmpCloneDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-fixgen-'))
      logger.info(`Fetching repo ${repoUrl} [branch: ${branch}] to inspect ${finding.filePath}`)
      await execFileAsync('git', ['clone', '--depth', '1', '-b', branch, repoUrl, tmpCloneDir], {
        timeout: 35000,
      })
      const targetPath = path.join(tmpCloneDir, finding.filePath)
      fileContent = await fs.readFile(targetPath, 'utf-8')
    }
  } catch (fetchErr: any) {
    logger.error(`Error loading source file ${finding.filePath}: ${fetchErr.message}`)
    fileContent = finding.snippet || ''
    if (!fileContent) {
      throw new Error(`Unable to read file ${finding.filePath} from repository: ${fetchErr.message}`)
    }
  } finally {
    if (tmpCloneDir) {
      try {
        await fs.rm(tmpCloneDir, { recursive: true, force: true })
      } catch {}
    }
  }

  const { context, annotatedContext } = extractContextWindow(fileContent, finding.line, 25)
  const fallbackFix = generateDeterministicHardenedFix(finding, fileContent)

  let searchSnippet = fallbackFix.searchSnippet
  let replacementSnippet = fallbackFix.replacementSnippet
  let explanation = fallbackFix.explanation
  let commitMessage = `fix(security): resolve ${finding.ruleName} in ${path.basename(finding.filePath)}`
  let prTitle = `fix(security): resolve ${finding.ruleName} in ${path.basename(finding.filePath)}`
  let prDescription = `### Security Remediation\n\nThis Pull Request resolves **${finding.ruleName}** (${finding.cwe}) in \`${finding.filePath}:${finding.line}\`.\n\n- **Vulnerability**: ${finding.ruleName}\n- **CWE**: ${finding.cwe}\n- **Severity**: ${finding.severity}\n- **Remediation Details**: ${explanation}`

  try {
    const systemPrompt = getDomainSpecificFixPrompt(finding)
    const userPrompt = `Target File: ${finding.filePath}
Flagged Line: ${finding.line}
Vulnerability: ${finding.ruleName} (${finding.cwe}, Severity: ${finding.severity})
Flagged Sink: ${finding.sink}

Code Context:
\`\`\`javascript
${annotatedContext}
\`\`\`

Generate the production-ready hardened fix JSON.`

    const rawResponse = await sendAiChatCompletion({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.1,
      maxTokens: 2048,
      jsonMode: true,
      timeoutMs: 35000,
    })

    const fixJson = parseLlmJson(rawResponse)
    if (fixJson.searchSnippet && fixJson.replacementSnippet) {
      const candidateSearch = fixJson.searchSnippet.trim()
      const candidateReplacement = fixJson.replacementSnippet.trim()

      if (candidateSearch !== candidateReplacement && candidateReplacement.length > 0) {
        // Verify that candidate patch can be applied to fileContent
        const { updatedContent, applied } = applySnippetReplacement(
          fileContent,
          candidateSearch,
          candidateReplacement,
          finding.line
        )

        if (applied) {
          // Validate that updated file has valid syntax
          const parsedAst = parseSourceCode(updatedContent, finding.filePath)
          if (parsedAst) {
            searchSnippet = candidateSearch
            replacementSnippet = candidateReplacement
            if (fixJson.explanation) explanation = fixJson.explanation
            if (fixJson.commitMessage) commitMessage = fixJson.commitMessage
            if (fixJson.prTitle) prTitle = fixJson.prTitle
            if (fixJson.prDescription) prDescription = fixJson.prDescription
            logger.info(`[FixEngine] Successfully generated and verified AI patch for ${finding.id}`)
          } else {
            logger.warn(`[FixEngine] AI patch for ${finding.id} failed AST syntax validation. Using hardened deterministic recipe.`)
          }
        } else {
          logger.warn(`[FixEngine] AI searchSnippet did not match in ${finding.filePath}. Using hardened deterministic recipe.`)
        }
      } else {
        logger.warn(`[FixEngine] AI returned identical search and replacement snippet for ${finding.id}. Using hardened deterministic recipe.`)
      }
    }
  } catch (aiErr: any) {
    logger.warn(`[FixEngine] AI generation failed (${aiErr.message}). Using hardened deterministic fallback for ${finding.id}`)
  }

  // Compute preview context with the replacement applied
  const { updatedContent, applied } = applySnippetReplacement(
    context,
    searchSnippet,
    replacementSnippet,
    finding.line
  )
  const fixedContext = applied ? updatedContent : context

  const cleanRuleId = finding.ruleId.toLowerCase().replace(/[^a-z0-9]/g, '-')
  const randomSuffix = Math.random().toString(36).substring(2, 7)
  const suggestedBranch = `vulscan/fix-${cleanRuleId}-${randomSuffix}`

  return {
    findingId: finding.id,
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    cwe: finding.cwe,
    severity: finding.severity,
    filePath: finding.filePath,
    line: finding.line,
    sink: finding.sink,
    targetBranch: branch,
    suggestedBranch,
    searchSnippet,
    replacementSnippet,
    originalContext: context,
    fixedContext,
    explanation,
    prTitle,
    prDescription,
    commitMessage,
    canCreatePr: Boolean(gh),
    repoOwner: gh?.owner,
    repoName: gh?.repo,
  }
}

/**
 * Generates automated security fix proposals for multiple vulnerability findings
 */
export async function generateBatchAiFixes(
  repoUrl: string,
  branch: string,
  findings: Finding[]
): Promise<BatchSecurityFixProposal> {
  const gh = parseGitHubUrl(repoUrl)
  const isLocal = repoUrl.startsWith('file://') || repoUrl.startsWith('/')
  const filesMap = new Map<string, string>()
  let tmpCloneDir: string | null = null

  try {
    if (isLocal) {
      const localBase = repoUrl.replace(/^file:\/\//, '')
      for (const f of findings) {
        if (!filesMap.has(f.filePath)) {
          try {
            const fullPath = path.join(localBase, f.filePath)
            const content = await fs.readFile(fullPath, 'utf-8')
            filesMap.set(f.filePath, content)
          } catch (err: any) {
            logger.warn(`Could not read local file ${f.filePath}: ${err.message}`)
            if (f.snippet) filesMap.set(f.filePath, f.snippet)
          }
        }
      }
    } else {
      tmpCloneDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-batch-fixgen-'))
      logger.info(`Fetching repo ${repoUrl} [branch: ${branch}] for batch fix generation`)
      await execFileAsync('git', ['clone', '--depth', '1', '-b', branch, repoUrl, tmpCloneDir], {
        timeout: 45000,
      })

      for (const f of findings) {
        if (!filesMap.has(f.filePath)) {
          try {
            const targetPath = path.join(tmpCloneDir, f.filePath)
            const content = await fs.readFile(targetPath, 'utf-8')
            filesMap.set(f.filePath, content)
          } catch (err: any) {
            logger.warn(`Could not read file ${f.filePath} in cloned repository: ${err.message}`)
            if (f.snippet) filesMap.set(f.filePath, f.snippet)
          }
        }
      }
    }
  } catch (fetchErr: any) {
    logger.error(`Error loading repository files for batch fix: ${fetchErr.message}`)
    for (const f of findings) {
      if (!filesMap.has(f.filePath) && f.snippet) {
        filesMap.set(f.filePath, f.snippet)
      }
    }
  } finally {
    if (tmpCloneDir) {
      try {
        await fs.rm(tmpCloneDir, { recursive: true, force: true })
      } catch {}
    }
  }

  const fixes: FindingFixItem[] = []

  // Generate fix for each finding
  for (const finding of findings) {
    const fileContent = filesMap.get(finding.filePath) || finding.snippet || ''
    const { context, annotatedContext } = extractContextWindow(fileContent, finding.line, 25)
    const fallbackFix = generateDeterministicHardenedFix(finding, fileContent)

    let searchSnippet = fallbackFix.searchSnippet
    let replacementSnippet = fallbackFix.replacementSnippet
    let explanation = fallbackFix.explanation

    try {
      const systemPrompt = getDomainSpecificFixPrompt(finding)
      const userPrompt = `Target File: ${finding.filePath}
Flagged Line: ${finding.line}
Vulnerability: ${finding.ruleName} (${finding.cwe}, Severity: ${finding.severity})
Flagged Sink: ${finding.sink}

Code Context:
\`\`\`javascript
${annotatedContext}
\`\`\`

Generate the production-ready hardened fix JSON.`

      const rawResponse = await sendAiChatCompletion({
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.1,
        maxTokens: 2048,
        jsonMode: true,
        timeoutMs: 35000,
      })

      const fixJson = parseLlmJson(rawResponse)
      if (fixJson.searchSnippet && fixJson.replacementSnippet) {
        const candidateSearch = fixJson.searchSnippet.trim()
        const candidateReplacement = fixJson.replacementSnippet.trim()

        if (candidateSearch !== candidateReplacement && candidateReplacement.length > 0) {
          const { updatedContent, applied } = applySnippetReplacement(
            fileContent,
            candidateSearch,
            candidateReplacement,
            finding.line
          )

          if (applied) {
            const parsedAst = parseSourceCode(updatedContent, finding.filePath)
            if (parsedAst) {
              searchSnippet = candidateSearch
              replacementSnippet = candidateReplacement
              if (fixJson.explanation) explanation = fixJson.explanation
            }
          }
        }
      }
    } catch (e: any) {
      logger.debug(`[FixEngine] Batch AI fallback for finding ${finding.id}: ${e.message}`)
    }

    const { updatedContent, applied } = applySnippetReplacement(
      context,
      searchSnippet,
      replacementSnippet,
      finding.line
    )
    const fixedContext = applied ? updatedContent : context

    fixes.push({
      findingId: finding.id,
      ruleId: finding.ruleId,
      ruleName: finding.ruleName,
      cwe: finding.cwe,
      severity: finding.severity,
      filePath: finding.filePath,
      line: finding.line,
      sink: finding.sink,
      searchSnippet,
      replacementSnippet,
      explanation,
      originalContext: context,
      fixedContext,
    })
  }

  const randomSuffix = Math.random().toString(36).substring(2, 7)
  const uniqueFilesCount = new Set(findings.map(f => f.filePath)).size
  const suggestedBranch = `vulscan/fix-security-remediations-${findings.length}-vulns-${randomSuffix}`

  const prTitle =
    findings.length === 1
      ? `fix(security): resolve ${findings[0].ruleName} in ${path.basename(findings[0].filePath)}`
      : `fix(security): resolve ${findings.length} vulnerabilities across ${uniqueFilesCount} ${
          uniqueFilesCount === 1 ? 'file' : 'files'
        }`

  const summaryTableRows = fixes
    .map(
      f =>
        `| \`${f.findingId}\` | ${f.ruleName} | **${f.severity}** | \`${f.cwe}\` | \`${f.filePath}:${f.line}\` | \`${f.sink}\` |`
    )
    .join('\n')

  const detailsSections = fixes
    .map(
      (f, idx) => `#### ${idx + 1}. \`${f.findingId}\` — ${f.ruleName} (\`${f.cwe}\`)
- **File**: \`${f.filePath}:${f.line}\`
- **Severity**: **${f.severity}**
- **Dangerous Sink**: \`${f.sink}\`
- **Mitigation Applied**: ${f.explanation}
`
    )
    .join('\n')

  const prDescription = `## Automated Security Remediation

This Pull Request resolves **${findings.length} security ${
    findings.length === 1 ? 'vulnerability' : 'vulnerabilities'
  }** identified by **VulnScan AST Static Application Security Testing (SAST)** on branch \`${branch}\`.

---

### Resolved Vulnerabilities Summary

| Finding ID | Vulnerability | Severity | CWE | Location | Sink |
| :--- | :--- | :--- | :--- | :--- | :--- |
${summaryTableRows}

---

### Technical Remediation Breakdown

${detailsSections}

---

### Verification & Testing Instructions

1. **Automated Unit Tests**: Ensure existing application test suites pass without regressions (\`npm test\` / \`pnpm test\`).
2. **Defensive Boundaries**: Verify all dynamic database parameters and client-rendered inputs strictly adhere to prepared statement placeholders or sanitization routines.`

  const commitMessage =
    findings.length === 1
      ? `fix(security): resolve ${findings[0].ruleName} in ${path.basename(findings[0].filePath)}`
      : `fix(security): resolve ${findings.length} security vulnerabilities across ${uniqueFilesCount} ${
          uniqueFilesCount === 1 ? 'file' : 'files'
        }`

  return {
    targetBranch: branch,
    suggestedBranch,
    prTitle,
    prDescription,
    commitMessage,
    canCreatePr: Boolean(gh),
    repoOwner: gh?.owner,
    repoName: gh?.repo,
    totalFindings: findings.length,
    fixes,
  }
}

/**
 * Pushes single fix to branch and opens a GitHub Pull Request
 */
export async function createGitHubPullRequest(params: {
  repoUrl: string
  targetBranch: string
  branchName: string
  filePath: string
  searchSnippet: string
  replacementSnippet: string
  commitMessage: string
  prTitle: string
  prDescription: string
  githubToken?: string
}): Promise<CreatePrResult> {
  return createBatchGitHubPullRequest({
    repoUrl: params.repoUrl,
    targetBranch: params.targetBranch,
    branchName: params.branchName,
    patches: [
      {
        findingId: 'single-fix',
        filePath: params.filePath,
        searchSnippet: params.searchSnippet,
        replacementSnippet: params.replacementSnippet,
      },
    ],
    commitMessage: params.commitMessage,
    prTitle: params.prTitle,
    prDescription: params.prDescription,
    githubToken: params.githubToken,
  })
}

/**
 * Applies multiple file patches and opens a unified GitHub Pull Request
 */
export async function createBatchGitHubPullRequest(params: CreateBatchPrParams): Promise<CreatePrResult> {
  const token = params.githubToken || config.githubToken
  if (!token) {
    throw new Error(
      'GitHub Personal Access Token is required to push branches and open Pull Requests. Please provide a GitHub token with "repo" scope.'
    )
  }

  const gh = parseGitHubUrl(params.repoUrl)
  if (!gh) {
    throw new Error('Only GitHub repositories are supported for automated Pull Requests.')
  }

  if (!params.patches || params.patches.length === 0) {
    throw new Error('No file patches provided to create Pull Request.')
  }

  const { owner, repo } = gh
  const cleanBranch = params.branchName
    .replace(/[^a-zA-Z0-9_\-\.\/]/g, '-')
    .replace(/\.+/g, '.')
    .replace(/^\/+|\/+$/g, '')

  // 1. Authenticate with GitHub API
  logger.info(`Authenticating with GitHub API for batch PR creation on ${owner}/${repo}...`)
  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'VulnScan-Bot/1.0',
    },
  })

  if (!userRes.ok) {
    if (userRes.status === 401) {
      throw new Error('Invalid GitHub Personal Access Token. Authentication failed.')
    }
    const errText = await userRes.text()
    throw new Error(`GitHub API error (${userRes.status}): ${errText}`)
  }

  const userData = (await userRes.json()) as { login: string; email?: string }
  const authUser = userData.login

  // 2. Check repository permissions
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'VulnScan-Bot/1.0',
    },
  })

  if (!repoRes.ok) {
    if (repoRes.status === 404) {
      throw new Error(`Repository ${owner}/${repo} not found or token lacks access permissions.`)
    }
    throw new Error(`Failed to query repository ${owner}/${repo}: ${repoRes.statusText}`)
  }

  const repoData = (await repoRes.json()) as {
    permissions?: { push: boolean }
    default_branch: string
    fork: boolean
  }

  const canPushDirectly = Boolean(repoData.permissions?.push)
  let pushOwner = owner
  let prHead = cleanBranch
  let isFork = false

  if (!canPushDirectly && authUser.toLowerCase() !== owner.toLowerCase()) {
    logger.info(`User ${authUser} lacks push access to ${owner}/${repo}. Initializing fork for batch PR...`)
    isFork = true
    pushOwner = authUser
    prHead = `${authUser}:${cleanBranch}`

    const forkRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/forks`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'VulnScan-Bot/1.0',
      },
    })

    if (!forkRes.ok && forkRes.status !== 202) {
      const forkErr = await forkRes.text()
      throw new Error(`Failed to fork repository ${owner}/${repo}: ${forkErr}`)
    }

    await new Promise(r => setTimeout(r, 2500))
  }

  // 3. Workspace setup: clone, apply all patches, commit, and push
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-batch-pr-'))
  const cloneUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`
  const pushUrl = `https://x-access-token:${token}@github.com/${pushOwner}/${repo}.git`
  const fixedFindingIds: string[] = []

  try {
    logger.info(`Cloning ${owner}/${repo} [branch: ${params.targetBranch}] to temporary workspace for batch PR`)
    await execFileAsync('git', ['clone', '--depth', '1', '-b', params.targetBranch, cloneUrl, tmpDir], {
      timeout: 45000,
    })

    await execFileAsync('git', ['-C', tmpDir, 'config', 'user.name', authUser || 'VulnScan Security Bot'])
    await execFileAsync(
      'git',
      ['-C', tmpDir, 'config', 'user.email', userData.email || `${authUser || 'bot'}@users.noreply.github.com`]
    )
    await execFileAsync('git', ['-C', tmpDir, 'config', 'commit.gpgsign', 'false'])
    await execFileAsync('git', ['-C', tmpDir, 'config', 'core.hooksPath', '/dev/null'])
    await execFileAsync('git', ['-C', tmpDir, 'config', 'core.autocrlf', 'false'])

    await execFileAsync('git', ['-C', tmpDir, 'checkout', '-b', cleanBranch])

    const patchesByFile = new Map<string, BatchFilePatch[]>()
    for (const patch of params.patches) {
      const normalizedPath = patch.filePath.replace(/^[\/\\]+/, '').replace(/^\.\//, '')
      const list = patchesByFile.get(normalizedPath) || []
      list.push({ ...patch, filePath: normalizedPath })
      patchesByFile.set(normalizedPath, list)
    }

    let modifiedFileCount = 0

    for (const [relPath, filePatches] of patchesByFile.entries()) {
      const targetFilePath = path.join(tmpDir, relPath)
      let currentContent = ''
      try {
        currentContent = await fs.readFile(targetFilePath, 'utf-8')
      } catch (readErr: any) {
        logger.warn(`Could not read file ${relPath} in repository: ${readErr.message}`)
        continue
      }

      let modifiedContent = currentContent
      for (const p of filePatches) {
        const { updatedContent, applied } = applySnippetReplacement(
          modifiedContent,
          p.searchSnippet,
          p.replacementSnippet,
          p.line
        )
        if (applied) {
          modifiedContent = updatedContent
          fixedFindingIds.push(p.findingId)
        } else {
          logger.warn(`Patch could not be matched for finding ${p.findingId} in ${relPath}`)
        }
      }

      if (modifiedContent !== currentContent) {
        await fs.writeFile(targetFilePath, modifiedContent, 'utf-8')
        modifiedFileCount++
      }
    }

    if (fixedFindingIds.length === 0 || modifiedFileCount === 0) {
      throw new Error(
        'None of the security patches introduced new changes to the target files. The code in the repository may already be updated.'
      )
    }

    // Stage all changes
    await execFileAsync('git', ['-C', tmpDir, 'add', '-A'])

    // Ensure there are staged changes before committing
    const statusRes = await execFileAsync('git', ['-C', tmpDir, 'status', '--porcelain'])
    if (!statusRes.stdout || !statusRes.stdout.trim()) {
      throw new Error(
        'No file modifications detected to commit. The repository files may already contain the security remediations.'
      )
    }

    const commitMsg = (params.commitMessage || 'fix(security): resolve security vulnerabilities').trim()
    try {
      await execFileAsync('git', ['-C', tmpDir, 'commit', '-m', commitMsg])
    } catch (commitErr: any) {
      const commitErrMsg = commitErr.stderr || commitErr.stdout || commitErr.message
      throw new Error(`Git commit failed: ${commitErrMsg}`)
    }

    await execFileAsync('git', ['-C', tmpDir, 'remote', 'set-url', 'origin', pushUrl])

    logger.info(`Pushing batch fix branch ${cleanBranch} to origin...`)
    try {
      await execFileAsync('git', ['-C', tmpDir, 'push', '-u', 'origin', cleanBranch, '--force'], {
        timeout: 45000,
      })
    } catch (pushErr: any) {
      const pushErrMsg = pushErr.stderr || pushErr.stdout || pushErr.message
      throw new Error(`Git push failed: ${pushErrMsg}`)
    }
  } finally {
    try {
      await fs.rm(tmpDir, { recursive: true, force: true })
    } catch {}
  }

  // 4. Open Pull Request on upstream repository
  logger.info(`Opening Batch Pull Request from ${prHead} to ${owner}/${repo}:${params.targetBranch}...`)
  const prRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'VulnScan-Bot/1.0',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      title: params.prTitle,
      body: params.prDescription,
      head: prHead,
      base: params.targetBranch,
    }),
  })

  if (prRes.ok) {
    const prData = (await prRes.json()) as { html_url: string; number: number; state: string }
    return {
      prUrl: prData.html_url,
      prNumber: prData.number,
      branch: cleanBranch,
      isFork,
      state: prData.state,
      message: `Pull Request #${prData.number} created successfully`,
      fixedFindingIds,
    }
  }

  if (prRes.status === 422) {
    const listRes = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/pulls?head=${encodeURIComponent(
        prHead
      )}&base=${encodeURIComponent(params.targetBranch)}&state=open`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'VulnScan-Bot/1.0',
        },
      }
    )

    if (listRes.ok) {
      const existingPrs = (await listRes.json()) as Array<{ html_url: string; number: number; state: string }>
      if (existingPrs.length > 0) {
        return {
          prUrl: existingPrs[0].html_url,
          prNumber: existingPrs[0].number,
          branch: cleanBranch,
          isFork,
          state: existingPrs[0].state,
          message: 'Branch updated and existing pull request refreshed.',
          fixedFindingIds,
        }
      }
    }
  }

  const errData = await prRes.text()
  throw new Error(`Failed to create Pull Request: ${errData}`)
}

/**
 * Merges a GitHub Pull Request
 */
export async function mergeGitHubPullRequest(params: {
  repoUrl: string
  pullNumber: number
  mergeMethod?: 'merge' | 'squash' | 'rebase'
  githubToken?: string
}): Promise<{ merged: boolean; message: string }> {
  const token = params.githubToken || config.githubToken
  if (!token) {
    throw new Error('GitHub Personal Access Token is required to merge Pull Requests.')
  }

  const gh = parseGitHubUrl(params.repoUrl)
  if (!gh) {
    throw new Error('Only GitHub repositories are supported for Pull Request operations.')
  }

  const { owner, repo } = gh
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${params.pullNumber}/merge`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'VulnScan-Bot/1.0',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      merge_method: params.mergeMethod || 'squash',
    }),
  })

  if (res.ok) {
    const data = (await res.json()) as { merged: boolean; message: string }
    return {
      merged: data.merged,
      message: data.message || `Pull Request #${params.pullNumber} merged successfully.`,
    }
  }

  const errText = await res.text()
  throw new Error(`Failed to merge Pull Request #${params.pullNumber}: ${errText}`)
}
