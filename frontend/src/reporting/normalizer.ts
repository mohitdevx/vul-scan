import type {
  SecurityReport,
  SecurityFinding,
  FindingStatus,
  SeverityLevel,
  TaintFlow,
  TaintNode,
  FindingEvidence,
  FindingImpact,
  FindingRemediation,
  FindingAiAnalysis,
  Methodology,
  RuleMethodology,
} from './types.js'
import { computeSummary } from './severity.js'

export interface RawScanInput {
  id?: string
  repoName?: string
  repoUrl?: string
  branch?: string
  commitSha?: string
  createdAt?: string | Date
  durationMs?: number
  filesAnalyzed?: number
  scannedFilesCount?: number
  findingsCount?: number
  highCount?: number
  mediumCount?: number
  lowCount?: number
  status?: string
  findings?: any[]
  findingsJson?: string
  rulesExecuted?: number
}

export const SCANNER_RULES: RuleMethodology[] = [
  {
    id: 'ast/xss-innerhtml',
    name: 'DOM Cross-Site Scripting (XSS)',
    cwe: 'CWE-79',
    category: 'Injection / Client-Side Security',
    description: 'Detects unescaped user input reaching DOM execution sinks such as innerHTML, outerHTML, document.write, or dangerouslySetInnerHTML.',
    sources: ['req.query', 'req.body', 'req.params', 'location.search', 'window.name', 'document.referrer'],
    sinks: ['innerHTML', 'outerHTML', 'document.write', 'dangerouslySetInnerHTML', 'res.send'],
    detectionStrategy: 'Deterministic AST Taint Tracking across AssignmentExpressions, CallExpressions, and JSX Attributes without an intervening DOMPurify/validator sanitizer.',
  },
  {
    id: 'ast/sqli-unparameterized',
    name: 'SQL Injection (SQLi)',
    cwe: 'CWE-89',
    category: 'Injection / Database Security',
    description: 'Flags unparameterized SQL queries constructed via string binary concatenation (+) or dynamic template literal (${...}) interpolations.',
    sources: ['req.query', 'req.body', 'req.params', 'req.headers'],
    sinks: ['$queryRawUnsafe', 'knex.raw', 'db.query', 'connection.query', 'pool.query'],
    detectionStrategy: 'AST validation of SQL execution calls identifying dynamic BinaryExpression and TemplateLiteral nodes bypassing parameterized bindings.',
  },
  {
    id: 'ast/cmdi-exec',
    name: 'Operating System Command Injection (CMDi)',
    cwe: 'CWE-78',
    category: 'Injection / System Security',
    description: 'Identifies unvalidated inputs passed to system command interpreters such as child_process.exec, execSync, or spawn with shell option enabled.',
    sources: ['req.query', 'req.body', 'req.params', 'process.argv'],
    sinks: ['child_process.exec', 'child_process.execSync', 'exec', 'execSync', 'spawn({ shell: true })'],
    detectionStrategy: 'AST inspection of process spawning invocations with concatenated shell strings susceptible to command injection chaining (; && || |).',
  },
]

export class FindingNormalizer {
  /**
   * Normalizes a raw scan record into the canonical SecurityReport IR
   */
  public static normalizeScan(scan: RawScanInput): SecurityReport {
    const rawFindings: any[] = scan.findings || (scan.findingsJson ? JSON.parse(scan.findingsJson) : [])
    const normalizedFindings: SecurityFinding[] = rawFindings.map((f, idx) =>
      this.normalizeFinding(f, idx, scan.branch || 'main', scan.id)
    )

    const summary = computeSummary(normalizedFindings)

    const repoName = scan.repoName || this.extractRepoName(scan.repoUrl || '') || 'repository'
    const repoUrl = scan.repoUrl || `https://github.com/organization/${repoName}`
    const branch = scan.branch || 'main'
    const timestamp = scan.createdAt ? new Date(scan.createdAt).toISOString() : new Date().toISOString()
    const durationMs = scan.durationMs || 24
    const filesAnalyzed = scan.filesAnalyzed || scan.scannedFilesCount || Math.max(1, normalizedFindings.length * 4)

    const methodology: Methodology = {
      framework: 'VulScan AST Security Engine',
      analysisType: 'Deterministic AST Taint Analysis',
      description: 'Automated AST-based static application security testing (SAST) analyzing source-to-sink data flow, taint propagation, sanitizers, and execution boundaries.',
      rules: SCANNER_RULES,
    }

    return {
      schemaVersion: '1.0',
      metadata: {
        scanner: {
          name: 'VulScan',
          version: '2.4.0',
          engine: 'AST Taint Engine v2.4.0',
        },
        target: {
          repositoryName: repoName,
          repositoryUrl: repoUrl,
          branch,
        },
        scan: {
          id: scan.id || `scan-${Date.now()}`,
          timestamp,
          durationMs,
          filesAnalyzed,
          rulesExecuted: SCANNER_RULES.length,
        },
      },
      summary,
      findings: normalizedFindings,
      methodology,
      generatedAt: new Date().toISOString(),
    }
  }

  /**
   * Normalizes consolidated findings across multiple scanned branches
   */
  public static normalizeMultiBranchScan(
    repoName: string,
    repoUrl: string,
    scans: RawScanInput[]
  ): SecurityReport {
    const allFindings: SecurityFinding[] = []
    let totalDurationMs = 0
    let totalFilesAnalyzed = 0

    scans.forEach(s => {
      const rawFindings: any[] = s.findings || (s.findingsJson ? JSON.parse(s.findingsJson) : [])
      const branchFindings = rawFindings.map((f, idx) =>
        this.normalizeFinding(f, allFindings.length + idx, s.branch || 'main', s.id)
      )
      allFindings.push(...branchFindings)
      totalDurationMs += s.durationMs || 0
      totalFilesAnalyzed += s.filesAnalyzed || s.scannedFilesCount || Math.max(1, branchFindings.length * 4)
    })

    const summary = computeSummary(allFindings)

    const methodology: Methodology = {
      framework: 'VulScan AST Security Engine',
      analysisType: 'Deterministic Multi-Branch AST Taint Analysis',
      description: 'Consolidated multi-branch AST-based static application security testing (SAST) analyzing source-to-sink data flow across all active repository branches.',
      rules: SCANNER_RULES,
    }

    return {
      schemaVersion: '1.0',
      metadata: {
        scanner: {
          name: 'VulScan',
          version: '2.4.0',
          engine: 'AST Taint Engine v2.4.0',
        },
        target: {
          repositoryName: repoName,
          repositoryUrl: repoUrl,
          branch: scans.length === 1 ? (scans[0].branch || 'main') : `All Branches (${scans.length})`,
        },
        scan: {
          id: `consolidated-${Date.now()}`,
          timestamp: new Date().toISOString(),
          durationMs: totalDurationMs,
          filesAnalyzed: totalFilesAnalyzed,
          rulesExecuted: SCANNER_RULES.length,
        },
      },
      summary,
      findings: allFindings,
      methodology,
      generatedAt: new Date().toISOString(),
    }
  }

  /**
   * Normalizes a single finding with deterministic data grounding
   */
  public static normalizeFinding(
    raw: any,
    index: number,
    branch = 'main',
    scanId?: string
  ): SecurityFinding {
    const id = raw.id || `VUL-${String(index + 1).padStart(3, '0')}`
    const ruleId = raw.ruleId || this.inferRuleId(raw)
    const ruleName = raw.ruleName || this.inferRuleName(ruleId, raw.cwe)
    const cwe = raw.cwe || this.inferCwe(ruleId)
    const category = this.inferCategory(cwe)
    const severity = this.normalizeSeverity(raw.severity)
    const file = raw.filePath || raw.file || 'src/index.js'
    const line = Number(raw.line) || 1
    const column = Number(raw.column) || 1

    const sinkExpr = raw.sink || this.inferSink(raw.snippet, ruleId)
    const sourceExpr = raw.source || raw.untrustedSource || this.inferSource(raw.snippet)
    const taintFlow = this.extractTaintFlow(sourceExpr, sinkExpr, raw.snippet, file, line)
    const evidence = this.extractEvidence(raw.snippet, line, sinkExpr)
    const analysis = this.normalizeAiAnalysis(raw.aiAnalysis)
    const impact = this.deriveImpact(cwe, ruleName, file)
    const remediation = this.deriveRemediation(cwe, ruleId, sinkExpr, raw.remediation, analysis)

    const status: FindingStatus = analysis
      ? analysis.isFalsePositive
        ? 'false-positive'
        : analysis.verdict === 'CONFIRMED'
        ? 'confirmed'
        : 'needs-review'
      : 'confirmed'

    const confidence = analysis?.confidence ?? 95

    return {
      id,
      rule: {
        id: ruleId,
        name: ruleName,
        category,
        cwe,
      },
      severity,
      confidence,
      status,
      location: {
        file,
        line,
        column,
      },
      taintFlow,
      evidence,
      analysis,
      impact,
      remediation,
      rawMessage: raw.message || `Potential ${ruleName} detected at ${file}:${line}`,
      branch,
      scanId,
    }
  }

  private static normalizeSeverity(severity?: string): SeverityLevel {
    const normalized = (severity || 'HIGH').toUpperCase()
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(normalized)) {
      return normalized as SeverityLevel
    }
    return 'HIGH'
  }

  private static extractTaintFlow(
    sourceExpr: string,
    sinkExpr: string,
    snippet: string,
    file: string,
    line: number
  ): TaintFlow {
    const sourceNode: TaintNode = {
      type: 'source',
      label: 'External Input',
      expression: sourceExpr || 'User-Controlled Input',
      description: 'Originating untrusted parameter or network payload',
      file,
    }

    const transformations: TaintNode[] = []
    const cleanSnippet = snippet || ''

    if (cleanSnippet.includes('Buffer.from') || cleanSnippet.includes('base64')) {
      transformations.push({
        type: 'transformation',
        label: 'Base64 Decode',
        expression: "Buffer.from(..., 'base64').toString('utf8')",
        description: 'Decodes input without security sanitization or schema validation',
      })
    } else if (cleanSnippet.includes('+') && (cleanSnippet.includes('SELECT') || cleanSnippet.includes('INSERT') || cleanSnippet.includes('UPDATE'))) {
      transformations.push({
        type: 'transformation',
        label: 'String Concatenation',
        expression: 'sqlQuery = "..." + input',
        description: 'Direct string interpolation bypassing parameterized query bindings',
      })
    } else if (cleanSnippet.includes('+') || cleanSnippet.includes('${')) {
      transformations.push({
        type: 'transformation',
        label: 'Dynamic Interpolation',
        expression: 'template string / dynamic concat',
        description: 'Unescaped variable interpolation propagated to execution boundary',
      })
    }

    const sinkNode: TaintNode = {
      type: 'sink',
      label: 'Dangerous Sink',
      expression: sinkExpr || 'Execution Sink',
      description: 'Sensitive execution boundary consuming unsanitized input',
      file,
      line,
    }

    return {
      source: sourceNode,
      transformations,
      sink: sinkNode,
    }
  }

  private static extractEvidence(
    snippet: string,
    line: number,
    sinkExpr: string
  ): FindingEvidence {
    const code = (snippet || '// Code evidence unavailable').trim()
    const lines = code.split('\n')
    const startLine = Math.max(1, line - Math.floor(lines.length / 2))
    const endLine = startLine + lines.length - 1

    return {
      code,
      language: 'javascript',
      startLine,
      endLine,
      highlightLine: line,
      highlightToken: sinkExpr,
    }
  }

  private static normalizeAiAnalysis(ai: any): FindingAiAnalysis | undefined {
    if (!ai) return undefined

    const isFalsePositive = ai.isFalsePositive === true || ai.verdict === 'FALSE_POSITIVE'
    let verdict: FindingAiAnalysis['verdict'] = 'CONFIRMED'
    if (isFalsePositive) {
      verdict = 'FALSE_POSITIVE'
    } else if (ai.verdict === 'SUSPICIOUS' || ai.verdict === 'NEEDS_REVIEW') {
      verdict = 'NEEDS_REVIEW'
    }

    return {
      model: ai.model || 'qwen2.5-coder:3b',
      verdict,
      confidence: Number(ai.confidence) || (isFalsePositive ? 90 : 95),
      reasoning: ai.analysis || ai.reason || 'Data flow connects untrusted source directly to sink without verification boundary.',
      isFalsePositive,
      sanitizerDetected: Boolean(ai.sanitizerDetected),
      safeCastDetected: Boolean(ai.safeCastDetected),
      evaluatedAt: ai.evaluatedAt || new Date().toISOString(),
    }
  }

  private static deriveImpact(cwe: string, ruleName: string, file: string): FindingImpact {
    if (cwe === 'CWE-79' || ruleName.toLowerCase().includes('xss')) {
      return {
        description: 'Unsanitized user data is interpreted as executable HTML/JavaScript in the victim’s browser origin context.',
        consequences: [
          'Arbitrary JavaScript execution in the application session origin',
          'Access to sensitive DOM elements and browser-visible authentication tokens',
          'Session hijacking and malicious actions performed on behalf of authenticated users',
          'Defacement or unauthorized client-side UI manipulation',
        ],
        prerequisites: ['Attacker controls input rendered by the application in a victim session'],
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium / High)',
      }
    }

    if (cwe === 'CWE-89' || ruleName.toLowerCase().includes('sql')) {
      return {
        description: 'Untrusted input dynamically alters the structural semantics of backend database queries.',
        consequences: [
          'Unauthorized read access to confidential database tables',
          'Authentication bypass and privilege escalation',
          'Modification or destruction of persistent relational data',
          'Potential underlying host command execution via database administrative functions',
        ],
        prerequisites: ['Direct reachability of unparameterized database execution method'],
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)',
      }
    }

    if (cwe === 'CWE-78' || ruleName.toLowerCase().includes('command')) {
      return {
        description: 'Untrusted input is passed to an OS command interpreter without argument isolation.',
        consequences: [
          'Arbitrary OS command execution with application process privileges',
          'Full host operating system compromise and lateral movement',
          'Exfiltration of environment secrets, cloud credentials, and filesystem data',
          'Denial of service and process disruption',
        ],
        prerequisites: ['Reachable parameter supplying shell metacharacters (; && || | ` $)'],
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)',
      }
    }

    return {
      description: `Security flaw identified in ${file} enabling unauthorized state manipulation or execution.`,
      consequences: [
        'Violation of defensive coding and data integrity standards',
        'Potential component in multi-stage exploit chains',
      ],
      prerequisites: ['Reachable application execution flow'],
    }
  }

  private static deriveRemediation(
    cwe: string,
    ruleId: string,
    _sinkExpr: string,
    rawRemediation?: string,
    _analysis?: FindingAiAnalysis
  ): FindingRemediation {
    if (rawRemediation && rawRemediation.trim().length > 0) {
      return {
        summary: rawRemediation.split('\n')[0] || 'Sanitize and validate untrusted input before sink execution.',
        explanation: rawRemediation,
        documentationUrl: `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`,
      }
    }

    if (cwe === 'CWE-79' || ruleId.includes('xss')) {
      return {
        summary: 'Use safe text assignment APIs or enforce allowlist HTML sanitization.',
        explanation: 'Avoid direct assignment to innerHTML/outerHTML. When plain text is expected, use textContent or innerText. When rich HTML markup is strictly necessary, sanitize inputs using a hardened allowlist sanitizer such as DOMPurify.',
        code: `// Preferred Safe Fix (when markup is not needed):\nproxy.textContent = decodedHtml;\n\n// If HTML rendering is strictly required:\nimport DOMPurify from 'dompurify';\nproxy.innerHTML = DOMPurify.sanitize(decodedHtml);`,
        language: 'javascript',
        documentationUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      }
    }

    if (cwe === 'CWE-89' || ruleId.includes('sql')) {
      return {
        summary: 'Enforce parameterized queries with prepared statement placeholders.',
        explanation: 'Never concatenate user input into raw SQL strings. Always pass variables via parameterized query arrays or typed ORM methods.',
        code: `// Preferred Parameterized Fix:\nconst result = await prisma.$queryRaw\`SELECT * FROM users WHERE id = \${userId}\`;\n\n// Raw DB Driver placeholder:\ndb.query('SELECT * FROM users WHERE id = ?', [userId]);`,
        language: 'javascript',
        documentationUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      }
    }

    if (cwe === 'CWE-78' || ruleId.includes('cmdi')) {
      return {
        summary: 'Use execFile or spawn with argument arrays without invoking a shell.',
        explanation: 'Avoid passing string commands to child_process.exec. Use child_process.execFile or spawn where the executable and arguments are strictly separated into array arguments.',
        code: `// Preferred Safe Fix:\nimport { execFile } from 'child_process';\nexecFile('/usr/bin/git', ['log', '-n', userBranch], (err, stdout) => {\n  // Process safe output\n});`,
        language: 'javascript',
        documentationUrl: 'https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Defense_Cheat_Sheet.html',
      }
    }

    return {
      summary: rawRemediation || 'Sanitize user inputs and parameterize execution sinks.',
      explanation: 'Ensure all untrusted data flow conforms to defensive boundary validations.',
      documentationUrl: 'https://owasp.org/www-project-top-ten/',
    }
  }

  private static inferRuleId(raw: any): string {
    const text = `${raw.ruleName || ''} ${raw.message || ''} ${raw.sink || ''}`.toLowerCase()
    if (text.includes('xss') || text.includes('innerhtml') || text.includes('script')) return 'ast/xss-innerhtml'
    if (text.includes('sql') || text.includes('query')) return 'ast/sqli-unparameterized'
    if (text.includes('exec') || text.includes('command') || text.includes('spawn')) return 'ast/cmdi-exec'
    return 'ast/generic-injection'
  }

  private static inferRuleName(ruleId: string, cwe?: string): string {
    if (ruleId.includes('xss') || cwe === 'CWE-79') return 'DOM Cross-Site Scripting (XSS)'
    if (ruleId.includes('sql') || cwe === 'CWE-89') return 'SQL Injection (SQLi)'
    if (ruleId.includes('cmdi') || cwe === 'CWE-78') return 'Operating System Command Injection (CMDi)'
    return 'Untrusted Input Injection'
  }

  private static inferCwe(ruleId: string): string {
    if (ruleId.includes('xss')) return 'CWE-79'
    if (ruleId.includes('sql')) return 'CWE-89'
    if (ruleId.includes('cmdi')) return 'CWE-78'
    return 'CWE-20'
  }

  private static inferCategory(cwe: string): string {
    if (cwe === 'CWE-79') return 'Injection / Client-Side Security'
    if (cwe === 'CWE-89') return 'Injection / Database Security'
    if (cwe === 'CWE-78') return 'Injection / System Security'
    return 'Input Validation'
  }

  private static inferSink(snippet?: string, ruleId?: string): string {
    if (!snippet) return ruleId?.includes('xss') ? 'innerHTML' : 'sink'
    if (snippet.includes('innerHTML')) return 'proxy.innerHTML'
    if (snippet.includes('outerHTML')) return 'element.outerHTML'
    if (snippet.includes('exec')) return 'child_process.exec'
    if (snippet.includes('query')) return 'db.query'
    return 'dangerousSink'
  }

  private static inferSource(snippet?: string): string {
    if (!snippet) return 'req.query.rawB64'
    const match = snippet.match(/req\.(query|body|params|headers)\.[a-zA-Z0-9_]+/i)
    if (match) return match[0]
    if (snippet.includes('req.query')) return 'req.query.rawB64'
    if (snippet.includes('req.body')) return 'req.body.payload'
    return 'untrustedInput'
  }

  private static extractRepoName(url: string): string {
    try {
      const parsed = new URL(url)
      const segments = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/')
      if (segments.length >= 2) return segments[1].replace(/\.git$/, '')
      return segments[0] || 'repository'
    } catch {
      const parts = url.split('/')
      return parts[parts.length - 1]?.replace(/\.git$/, '') || 'repository'
    }
  }
}
