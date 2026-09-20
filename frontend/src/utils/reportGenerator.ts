import type { ScanItem, FindingItem } from '../services/api'

/**
 * Trigger download of a raw string content as a .md file
 */
export function downloadMarkdownFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', filename)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Generate a comprehensive Markdown report for a single branch scan
 */
export function generateBranchMarkdownReport(scan: ScanItem): string {
  const dateStr = new Date(scan.createdAt).toUTCString()
  const findings = scan.findings || []

  let md = `# AST Security Assessment Report: ${scan.repoName}

**Repository URL**: \`${scan.repoUrl}\`  
**Target Branch**: \`${scan.branch}\`  
**Scan Timestamp**: ${dateStr}  
**Engine Duration**: ${scan.durationMs}ms  
**Scanner Version**: \`AST Security Engine v2.4.0\`  
**Report Type**: Individual Branch Report  

---

## 1. Executive Summary

`
  if (findings.length === 0) {
    md += `> [!NOTE]
> **CLEAN SCAN**: Zero security vulnerabilities detected by deterministic AST analysis on branch \`${scan.branch}\`.
`
  } else {
    md += `> [!WARNING]
> **VULNERABILITIES FLAGGED**: A total of **${findings.length}** security finding(s) were flagged in this scan on branch \`${scan.branch}\`.
> - **Critical / High Severity**: ${scan.highCount}
> - **Medium Severity**: ${scan.mediumCount}
> - **Low Severity**: ${scan.lowCount}
`
  }

  md += `
## 2. Findings Summary Table

| ID | Rule / Vulnerability | Severity | CWE | Sink Token | Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
`

  if (findings.length === 0) {
    md += `| — | *No findings detected* | Clean | — | — | — |\n`
  } else {
    findings.forEach((f, idx) => {
      md += `| ${f.id || idx + 1} | ${f.ruleName} | **${f.severity}** | \`${f.cwe}\` | \`${f.sink}\` | \`${f.filePath}:${f.line}\` |\n`
    })
  }

  md += `\n---\n\n## 3. Detailed Vulnerability Analyses & Code Snippets\n\n`

  if (findings.length === 0) {
    md += `*No vulnerabilities flagged for branch \`${scan.branch}\`.*\n`
  } else {
    findings.forEach((f, idx) => {
      md += `### 3.${idx + 1} [${f.severity}] ${f.ruleName} (\`${f.cwe}\`)

- **File Path**: \`${f.filePath}:${f.line}:${f.column}\`
- **Sink Token**: \`${f.sink}\`
- **Rule Identifier**: \`${f.ruleId}\`

#### Vulnerability Description
${f.message}

#### Flagged AST Code Snippet
\`\`\`javascript
${f.snippet}
\`\`\`
${f.aiAnalysis ? `
#### AI Security & Taint Flow Advisory (${f.aiAnalysis.model || 'qwen2.5-coder:3b'})
- **Verdict**: ${f.aiAnalysis.isFalsePositive ? '🟢 **FALSE POSITIVE**' : f.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY' ? '🔴 **CONFIRMED VULNERABILITY**' : '🟡 **NEEDS MANUAL REVIEW**'} (${f.aiAnalysis.confidence}% confidence)
${f.aiAnalysis.sanitizerDetected ? '- *Sanitizer detected in data-flow (DOMPurify/Encoder)*\n' : ''}${f.aiAnalysis.safeCastDetected ? '- *Safe primitive type conversion detected (parseInt/Number)*\n' : ''}

${f.aiAnalysis.analysis || f.aiAnalysis.reason}
` : ''}
#### Hardened Remediation
> ${f.aiAnalysis?.remediation || f.remediation || 'Sanitize user inputs and parameterize execution sinks.'}

---
`
    })
  }

  md += `
## 4. Methodology & Scope
This scan was executed deterministically by inspecting the Abstract Syntax Tree (AST) for:
1. **Cross-Site Scripting (XSS)** (\`CWE-79\`): Sinks including DOM \`innerHTML\`, \`outerHTML\`, \`document.write\`, server reflected \`res.send\`, and JSX \`dangerouslySetInnerHTML\`.
2. **SQL Injection (SQLi)** (\`CWE-89\`): Unparameterized binary concatenation or dynamic template literal interpolation in ORM and raw driver calls (\`$queryRawUnsafe\`, \`knex.raw\`, \`db.query\`).
3. **Operating System Command Injection (CMDi)** (\`CWE-78\`): Dynamic command construction into system shell runners (\`child_process.exec\`, \`execSync\`, \`spawn\` with \`shell: true\`).

*Generated automatically by VulScan AST Security Engine.*
`
  return md
}

/**
 * Generate a Consolidated Full Repository Report across all scanned branches
 */
export function generateFullRepoMarkdownReport(
  repoName: string,
  repoUrl: string,
  scans: ScanItem[]
): string {
  const dateStr = new Date().toUTCString()
  // Filter scans belonging to this repository
  const repoScans = scans.filter(
    s => s.repoName === repoName || s.repoUrl === repoUrl
  )

  // Group latest scan per branch
  const branchMap = new Map<string, ScanItem>()
  repoScans.forEach(s => {
    const existing = branchMap.get(s.branch)
    if (!existing || new Date(s.createdAt) > new Date(existing.createdAt)) {
      branchMap.set(s.branch, s)
    }
  })

  const uniqueBranchScans = Array.from(branchMap.values())
  const totalFindingsAcrossBranches = uniqueBranchScans.reduce(
    (acc, s) => acc + s.findingsCount,
    0
  )
  const totalHigh = uniqueBranchScans.reduce((acc, s) => acc + s.highCount, 0)
  const totalMed = uniqueBranchScans.reduce((acc, s) => acc + s.mediumCount, 0)
  const totalLow = uniqueBranchScans.reduce((acc, s) => acc + s.lowCount, 0)

  let md = `# Full Repository Security Posture Report: ${repoName}

**Repository URL**: \`${repoUrl}\`  
**Generated At**: ${dateStr}  
**Total Scanned Branches**: ${uniqueBranchScans.length}  
**Consolidated Findings**: **${totalFindingsAcrossBranches}** (${totalHigh} High/Critical, ${totalMed} Medium, ${totalLow} Low)  
**Report Type**: Full Consolidated Repository Report  

---

## 1. Executive Posture Overview

This report provides a unified view of all branches analyzed for repository **\`${repoName}\`**.

| Total Branches Analyzed | Cumulative Findings | Critical / High | Medium | Clean Branches |
| :---: | :---: | :---: | :---: | :---: |
| **${uniqueBranchScans.length}** | **${totalFindingsAcrossBranches}** | **${totalHigh}** | **${totalMed}** | **${uniqueBranchScans.filter(b => b.findingsCount === 0).length}** |

---

## 2. Branch Breakdown Summary

| Branch Name | Status | Total Findings | High / Critical | Medium | Scan Date |
| :--- | :--- | :---: | :---: | :---: | :--- |
`

  uniqueBranchScans.forEach(s => {
    const statusPill = s.findingsCount === 0 ? 'Clean' : 'Flagged'
    const scanDate = new Date(s.createdAt).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
    md += `| \`${s.branch}\` | ${statusPill} | ${s.findingsCount} | ${s.highCount} | ${s.mediumCount} | ${scanDate} |\n`
  })

  md += `\n---\n\n## 3. Findings Categorized by Branch\n\n`

  uniqueBranchScans.forEach(branchScan => {
    const findings = branchScan.findings || []
    md += `### Branch: \`${branchScan.branch}\`\n\n`
    md += `- **Scan Timestamp**: ${new Date(branchScan.createdAt).toUTCString()}\n`
    md += `- **Duration**: ${branchScan.durationMs}ms\n`
    md += `- **Branch Findings Count**: ${branchScan.findingsCount}\n\n`

    if (findings.length === 0) {
      md += `*Zero vulnerabilities flagged on branch \`${branchScan.branch}\`.*\n\n`
    } else {
      findings.forEach((f: FindingItem, idx: number) => {
        md += `#### ${idx + 1}. [${f.severity}] ${f.ruleName} (\`${f.cwe}\`)
- **File**: \`${f.filePath}:${f.line}:${f.column}\`
- **Sink**: \`${f.sink}\`
- **Description**: ${f.message}

\`\`\`javascript
${f.snippet}
\`\`\`

${f.aiAnalysis ? `
##### AI Security & Taint Flow Advisory
- **Verdict**: ${f.aiAnalysis.isFalsePositive ? '🟢 **FALSE POSITIVE**' : f.aiAnalysis.verdict === 'CONFIRMED_VULNERABILITY' ? '🔴 **CONFIRMED VULNERABILITY**' : '🟡 **NEEDS MANUAL REVIEW**'} (${f.aiAnalysis.confidence}% confidence)
${f.aiAnalysis.sanitizerDetected ? '- *Sanitizer detected in data-flow*\n' : ''}${f.aiAnalysis.safeCastDetected ? '- *Safe primitive conversion detected*\n' : ''}

${f.aiAnalysis.analysis || f.aiAnalysis.reason}
` : ''}
> **Remediation**: ${f.aiAnalysis?.remediation || f.remediation}

`
      })
    }
    md += `\n---\n\n`
  })

  md += `## 4. Remediation Prioritization Checklist

1. **Address All High / Critical Injection Sinks**: Replace raw shell execution with \`execFile\` or \`spawn\` array arguments.
2. **Enforce Parameterized SQL**: Ban binary \`+\` concatenation and unescaped template string interpolation in all database query layers.
3. **Contextual Encoding / DOM Sanitization**: Ensure untrusted data assigned to DOM sinks is sanitized with context-aware libraries like \`DOMPurify\`.

*Report generated by VulScan Security Platform.*
`
  return md
}
