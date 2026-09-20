import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { config } from '../config/env.js'
import { logger } from '../utils/logger.js'
import type { Finding } from '../engine/types.js'

const execFileAsync = promisify(execFile)

export interface SecurityFixProposal {
  findingId: string
  filePath: string
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
}

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  try {
    const trimmed = url.trim()
    // Match https://github.com/owner/repo or http://github.com/owner/repo
    const httpsMatch = trimmed.match(/^https?:\/\/(?:www\.)?github\.com\/([^\/]+)\/([^\/\.]+)(?:\.git)?(?:\/.*)?$/i)
    if (httpsMatch) {
      return { owner: httpsMatch[1], repo: httpsMatch[2] }
    }
    // Match git@github.com:owner/repo.git
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
 * Extracts focused lines around the vulnerability for AI fix context
 */
function extractContextWindow(fileContent: string, line: number, radius = 25): {
  context: string
  startLine: number
  endLine: number
} {
  const lines = fileContent.split('\n')
  const total = lines.length
  const start = Math.max(0, line - 1 - radius)
  const end = Math.min(total, line + radius)

  const slice = lines.slice(start, end).join('\n')
  return {
    context: slice,
    startLine: start + 1,
    endLine: end,
  }
}

/**
 * Robust JSON parser that handles markdown fences and trailing commas from LLM output
 */
function parseLlmJson(rawText: string): any {
  let cleaned = rawText.trim()

  // Extract from ```json ... ``` or ``` ... ```
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)
  if (codeBlockMatch && codeBlockMatch[1]) {
    cleaned = codeBlockMatch[1].trim()
  }

  // Find the first '{' and last '}'
  const firstBrace = cleaned.indexOf('{')
  const lastBrace = cleaned.lastIndexOf('}')
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    cleaned = cleaned.substring(firstBrace, lastBrace + 1)
  }

  try {
    return JSON.parse(cleaned)
  } catch (err: any) {
    logger.warn(`Direct JSON parse failed (${err.message}), attempting sanitized parse...`)
    // Remove potential unescaped newlines inside strings or trailing commas
    const relaxed = cleaned
      .replace(/,\s*([}\]])/g, '$1')
    try {
      return JSON.parse(relaxed)
    } catch {
      throw new Error(`Failed to parse AI-generated fix JSON. Raw response: ${rawText.slice(0, 300)}...`)
    }
  }
}

/**
 * Replaces search snippet in target file content with tolerance for whitespace/line-ending differences
 */
export function applySnippetReplacement(
  fileContent: string,
  searchSnippet: string,
  replacementSnippet: string
): { updatedContent: string; applied: boolean } {
  // 1. Direct exact match
  if (fileContent.includes(searchSnippet)) {
    return {
      updatedContent: fileContent.replace(searchSnippet, replacementSnippet),
      applied: true,
    }
  }

  // 2. Line-ending normalized match (\r\n -> \n)
  const normFile = fileContent.replace(/\r\n/g, '\n')
  const normSearch = searchSnippet.replace(/\r\n/g, '\n')
  const normReplacement = replacementSnippet.replace(/\r\n/g, '\n')

  if (normFile.includes(normSearch)) {
    return {
      updatedContent: normFile.replace(normSearch, normReplacement),
      applied: true,
    }
  }

  // 3. Trimmed multi-line matching
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

  return { updatedContent: fileContent, applied: false }
}

/**
 * Generates an automated AI security fix for a vulnerability finding
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
      // Shallow clone to read the exact file from git branch
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
    // Fallback: If file cannot be read from repo directly, use finding snippet as baseline
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

  const { context } = extractContextWindow(fileContent, finding.line, 25)

  // Prompt Qwen 2.5 Coder 3B to generate an exact contiguous replacement
  const systemPrompt = `You are a Principal Security Engineer and Senior Software Architect specializing in code remediation.
Your task is to fix a confirmed vulnerability (${finding.ruleName}, ${finding.cwe}) in source code.

RULES:
1. "searchSnippet": Provide the exact contiguous lines from the vulnerable code that need to be replaced. MUST be an exact verbatim substring from the provided code context. Keep it concise (1 to 8 lines around the dangerous sink).
2. "replacementSnippet": Provide the secure, production-ready replacement code that mitigates the vulnerability using security best practices (e.g. DOMPurify.sanitize, textContent, parameterization, or appropriate validation/escaping). Retain existing indentation style.
3. "explanation": A crisp 2-3 sentence explanation of how this fix neutralizes the threat.
4. "commitMessage": A conventional git commit message (e.g. "fix(security): sanitize DOM sink with DOMPurify in ...").
5. "prTitle": A clean Pull Request title.
6. "prDescription": A structured GitHub Pull Request body in Markdown (including Overview, CWE, Changes Applied, and Verification instructions).

Respond ONLY with a valid JSON object with keys:
"searchSnippet", "replacementSnippet", "explanation", "commitMessage", "prTitle", "prDescription"`

  const userPrompt = `Target File: ${finding.filePath}
Flagged Line: ${finding.line}
Vulnerability: ${finding.ruleName} (${finding.cwe}, Severity: ${finding.severity})
Dangerous Sink: ${finding.sink}

Code Context:
\`\`\`
${context}
\`\`\`

Generate the production-grade bug fix JSON.`

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 45000)

  const res = await fetch(`${config.ollamaBaseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: config.aiModel,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      stream: false,
      format: 'json',
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

  const fixJson = parseLlmJson(rawContent)

  let searchSnippet = (fixJson.searchSnippet || finding.snippet || '').trim()
  let replacementSnippet = (fixJson.replacementSnippet || '').trim()

  // Safety fallback if model didn't return search snippet matching the file
  if (!fileContent.includes(searchSnippet)) {
    // Try matching the finding snippet line
    if (finding.snippet && fileContent.includes(finding.snippet.trim())) {
      searchSnippet = finding.snippet.trim()
    }
  }

  // Compute preview context with the replacement applied
  const { updatedContent, applied } = applySnippetReplacement(context, searchSnippet, replacementSnippet)
  const fixedContext = applied ? updatedContent : context

  const cleanRuleId = finding.ruleId.toLowerCase().replace(/[^a-z0-9]/g, '-')
  const randomSuffix = Math.random().toString(36).substring(2, 7)
  const suggestedBranch = `vulscan/fix-${cleanRuleId}-${randomSuffix}`

  return {
    findingId: finding.id,
    filePath: finding.filePath,
    targetBranch: branch,
    suggestedBranch,
    searchSnippet,
    replacementSnippet,
    originalContext: context,
    fixedContext,
    explanation: fixJson.explanation || 'Applied security sanitization and input hardening.',
    prTitle: fixJson.prTitle || `fix(security): resolve ${finding.ruleName} in ${path.basename(finding.filePath)}`,
    prDescription:
      fixJson.prDescription ||
      `### Security Advisory & Automated Fix\n\nThis Pull Request fixes **${finding.ruleName}** (${finding.cwe}) in \`${finding.filePath}\` on line ${finding.line}.\n\n- **Vulnerability**: ${finding.ruleName}\n- **CWE**: ${finding.cwe}\n- **Severity**: ${finding.severity}\n- **Remediation**: ${fixJson.explanation || finding.remediation}`,
    commitMessage:
      fixJson.commitMessage || `fix(security): sanitize ${finding.sink} in ${path.basename(finding.filePath)}`,
    canCreatePr: Boolean(gh),
    repoOwner: gh?.owner,
    repoName: gh?.repo,
  }
}

/**
 * Pushes fix to branch and opens a GitHub Pull Request
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

  const { owner, repo } = gh
  const cleanBranch = params.branchName
    .replace(/[^a-zA-Z0-9_\-\.\/]/g, '-')
    .replace(/\.+/g, '.')
    .replace(/^\/+|\/+$/g, '')

  // 1. Authenticate with GitHub API to get the user's username
  logger.info(`Authenticating with GitHub API for PR creation on ${owner}/${repo}...`)
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

  // 2. Check repository permissions (Can the user push directly or do we need to fork?)
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
    // Authenticated user doesn't have write access to the upstream repo: fork it!
    logger.info(`User ${authUser} lacks push access to ${owner}/${repo}. Initializing fork...`)
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

    // Wait 2.5 seconds for GitHub to provision the fork
    await new Promise(r => setTimeout(r, 2500))
  }

  // 3. Workspace setup: clone, patch, commit, and push
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-pr-'))
  const cloneUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`
  const pushUrl = `https://x-access-token:${token}@github.com/${pushOwner}/${repo}.git`

  try {
    logger.info(`Cloning ${owner}/${repo} [branch: ${params.targetBranch}] to temporary workspace`)
    await execFileAsync('git', ['clone', '--depth', '1', '-b', params.targetBranch, cloneUrl, tmpDir], {
      timeout: 45000,
    })

    // Configure committer identity
    await execFileAsync('git', ['-C', tmpDir, 'config', 'user.name', authUser])
    await execFileAsync(
      'git',
      ['-C', tmpDir, 'config', 'user.email', userData.email || `${authUser}@users.noreply.github.com`]
    )

    // Checkout new feature branch
    await execFileAsync('git', ['-C', tmpDir, 'checkout', '-b', cleanBranch])

    // Read and patch target file
    const targetFilePath = path.join(tmpDir, params.filePath)
    const originalContent = await fs.readFile(targetFilePath, 'utf-8')

    const { updatedContent, applied } = applySnippetReplacement(
      originalContent,
      params.searchSnippet,
      params.replacementSnippet
    )

    if (!applied || updatedContent === originalContent) {
      throw new Error(
        `Failed to match code snippet in ${params.filePath}. The file may have changed or snippet did not match.`
      )
    }

    await fs.writeFile(targetFilePath, updatedContent, 'utf-8')

    // Commit and push
    await execFileAsync('git', ['-C', tmpDir, 'add', params.filePath])
    await execFileAsync('git', ['-C', tmpDir, 'commit', '-m', params.commitMessage])
    await execFileAsync('git', ['-C', tmpDir, 'remote', 'set-url', 'origin', pushUrl])

    logger.info(`Pushing branch ${cleanBranch} to origin...`)
    await execFileAsync('git', ['-C', tmpDir, 'push', '-u', 'origin', cleanBranch, '--force'], {
      timeout: 30000,
    })
  } finally {
    try {
      await fs.rm(tmpDir, { recursive: true, force: true })
    } catch {}
  }

  // 4. Create Pull Request on the upstream repository
  logger.info(`Opening Pull Request from ${prHead} to ${owner}/${repo}:${params.targetBranch}...`)
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
      body: `${params.prDescription}\n\n---\n*Automated security fix generated by [VulnScan](https://github.com/mohitdevx/vul-scan) AI Engine (${config.aiModel})*`,
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
      message: 'Pull request created successfully!',
    }
  }

  // If status 422: Check if a PR already exists for this branch
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
        }
      }
    }
  }

  const errData = await prRes.text()
  throw new Error(`Failed to create Pull Request: ${errData}`)
}

/**
 * Merges an open GitHub Pull Request
 */
export async function mergeGitHubPullRequest(params: {
  repoUrl: string
  pullNumber: number
  commitTitle?: string
  mergeMethod?: 'merge' | 'squash' | 'rebase'
  githubToken?: string
}): Promise<{ merged: boolean; message: string; sha: string }> {
  const token = params.githubToken || config.githubToken
  if (!token) {
    throw new Error('GitHub token required to merge pull request.')
  }

  const gh = parseGitHubUrl(params.repoUrl)
  if (!gh) {
    throw new Error('Invalid GitHub repository URL.')
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
      commit_title: params.commitTitle || `Merge security fix from VulnScan (PR #${params.pullNumber})`,
      merge_method: params.mergeMethod || 'squash',
    }),
  })

  if (!res.ok) {
    const errText = await res.text()
    if (res.status === 405) {
      throw new Error('Pull Request cannot be merged (branch has conflicts or is already merged).')
    }
    if (res.status === 403) {
      throw new Error('You do not have write/admin permission to merge this Pull Request on this repository.')
    }
    throw new Error(`Failed to merge PR: ${errText}`)
  }

  const data = (await res.json()) as { sha: string; merged: boolean; message: string }
  return {
    merged: data.merged,
    message: data.message,
    sha: data.sha,
  }
}

