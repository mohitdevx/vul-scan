import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { parseSourceCode } from './parser.js'
import { masterEngine } from './masterEngine.js'
import type { Finding, ScanResult, EngineContext } from './types.js'
import { logger } from '../utils/logger.js'
import { config } from '../config/env.js'
import { validateFindingsBatch } from '../services/aiValidator.service.js'

const execFileAsync = promisify(execFile)

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'coverage',
  'vendor',
  '.turbo',
  '.husky',
  'fixtures',
  'fixture',
])

const VALID_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'])

export async function getRemoteBranches(repoUrl: string): Promise<{ branches: string[]; defaultBranch: string }> {
  try {
    // 1. Get HEAD symref for default branch
    let defaultBranch = 'main'
    try {
      const { stdout: symrefOut } = await execFileAsync('git', ['ls-remote', '--symref', repoUrl, 'HEAD'], {
        timeout: 10000,
      })
      const match = symrefOut.match(/ref:\s+refs\/heads\/([^\s]+)\s+HEAD/)
      if (match && match[1]) {
        defaultBranch = match[1]
      }
    } catch (e: any) {
      logger.debug(`Could not resolve default branch via symref: ${e.message}`)
    }

    // 2. Get all remote branches
    const { stdout: headsOut } = await execFileAsync('git', ['ls-remote', '--heads', repoUrl], {
      timeout: 15000,
    })

    const branchList: string[] = []
    const lines = headsOut.split('\n')
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        const ref = parts[1]
        if (ref.startsWith('refs/heads/')) {
          branchList.push(ref.replace('refs/heads/', ''))
        }
      }
    }

    // Ensure defaultBranch is in list and at the top
    if (!branchList.includes(defaultBranch)) {
      branchList.unshift(defaultBranch)
    } else {
      branchList.sort((a, b) => {
        if (a === defaultBranch) return -1
        if (b === defaultBranch) return 1
        return a.localeCompare(b)
      })
    }

    return {
      branches: branchList.length > 0 ? branchList : [defaultBranch],
      defaultBranch,
    }
  } catch (error: any) {
    logger.error(`Failed to fetch branches from git repository ${repoUrl}: ${error.message}`)
    throw new Error(`Unable to fetch remote branches from ${repoUrl}: ${error.message}`)
  }
}

async function collectFiles(dir: string, baseDir: string): Promise<string[]> {
  const result: string[] = []
  const entries = await fs.readdir(dir, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    const relPath = path.relative(baseDir, fullPath)

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        const subFiles = await collectFiles(fullPath, baseDir)
        result.push(...subFiles)
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase()
      if (VALID_EXTENSIONS.has(ext) && !entry.name.endsWith('.d.ts') && !entry.name.endsWith('.min.js')) {
        result.push(fullPath)
      }
    }
  }

  return result
}

export async function runSecurityScan(repoUrl: string, branch: string = 'main'): Promise<ScanResult> {
  const startTime = Date.now()
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-engine-'))

  try {
    logger.info(`Cloning repository ${repoUrl} [branch: ${branch}] for AST analysis into ${tmpDir}`)

    // Shallow clone target branch
    await execFileAsync('git', ['clone', '--depth', '1', '-b', branch, repoUrl, tmpDir], {
      timeout: 45000,
    })

    const targetFiles = await collectFiles(tmpDir, tmpDir)
    logger.info(`Collected ${targetFiles.length} JavaScript/TypeScript files for AST analysis`)

    let allFindings: Finding[] = []
    const filesMap = new Map<string, string>()
    let scannedFilesCount = 0

    for (const filePath of targetFiles) {
      scannedFilesCount++
      const relPath = path.relative(tmpDir, filePath)

      try {
        const fileContent = await fs.readFile(filePath, 'utf-8')
        filesMap.set(relPath, fileContent)
        const lines = fileContent.split('\n')

        const ast = parseSourceCode(fileContent, filePath)
        if (!ast) continue

        const ctx: EngineContext = {
          filePath: relPath,
          fileContent,
          lines,
        }

        const findings = masterEngine.analyze(ast, ctx)
        allFindings.push(...findings)
      } catch (err: any) {
        logger.debug(`Error analyzing file ${relPath}: ${err.message}`)
      }
    }

    logger.info(
      `AST Pattern scan finished with ${allFindings.length} preliminary findings across ${scannedFilesCount} files.`
    )

    // AI Validation Tier: Verify findings against business logic using local Qwen 2.5 Coder
    let aiConfirmedCount = 0
    let aiFalsePositiveCount = 0

    if (config.aiValidationEnabled && allFindings.length > 0) {
      logger.info(`Dispatching ${allFindings.length} findings to AI Validation Pipeline (${config.aiModel})...`)
      try {
        allFindings = await validateFindingsBatch(allFindings, filesMap, 2)
        aiConfirmedCount = allFindings.filter(f => f.aiAnalysis?.verdict === 'CONFIRMED_VULNERABILITY').length
        aiFalsePositiveCount = allFindings.filter(f => f.aiAnalysis?.isFalsePositive).length
      } catch (aiErr: any) {
        logger.warn(`AI validation pipeline encountered an issue: ${aiErr.message}. Continuing with AST findings.`)
      }
    }

    const durationMs = Date.now() - startTime
    logger.info(
      `Scan complete for ${repoUrl}: ${allFindings.length} total findings (${aiConfirmedCount} confirmed, ${aiFalsePositiveCount} false-positives) in ${durationMs}ms`
    )

    return {
      findings: allFindings,
      scannedFilesCount,
      durationMs,
      aiValidated: config.aiValidationEnabled,
      aiConfirmedCount,
      aiFalsePositiveCount,
    }
  } finally {
    // Clean up temporary workspace directory
    try {
      await fs.rm(tmpDir, { recursive: true, force: true })
    } catch (e: any) {
      logger.warn(`Failed to clean up temp dir ${tmpDir}: ${e.message}`)
    }
  }
}
