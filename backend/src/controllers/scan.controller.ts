import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { prisma } from '../config/db.js'
import { logger } from '../utils/logger.js'
import { runSecurityScan, getRemoteBranches, cloneRepoToTemp, type ScanResult } from '../engine/index.js'
import {
  discoverEndpoints,
  auditDiscoveredEndpoints,
  generateRequestlyRuleSuite,
  generateRequestlyMcpBundle,
} from '../engine/api/index.js'
import { checkAiHealth, validateFindingWithAi } from '../services/aiValidator.service.js'
import {
  generateAiFix,
  generateBatchAiFixes,
  createGitHubPullRequest,
  createBatchGitHubPullRequest,
  mergeGitHubPullRequest,
} from '../services/prFix.service.js'

import { generateSecurityReport } from '../reporting/index.js'

const execFileAsync = promisify(execFile)

function normalizeRepoUrl(url: string): string {
  const trimmed = url.trim()
  if (trimmed.startsWith('/')) {
    return `file://${trimmed}`
  }
  return trimmed
}

const triggerScanSchema = z.object({
  repoUrl: z.string().min(1, 'Valid repository URL required').transform(normalizeRepoUrl),
  branch: z.string().optional().default(''),
  allBranches: z.boolean().optional().default(false),
})

function extractRepoName(url: string): string {
  try {
    const parsed = new URL(url)
    const segments = parsed.pathname.replace(/^\/+|\/+$/g, '').split('/')
    if (segments.length >= 2) {
      return segments[1].replace(/\.git$/, '')
    }
    return segments[0] || 'repository'
  } catch {
    const parts = url.split('/')
    return parts[parts.length - 1]?.replace(/\.git$/, '') || 'repository'
  }
}

export async function getRepoBranches(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const rawUrl = String(req.query.url || '').trim()
    if (!rawUrl) {
      res.status(400).json({ error: 'Repository URL is required' })
      return
    }

    const repoUrl = normalizeRepoUrl(rawUrl)

    const { branches, defaultBranch } = await getRemoteBranches(repoUrl)
    res.json({ branches, defaultBranch })
  } catch (error: any) {
    res.status(400).json({
      error: error.message || 'Failed to fetch repository branches. Ensure the repository is public and accessible.',
    })
  }
}

export async function triggerScan(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { repoUrl, branch, allBranches } = triggerScanSchema.parse(req.body)
    const repoName = extractRepoName(repoUrl)
    const requestedBranch = branch?.trim() || ''
    const isAllBranches = allBranches || requestedBranch === '__ALL__' || requestedBranch === '*'

    // Multi-branch scan mode
    if (isAllBranches) {
      logger.info(`Starting multi-branch AST security scan for user ${userId}: ${repoUrl} [ALL BRANCHES]`)

      let targetBranches: string[] = []
      let defaultBranch = 'main'
      try {
        const branchInfo = await getRemoteBranches(repoUrl)
        targetBranches = branchInfo.branches || []
        defaultBranch = branchInfo.defaultBranch || 'main'
      } catch (branchErr: any) {
        logger.warn(`Failed to fetch remote branch list for ${repoUrl}: ${branchErr.message}. Defaulting to main branch.`)
        targetBranches = ['main']
      }

      if (targetBranches.length === 0) {
        targetBranches = [defaultBranch || 'main']
      }

      // Ensure Repository record exists for this user
      let repository = await prisma.repository.findFirst({
        where: { userId, url: repoUrl },
      })

      if (!repository) {
        repository = await prisma.repository.create({
          data: {
            name: repoName,
            url: repoUrl,
            defaultBranch,
            userId,
          },
        })
      } else {
        await prisma.repository.update({
          where: { id: repository.id },
          data: { defaultBranch, updatedAt: new Date() },
        })
      }

      const createdScans: any[] = []
      const branchErrors: string[] = []

      for (const b of targetBranches) {
        try {
          logger.info(`Scanning branch '${b}' for repository ${repoUrl}...`)
          const scanResult = await runSecurityScan(repoUrl, b)
          const finalBranch = scanResult.actualBranch || b
          const findings = scanResult.findings
          const highCount = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length
          const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length
          const lowCount = findings.filter(f => f.severity === 'LOW').length

          const scan = await prisma.scan.create({
            data: {
              repoUrl,
              repoName,
              branch: finalBranch,
              status: 'completed',
              findingsCount: findings.length,
              highCount,
              mediumCount,
              lowCount,
              durationMs: scanResult.durationMs,
              findingsJson: JSON.stringify(findings),
              repositoryId: repository.id,
              userId,
              completedAt: new Date(),
            },
          })

          createdScans.push({
            ...scan,
            findings,
          })
        } catch (bErr: any) {
          logger.error(`Failed to scan branch '${b}' for ${repoUrl}: ${bErr.message}`)
          branchErrors.push(`Branch '${b}': ${bErr.message}`)
        }
      }

      if (createdScans.length === 0 && branchErrors.length > 0) {
        res.status(400).json({
          error: `Failed to scan branches: ${branchErrors.join('; ')}`,
        })
        return
      }

      const primaryScan = createdScans.find(s => s.findingsCount > 0) || createdScans[0]

      res.status(201).json({
        message: `Successfully scanned ${createdScans.length} branch${createdScans.length === 1 ? '' : 'es'}`,
        scan: primaryScan,
        scans: createdScans,
        scannedBranches: targetBranches,
      })
      return
    }

    // Single-branch scan mode
    logger.info(`Starting AST security scan for user ${userId}: ${repoUrl} [${requestedBranch || 'default'}]`)

    // 1. Execute Real AST Security Scan with XSS, SQLi, and CMDi Engines
    let scanResult: ScanResult
    try {
      scanResult = await runSecurityScan(repoUrl, requestedBranch)
    } catch (scanErr: any) {
      logger.error(`Error running AST security scan for ${repoUrl}: ${scanErr.message}`)
      res.status(400).json({
        error: `Failed to clone or analyze repository '${repoName}': ${scanErr.message}`,
      })
      return
    }

    const finalBranch = scanResult.actualBranch || requestedBranch || 'main'

    // 2. Ensure Repository record exists for this user
    let repository = await prisma.repository.findFirst({
      where: { userId, url: repoUrl },
    })

    if (!repository) {
      repository = await prisma.repository.create({
        data: {
          name: repoName,
          url: repoUrl,
          defaultBranch: finalBranch,
          userId,
        },
      })
    } else {
      await prisma.repository.update({
        where: { id: repository.id },
        data: { defaultBranch: finalBranch, updatedAt: new Date() },
      })
    }

    const findings = scanResult.findings
    const highCount = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length
    const lowCount = findings.filter(f => f.severity === 'LOW').length
    const durationMs = scanResult.durationMs

    // 3. Persist scan in Prisma
    const scan = await prisma.scan.create({
      data: {
        repoUrl,
        repoName,
        branch: finalBranch,
        status: 'completed',
        findingsCount: findings.length,
        highCount,
        mediumCount,
        lowCount,
        durationMs,
        findingsJson: JSON.stringify(findings),
        repositoryId: repository.id,
        userId,
        completedAt: new Date(),
      },
    })

    res.status(201).json({
      message: 'Scan completed successfully',
      scan: {
        ...scan,
        findings,
      },
    })
  } catch (error) {
    next(error)
  }
}

export async function listScans(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scans = await prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    })

    const formatted = scans.map(s => ({
      id: s.id,
      repoUrl: s.repoUrl,
      repoName: s.repoName,
      branch: s.branch,
      status: s.status,
      findingsCount: s.findingsCount,
      highCount: s.highCount,
      mediumCount: s.mediumCount,
      lowCount: s.lowCount,
      durationMs: s.durationMs,
      createdAt: s.createdAt,
      completedAt: s.completedAt,
      repositoryId: s.repositoryId,
    }))

    res.json({ scans: formatted })
  } catch (error) {
    next(error)
  }
}

export async function getScanStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
      include: { repository: true },
    })

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    res.json({
      scan: {
        ...scan,
        findings,
      },
    })
  } catch (error) {
    next(error)
  }
}

export async function getDashboardStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const [repoCount, scans] = await Promise.all([
      prisma.repository.count({ where: { userId } }),
      prisma.scan.findMany({
        where: { userId },
        select: {
          findingsCount: true,
          highCount: true,
          mediumCount: true,
          lowCount: true,
          status: true,
        },
      }),
    ])

    const totalScans = scans.length
    const totalHigh = scans.reduce((acc, s) => acc + s.highCount, 0)
    const totalMedium = scans.reduce((acc, s) => acc + s.mediumCount, 0)
    const totalFindings = scans.reduce((acc, s) => acc + s.findingsCount, 0)
    const cleanScans = scans.filter(s => s.findingsCount === 0).length

    res.json({
      stats: {
        totalRepositories: repoCount,
        totalScans,
        totalFindings,
        highSeverity: totalHigh,
        mediumSeverity: totalMedium,
        cleanScans,
      },
    })
  } catch (error) {
    next(error)
  }
}

export async function deleteScan(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    await prisma.scan.delete({
      where: { id },
    })

    res.json({ message: 'Scan deleted successfully', id })
  } catch (error) {
    next(error)
  }
}

export async function deleteAllScans(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const result = await prisma.scan.deleteMany({
      where: { userId },
    })

    res.json({
      message: 'All scan history deleted successfully',
      deletedCount: result.count,
    })
  } catch (error) {
    next(error)
  }
}

export async function deleteFinding(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id, findingId } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings: any[] = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    // Remove the specified finding
    const updatedFindings = findings.filter(f => f.id !== findingId)
    const highCount = updatedFindings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length
    const mediumCount = updatedFindings.filter(f => f.severity === 'MEDIUM').length
    const lowCount = updatedFindings.filter(f => f.severity === 'LOW').length

    const updatedScan = await prisma.scan.update({
      where: { id },
      data: {
        findingsCount: updatedFindings.length,
        highCount,
        mediumCount,
        lowCount,
        findingsJson: JSON.stringify(updatedFindings),
      },
    })

    res.json({
      message: 'Finding deleted successfully',
      scan: {
        ...updatedScan,
        findings: updatedFindings,
      },
    })
  } catch (error) {
    next(error)
  }
}

export async function getRepoScans(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const repoUrl = String(req.query.repoUrl || '').trim()
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scans = await prisma.scan.findMany({
      where: {
        userId,
        ...(repoUrl ? { repoUrl } : {}),
      },
      orderBy: { createdAt: 'desc' },
    })

    const formatted = scans.map(s => {
      let findings = []
      if (s.findingsJson) {
        try {
          findings = JSON.parse(s.findingsJson)
        } catch {
          findings = []
        }
      }
      return {
        ...s,
        findings,
      }
    })

    res.json({ scans: formatted })
  } catch (error) {
    next(error)
  }
}

export async function getAiStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const health = await checkAiHealth()
    res.json(health)
  } catch (error) {
    next(error)
  }
}

export async function revalidateScanWithAi(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings: any[] = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    if (findings.length === 0) {
      res.json({
        message: 'No findings to revalidate',
        scan: {
          ...scan,
          findings: [],
        },
      })
      return
    }

    // Attempt to clone repo to obtain full source context for high-precision verification
    const filesMap = new Map<string, string>()
    let tmpDir = ''

    if (scan.repoUrl && !scan.repoUrl.startsWith('file://')) {
      try {
        tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vulscan-reverify-'))
        const activeBranch = scan.branch || 'main'
        try {
          await execFileAsync('git', ['clone', '--depth', '1', '-b', activeBranch, scan.repoUrl, tmpDir], {
            timeout: 30000,
          })
        } catch {
          await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {})
          await fs.mkdir(tmpDir, { recursive: true }).catch(() => {})
          await execFileAsync('git', ['clone', '--depth', '1', scan.repoUrl, tmpDir], {
            timeout: 30000,
          })
        }

        for (const f of findings) {
          if (f.filePath) {
            try {
              const fullPath = path.join(tmpDir, f.filePath)
              const content = await fs.readFile(fullPath, 'utf-8')
              filesMap.set(f.filePath, content)
            } catch {
              // Ignore missing single file
            }
          }
        }
      } catch (cloneErr: any) {
        logger.warn(`[Reverify] Could not clone repository for full context: ${cloneErr.message}. Utilizing synthetic snippet context.`)
      } finally {
        if (tmpDir) {
          fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {})
        }
      }
    }

    const updatedFindings = []
    for (const f of findings) {
      let fileContent = filesMap.get(f.filePath)
      if (!fileContent) {
        // Construct a synthetic file context placing the snippet accurately at the reported line
        const snippetLines = (f.snippet || '').split('\n')
        const targetLine = Math.max(1, f.line || 1)
        const dummyLines = new Array(targetLine - 1).fill('// ...')
        dummyLines.push(...snippetLines)
        fileContent = dummyLines.join('\n')
      }

      const triage = await validateFindingWithAi(f, fileContent)
      updatedFindings.push({
        ...f,
        aiAnalysis: triage,
      })
    }

    const updatedScan = await prisma.scan.update({
      where: { id },
      data: {
        findingsJson: JSON.stringify(updatedFindings),
      },
    })

    res.json({
      message: 'AI verification completed successfully',
      scan: {
        ...updatedScan,
        findings: updatedFindings,
      },
    })
  } catch (error) {
    next(error)
  }
}

const createPrSchema = z.object({
  githubToken: z.string().optional(),
  targetBranch: z.string().min(1, 'Target branch required'),
  branchName: z.string().min(1, 'New branch name required'),
  filePath: z.string().min(1, 'File path required'),
  searchSnippet: z.string().min(1, 'Search snippet required'),
  replacementSnippet: z.string().min(1, 'Replacement snippet required'),
  commitMessage: z.string().min(1, 'Commit message required'),
  prTitle: z.string().min(1, 'PR title required'),
  prDescription: z.string().min(1, 'PR description required'),
})

export async function generateFindingFix(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id, findingId } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings: any[] = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    const finding = findings.find(f => f.id === findingId)
    if (!finding) {
      res.status(404).json({ error: 'Finding not found in this scan' })
      return
    }

    logger.info(`Generating AI fix for finding ${findingId} (${finding.ruleName}) in scan ${id}...`)
    const proposal = await generateAiFix(scan.repoUrl, scan.branch, finding)

    res.json({
      message: 'Fix generated successfully',
      proposal,
    })
  } catch (error: any) {
    logger.error(`Error generating fix: ${error.message}`)
    res.status(500).json({ error: error.message || 'Failed to generate fix with AI' })
  }
}

export async function createFindingPr(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id, findingId } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    const body = createPrSchema.parse(req.body)
    let githubToken: string | undefined = body.githubToken || (req.headers['x-github-token'] as string)
    if (!githubToken) {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { githubAccessToken: true },
      })
      githubToken = user?.githubAccessToken || undefined
    }

    logger.info(`Opening Pull Request for scan ${id} finding ${findingId} on ${scan.repoUrl}...`)
    const result = await createGitHubPullRequest({
      repoUrl: scan.repoUrl,
      targetBranch: body.targetBranch,
      branchName: body.branchName,
      filePath: body.filePath,
      searchSnippet: body.searchSnippet,
      replacementSnippet: body.replacementSnippet,
      commitMessage: body.commitMessage,
      prTitle: body.prTitle,
      prDescription: body.prDescription,
      githubToken,
    })

    if (scan.findingsJson) {
      try {
        const parsedFindings = JSON.parse(scan.findingsJson)
        const updated = parsedFindings.map((f: any) => {
          if (f.id === findingId) {
            return {
              ...f,
              pr: {
                prNumber: result.prNumber,
                prUrl: result.prUrl,
                branch: result.branch,
                state: 'open',
              },
            }
          }
          return f
        })
        await prisma.scan.update({
          where: { id: scan.id },
          data: { findingsJson: JSON.stringify(updated) },
        })
      } catch (e: any) {
        logger.warn(`Failed to update findingsJson with PR details: ${e.message}`)
      }
    }

    res.json({
      message: result.message,
      result,
    })
  } catch (error: any) {
    logger.error(`Error creating pull request: ${error.message}`)
    res.status(400).json({ error: error.message || 'Failed to create GitHub Pull Request' })
  }
}

const generateBatchFixSchema = z.object({
  findingIds: z.array(z.string()).optional(),
})

export async function generateBatchFixes(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings: any[] = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    const body = generateBatchFixSchema.parse(req.body || {})
    let targetFindings = findings

    if (body.findingIds && body.findingIds.length > 0) {
      const idSet = new Set(body.findingIds)
      targetFindings = findings.filter(f => idSet.has(f.id))
    } else {
      // Default: remediate all confirmed non-false-positive findings
      targetFindings = findings.filter(f => !f.aiAnalysis?.isFalsePositive)
      if (targetFindings.length === 0) {
        targetFindings = findings
      }
    }

    if (targetFindings.length === 0) {
      res.status(400).json({ error: 'No security findings available to remediate.' })
      return
    }

    logger.info(`Generating batch AI fixes for ${targetFindings.length} findings in scan ${id}...`)
    const proposal = await generateBatchAiFixes(scan.repoUrl, scan.branch, targetFindings)

    res.json({
      message: `Generated fix proposal for ${proposal.totalFindings} vulnerabilities`,
      proposal,
    })
  } catch (error: any) {
    logger.error(`Error generating batch fixes: ${error.message}`)
    res.status(500).json({ error: error.message || 'Failed to generate batch fixes with AI' })
  }
}

const createBatchPrSchema = z.object({
  targetBranch: z.string().min(1, 'Target branch required'),
  branchName: z.string().min(1, 'Branch name required'),
  patches: z
    .array(
      z.object({
        findingId: z.string().min(1),
        filePath: z.string().min(1),
        line: z.number().optional(),
        searchSnippet: z.string().min(1),
        replacementSnippet: z.string(),
      })
    )
    .min(1, 'At least one file patch is required'),
  commitMessage: z.string().min(1, 'Commit message required'),
  prTitle: z.string().min(1, 'PR title required'),
  prDescription: z.string().min(1, 'PR description required'),
  githubToken: z.string().optional(),
})

export async function createBatchPr(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    const body = createBatchPrSchema.parse(req.body)
    let githubToken: string | undefined = body.githubToken || (req.headers['x-github-token'] as string)
    if (!githubToken) {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { githubAccessToken: true },
      })
      githubToken = user?.githubAccessToken || undefined
    }

    logger.info(
      `Opening batch Pull Request for scan ${id} covering ${body.patches.length} patches on ${scan.repoUrl}...`
    )
    const result = await createBatchGitHubPullRequest({
      repoUrl: scan.repoUrl,
      targetBranch: body.targetBranch,
      branchName: body.branchName,
      patches: body.patches,
      commitMessage: body.commitMessage,
      prTitle: body.prTitle,
      prDescription: body.prDescription,
      githubToken,
    })

    if (scan.findingsJson) {
      try {
        const parsedFindings = JSON.parse(scan.findingsJson)
        const fixedSet = new Set(result.fixedFindingIds || body.patches.map(p => p.findingId))
        const updated = parsedFindings.map((f: any) => {
          if (fixedSet.has(f.id)) {
            return {
              ...f,
              pr: {
                prNumber: result.prNumber,
                prUrl: result.prUrl,
                branch: result.branch,
                state: 'open',
              },
            }
          }
          return f
        })
        await prisma.scan.update({
          where: { id: scan.id },
          data: { findingsJson: JSON.stringify(updated) },
        })
      } catch (e: any) {
        logger.warn(`Failed to update findingsJson with batch PR details: ${e.message}`)
      }
    }

    res.json({
      message: result.message,
      result,
    })
  } catch (error: any) {
    logger.error(`Error creating batch pull request: ${error.message}`)
    res.status(400).json({ error: error.message || 'Failed to create batch GitHub Pull Request' })
  }
}


const mergePrSchema = z.object({
  pullNumber: z.number().int().positive('Pull number required'),
  mergeMethod: z.enum(['merge', 'squash', 'rebase']).optional().default('squash'),
})

export async function mergeFindingPr(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    const body = mergePrSchema.parse(req.body)

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { githubAccessToken: true },
    })
    const githubToken = user?.githubAccessToken || (req.headers['x-github-token'] as string)

    logger.info(`Merging Pull Request #${body.pullNumber} for scan ${id}...`)
    const result = await mergeGitHubPullRequest({
      repoUrl: scan.repoUrl,
      pullNumber: body.pullNumber,
      mergeMethod: body.mergeMethod,
      githubToken,
    })

    res.json(result)
  } catch (error: any) {
    logger.error(`Error merging pull request: ${error.message}`)
    res.status(400).json({ error: error.message || 'Failed to merge GitHub Pull Request' })
  }
}

export async function exportScanReport(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params
    const format = (req.query.format as string || 'html').toLowerCase()

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
      include: { repository: true },
    })

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    let findings = []
    if (scan.findingsJson) {
      try {
        findings = JSON.parse(scan.findingsJson)
      } catch {
        findings = []
      }
    }

    const reportOutput = generateSecurityReport({
      id: scan.id,
      repoName: scan.repoName || scan.repository?.name,
      repoUrl: scan.repoUrl,
      branch: scan.branch,
      durationMs: scan.durationMs,
      createdAt: scan.createdAt,
      findings,
    })

    const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')
    const sanitizedBranch = scan.branch.replace(/[^a-zA-Z0-9_-]/g, '_')

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8')
      res.setHeader('Content-Disposition', `attachment; filename="vulscan-report-${sanitizedRepo}-${sanitizedBranch}.json"`)
      res.send(reportOutput.json)
      return
    }

    if (format === 'markdown' || format === 'md') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8')
      res.setHeader('Content-Disposition', `attachment; filename="vulscan-report-${sanitizedRepo}-${sanitizedBranch}.md"`)
      res.send(reportOutput.markdown)
      return
    }

    // Default to HTML
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.setHeader('Content-Disposition', `inline; filename="vulscan-report-${sanitizedRepo}-${sanitizedBranch}.html"`)
    res.send(reportOutput.html)
  } catch (error) {
    next(error)
  }
}

export async function auditScanApiEndpoints(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { id } = req.params
    let repoUrl = req.body?.repoUrl
    let branch = req.body?.branch
    const targetBaseUrl = req.body?.targetBaseUrl || 'http://localhost:3000'

    if (id) {
      const scan = await prisma.scan.findFirst({
        where: { id, userId },
      })
      if (scan) {
        repoUrl = scan.repoUrl
        branch = scan.branch
      }
    }

    if (!repoUrl) {
      res.status(400).json({ error: 'Repository URL is required for API security audit' })
      return
    }

    logger.info(`Starting API Endpoint Discovery and Logical Security Audit for ${repoUrl} [branch: ${branch || 'default'}]`)

    const { tmpDir, activeBranch, cleanup } = await cloneRepoToTemp(repoUrl, branch)

    try {
      const discovery = await discoverEndpoints(tmpDir)
      logger.info(
        `Discovered ${discovery.endpoints.length} API endpoints across ${discovery.totalFilesScanned} files (${discovery.frameworks.join(', ')})`
      )

      const auditResults = await auditDiscoveredEndpoints(discovery.endpoints, {
        aiAnalysis: true,
      })

      const requestlySuite = generateRequestlyRuleSuite(discovery.endpoints, {
        baseUrl: targetBaseUrl,
        ruleGroupName: `VulScan API Security - ${extractRepoName(repoUrl)}`,
      })

      const mcpBundle = generateRequestlyMcpBundle(requestlySuite)

      res.json({
        success: true,
        repoUrl,
        branch: activeBranch,
        totalEndpoints: discovery.endpoints.length,
        frameworks: discovery.frameworks,
        totalFilesScanned: discovery.totalFilesScanned,
        endpoints: discovery.endpoints,
        findings: auditResults.findings,
        summary: auditResults.summary,
        requestlySuite,
        mcpBundle,
      })
    } finally {
      await cleanup()
    }
  } catch (error: any) {
    logger.error(`API testing audit failed: ${error.message}`)
    next(error)
  }
}

export async function exportScanRequestlyRules(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { id } = req.params
    const targetBaseUrl = (req.query.baseUrl as string) || 'http://localhost:3000'
    const format = ((req.query.format as string) || 'rules').toLowerCase()

    const scan = await prisma.scan.findFirst({
      where: { id, userId },
    })

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' })
      return
    }

    const { tmpDir, cleanup } = await cloneRepoToTemp(scan.repoUrl, scan.branch)

    try {
      const discovery = await discoverEndpoints(tmpDir)
      const auditResults = await auditDiscoveredEndpoints(discovery.endpoints, { aiAnalysis: false })
      const requestlySuite = generateRequestlyRuleSuite(discovery.endpoints, {
        baseUrl: targetBaseUrl,
        ruleGroupName: `VulScan API Security - ${scan.repoName || 'Repo'}`,
      })

      const sanitizedRepo = (scan.repoName || 'repo').replace(/[^a-zA-Z0-9_-]/g, '_')

      if (format === 'mcp' || format === 'vscode') {
        const mcpBundle = generateRequestlyMcpBundle(requestlySuite)
        res.setHeader('Content-Type', 'application/json; charset=utf-8')
        res.setHeader('Content-Disposition', `attachment; filename="requestly-mcp-config-${sanitizedRepo}.json"`)
        res.json(mcpBundle.vscodeMcpConfig)
        return
      }

      res.setHeader('Content-Type', 'application/json; charset=utf-8')
      res.setHeader('Content-Disposition', `attachment; filename="requestly-rules-${sanitizedRepo}.json"`)
      res.json(requestlySuite)
    } finally {
      await cleanup()
    }
  } catch (error: any) {
    next(error)
  }
}


