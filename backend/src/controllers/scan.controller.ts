import type { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { prisma } from '../config/db.js'
import { logger } from '../utils/logger.js'
import { runSecurityScan, getRemoteBranches, type ScanResult } from '../engine/index.js'

function normalizeRepoUrl(url: string): string {
  const trimmed = url.trim()
  if (trimmed.startsWith('/')) {
    return `file://${trimmed}`
  }
  return trimmed
}

const triggerScanSchema = z.object({
  repoUrl: z.string().min(1, 'Valid repository URL required').transform(normalizeRepoUrl),
  branch: z.string().optional().default('main'),
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

    const { repoUrl, branch } = triggerScanSchema.parse(req.body)
    const repoName = extractRepoName(repoUrl)
    const scanBranch = branch || 'main'

    logger.info(`Starting AST security scan for user ${userId}: ${repoUrl} [${scanBranch}]`)

    // 1. Ensure Repository record exists for this user
    let repository = await prisma.repository.findFirst({
      where: { userId, url: repoUrl },
    })

    if (!repository) {
      repository = await prisma.repository.create({
        data: {
          name: repoName,
          url: repoUrl,
          defaultBranch: scanBranch,
          userId,
        },
      })
    } else {
      await prisma.repository.update({
        where: { id: repository.id },
        data: { defaultBranch: scanBranch, updatedAt: new Date() },
      })
    }

    // 2. Execute Real AST Security Scan with XSS, SQLi, and CMDi Engines
    let scanResult: ScanResult
    try {
      scanResult = await runSecurityScan(repoUrl, scanBranch)
    } catch (scanErr: any) {
      logger.error(`Error running AST security scan for ${repoUrl}: ${scanErr.message}`)
      res.status(400).json({
        error: `Failed to clone or analyze repository '${repoName}' on branch '${scanBranch}': ${scanErr.message}`,
      })
      return
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
        branch: scanBranch,
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
