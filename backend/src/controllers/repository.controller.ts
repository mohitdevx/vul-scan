import type { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { prisma } from '../config/db.js'

function normalizeRepoUrl(url: string): string {
  const trimmed = url.trim()
  if (trimmed.startsWith('/')) {
    return `file://${trimmed}`
  }
  return trimmed
}

const addRepoSchema = z.object({
  url: z
    .string()
    .min(1, 'Valid repository URL required')
    .transform(normalizeRepoUrl)
    .refine(
      url =>
        url.startsWith('file://') ||
        url.includes('github.com/') ||
        url.includes('gitlab.com/') ||
        url.includes('bitbucket.org/'),
      'Must be a valid GitHub, GitLab, Bitbucket, or local file repository URL'
    ),
  name: z.string().optional(),
  defaultBranch: z.string().optional().default('main'),
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

export async function listRepositories(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const repositories = await prisma.repository.findMany({
      where: { userId },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 1,
        },
      },
      orderBy: { updatedAt: 'desc' },
    })

    const formatted = repositories.map(repo => {
      const latestScan = repo.scans[0] || null
      return {
        id: repo.id,
        name: repo.name,
        url: repo.url,
        defaultBranch: repo.defaultBranch,
        createdAt: repo.createdAt,
        updatedAt: repo.updatedAt,
        latestScan: latestScan
          ? {
              id: latestScan.id,
              status: latestScan.status,
              findingsCount: latestScan.findingsCount,
              highCount: latestScan.highCount,
              mediumCount: latestScan.mediumCount,
              createdAt: latestScan.createdAt,
            }
          : null,
      }
    })

    res.json({ repositories: formatted })
  } catch (error) {
    next(error)
  }
}

export async function addRepository(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const parsed = addRepoSchema.parse(req.body)
    const repoName = parsed.name || extractRepoName(parsed.url)

    // Upsert or create repository for this user
    const repo = await prisma.repository.upsert({
      where: {
        userId_url: {
          userId,
          url: parsed.url,
        },
      },
      update: {
        name: repoName,
        defaultBranch: parsed.defaultBranch,
        updatedAt: new Date(),
      },
      create: {
        name: repoName,
        url: parsed.url,
        defaultBranch: parsed.defaultBranch,
        userId,
      },
    })

    res.status(201).json({
      message: 'Repository added successfully',
      repository: repo,
    })
  } catch (error) {
    next(error)
  }
}

export async function deleteRepository(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    const { id } = req.params

    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const existing = await prisma.repository.findFirst({
      where: { id, userId },
    })

    if (!existing) {
      res.status(404).json({ error: 'Repository not found' })
      return
    }

    await prisma.repository.delete({
      where: { id },
    })

    res.json({ message: 'Repository deleted successfully', id })
  } catch (error) {
    next(error)
  }
}
