import type { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { prisma } from '../config/db.js'
import { logger } from '../utils/logger.js'
import { config } from '../config/env.js'
import crypto from 'node:crypto'

const connectSchema = z.object({
  token: z.string().min(1, 'GitHub token is required'),
})

export async function getGitHubStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        githubAccessToken: true,
        githubUsername: true,
        githubAvatarUrl: true,
      },
    })

    if (!user || !user.githubAccessToken) {
      res.json({
        connected: false,
        username: null,
        avatarUrl: null,
      })
      return
    }

    // Verify token is still valid with GitHub
    try {
      const ghRes = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${user.githubAccessToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'VulnScan-Bot/1.0',
        },
      })

      if (!ghRes.ok) {
        // Token expired or revoked
        await prisma.user.update({
          where: { id: userId },
          data: {
            githubAccessToken: null,
            githubUsername: null,
            githubAvatarUrl: null,
          },
        })
        res.json({
          connected: false,
          username: null,
          avatarUrl: null,
          warning: 'Previous GitHub authorization expired or was revoked.',
        })
        return
      }

      const ghData = (await ghRes.json()) as { login: string; avatar_url: string }
      res.json({
        connected: true,
        username: ghData.login || user.githubUsername,
        avatarUrl: ghData.avatar_url || user.githubAvatarUrl,
      })
    } catch {
      // In case of network error, return cached status
      res.json({
        connected: true,
        username: user.githubUsername,
        avatarUrl: user.githubAvatarUrl,
      })
    }
  } catch (error) {
    next(error)
  }
}

export async function connectGitHub(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { token } = connectSchema.parse(req.body)

    logger.info(`Verifying GitHub token for user ${userId}...`)
    const ghRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${token.trim()}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'VulnScan-Bot/1.0',
      },
    })

    if (!ghRes.ok) {
      if (ghRes.status === 401) {
        res.status(400).json({ error: 'Invalid GitHub token. Please verify token permissions and validity.' })
        return
      }
      res.status(400).json({ error: `GitHub verification failed: ${ghRes.statusText}` })
      return
    }

    const ghData = (await ghRes.json()) as { login: string; avatar_url: string }

    await prisma.user.update({
      where: { id: userId },
      data: {
        githubAccessToken: token.trim(),
        githubUsername: ghData.login,
        githubAvatarUrl: ghData.avatar_url,
      },
    })

    logger.info(`User ${userId} successfully linked GitHub account @${ghData.login}`)

    res.json({
      message: `Successfully authorized as @${ghData.login}`,
      connected: true,
      username: ghData.login,
      avatarUrl: ghData.avatar_url,
    })
  } catch (error) {
    next(error)
  }
}

export async function disconnectGitHub(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        githubAccessToken: null,
        githubUsername: null,
        githubAvatarUrl: null,
      },
    })

    res.json({
      message: 'GitHub authorization disconnected',
      connected: false,
    })
  } catch (error) {
    next(error)
  }
}

export async function getOAuthUrl(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    let clientId = (config.githubClientId || '').trim()
    // Sanitize accidental leading char if user copied "aOv23..." instead of "Ov23..."
    if (clientId.startsWith('aOv23')) {
      clientId = clientId.substring(1)
    }

    if (!clientId) {
      res.json({
        configured: false,
        message: 'GitHub OAuth Client ID not configured on the server.',
      })
      return
    }

    const redirectUri = `${config.corsOrigin}/github/callback`
    const scope = 'repo read:user'
    const state = crypto.randomUUID()
    const url = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(
      redirectUri
    )}&scope=${encodeURIComponent(scope)}&state=${state}`

    logger.info(`Generated GitHub OAuth redirect URL for Client ID: ${clientId}`)

    res.json({
      configured: true,
      url,
      clientId,
      redirectUri,
    })
  } catch (error) {
    next(error)
  }
}

const callbackSchema = z.object({
  code: z.string().min(1, 'Authorization code required'),
})

export async function handleOAuthCallback(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user?.id
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { code } = callbackSchema.parse(req.body)

    let clientId = (config.githubClientId || '').trim()
    if (clientId.startsWith('aOv23')) {
      clientId = clientId.substring(1)
    }

    if (!clientId || !config.githubClientSecret) {
      res.status(500).json({ error: 'GitHub OAuth is not configured on the server.' })
      return
    }

    logger.info(`Exchanging OAuth code with GitHub for user ${userId}...`)
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'VulnScan-Bot/1.0',
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: config.githubClientSecret.trim(),
        code,
      }),
    })

    if (!tokenRes.ok) {
      throw new Error(`GitHub token exchange failed (${tokenRes.status})`)
    }

    const tokenData = (await tokenRes.json()) as { access_token?: string; error?: string; error_description?: string }
    if (tokenData.error || !tokenData.access_token) {
      throw new Error(tokenData.error_description || tokenData.error || 'Failed to obtain access token from GitHub')
    }

    const accessToken = tokenData.access_token

    // Fetch user profile from GitHub
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'VulnScan-Bot/1.0',
      },
    })

    if (!userRes.ok) {
      throw new Error('Failed to retrieve GitHub user profile')
    }

    const userData = (await userRes.json()) as { login: string; avatar_url: string }

    await prisma.user.update({
      where: { id: userId },
      data: {
        githubAccessToken: accessToken,
        githubUsername: userData.login,
        githubAvatarUrl: userData.avatar_url,
      },
    })

    logger.info(`User ${userId} successfully authorized via OAuth as @${userData.login}`)

    res.json({
      message: `Successfully connected GitHub as @${userData.login}`,
      connected: true,
      username: userData.login,
      avatarUrl: userData.avatar_url,
    })
  } catch (error: any) {
    logger.error(`OAuth callback error: ${error.message}`)
    res.status(400).json({ error: error.message || 'GitHub OAuth authorization failed' })
  }
}

