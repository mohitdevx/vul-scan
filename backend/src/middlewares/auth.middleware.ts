import type { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { config } from '../config/env.js'

export interface AuthUserPayload {
  id: string
  email: string
  orgName: string
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUserPayload
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization
  let token: string | undefined

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1]
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token
  }

  if (!token) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Access token required',
    })
    return
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as AuthUserPayload
    req.user = decoded
    next()
  } catch (_err) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired access token',
    })
  }
}
