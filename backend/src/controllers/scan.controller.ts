import type { Request, Response, NextFunction } from 'express'
import { logger } from '../utils/logger.js'

export async function triggerScan(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { repoUrl, branch } = req.body
    logger.info(`Received scan request for repo: ${repoUrl}, branch: ${branch || 'default'}`)

    res.status(202).json({
      message: 'Scan triggered successfully',
      scanId: 'placeholder-scan-id',
      status: 'pending',
    })
  } catch (error) {
    next(error)
  }
}

export async function getScanStatus(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const { id } = req.params
    res.json({
      scanId: id,
      status: 'pending',
      findings: [],
    })
  } catch (error) {
    next(error)
  }
}
