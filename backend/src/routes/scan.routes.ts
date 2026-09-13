import { Router } from 'express'
import {
  triggerScan,
  listScans,
  getScanStatus,
  getDashboardStats,
  getRepoBranches,
} from '../controllers/scan.controller.js'
import { requireAuth } from '../middlewares/auth.middleware.js'

export const scanRouter = Router()

// Public endpoint for fetching repository branches (supports both homepage & dashboard)
scanRouter.get('/branches', getRepoBranches)

// Authenticated endpoints
scanRouter.use(requireAuth)
scanRouter.get('/stats', getDashboardStats)
scanRouter.get('/', listScans)
scanRouter.post('/', triggerScan)
scanRouter.get('/:id', getScanStatus)
