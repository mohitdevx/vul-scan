import { Router } from 'express'
import {
  triggerScan,
  listScans,
  getScanStatus,
  getDashboardStats,
  getRepoBranches,
  deleteScan,
  deleteAllScans,
  deleteFinding,
  getRepoScans,
  getAiStatus,
  revalidateScanWithAi,
  generateFindingFix,
  generateBatchFixes,
  createFindingPr,
  createBatchPr,
  mergeFindingPr,
  exportScanReport,
  auditScanApiEndpoints,
  exportScanRequestlyRules,
} from '../controllers/scan.controller.js'
import { requireAuth } from '../middlewares/auth.middleware.js'

export const scanRouter = Router()

// Public endpoint for fetching repository branches (supports both homepage & dashboard)
scanRouter.get('/branches', getRepoBranches)

// Authenticated endpoints
scanRouter.use(requireAuth)
scanRouter.get('/ai-status', getAiStatus)
scanRouter.get('/stats', getDashboardStats)
scanRouter.get('/repo-scans', getRepoScans)
scanRouter.get('/', listScans)
scanRouter.post('/', triggerScan)
scanRouter.post('/api-test', auditScanApiEndpoints)
scanRouter.delete('/', deleteAllScans)
scanRouter.get('/:id', getScanStatus)
scanRouter.get('/:id/report', exportScanReport)
scanRouter.post('/:id/api-test', auditScanApiEndpoints)
scanRouter.get('/:id/requestly-rules', exportScanRequestlyRules)
scanRouter.post('/:id/ai-revalidate', revalidateScanWithAi)
scanRouter.post('/:id/generate-batch-fix', generateBatchFixes)
scanRouter.post('/:id/create-batch-pr', createBatchPr)
scanRouter.post('/:id/findings/:findingId/generate-fix', generateFindingFix)
scanRouter.post('/:id/findings/:findingId/create-pr', createFindingPr)
scanRouter.post('/:id/merge-pr', mergeFindingPr)
scanRouter.delete('/:id', deleteScan)
scanRouter.delete('/:id/findings/:findingId', deleteFinding)

