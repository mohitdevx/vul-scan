import { Router } from 'express'
import {
  getGitHubStatus,
  connectGitHub,
  disconnectGitHub,
  getOAuthUrl,
  handleOAuthCallback,
} from '../controllers/github.controller.js'
import { requireAuth } from '../middlewares/auth.middleware.js'

export const githubRouter = Router()

githubRouter.use(requireAuth)
githubRouter.get('/status', getGitHubStatus)
githubRouter.get('/oauth/url', getOAuthUrl)
githubRouter.post('/oauth/callback', handleOAuthCallback)
githubRouter.post('/connect', connectGitHub)
githubRouter.delete('/disconnect', disconnectGitHub)

