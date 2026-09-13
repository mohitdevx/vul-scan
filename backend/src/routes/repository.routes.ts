import { Router } from 'express'
import {
  listRepositories,
  addRepository,
  deleteRepository,
} from '../controllers/repository.controller.js'
import { requireAuth } from '../middlewares/auth.middleware.js'

export const repositoryRouter = Router()

repositoryRouter.use(requireAuth)

repositoryRouter.get('/', listRepositories)
repositoryRouter.post('/', addRepository)
repositoryRouter.delete('/:id', deleteRepository)
