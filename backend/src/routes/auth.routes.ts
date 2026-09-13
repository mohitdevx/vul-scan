import { Router } from 'express'
import { getMe, login, logout, signup } from '../controllers/auth.controller.js'
import { requireAuth } from '../middlewares/auth.middleware.js'

export const authRouter = Router()

authRouter.post('/signup', signup)
authRouter.post('/login', login)
authRouter.get('/me', requireAuth, getMe)
authRouter.post('/logout', logout)
