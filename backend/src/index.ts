import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { config } from './config/env.js'
import { healthRouter } from './routes/health.routes.js'
import { scanRouter } from './routes/scan.routes.js'
import { authRouter } from './routes/auth.routes.js'
import { repositoryRouter } from './routes/repository.routes.js'
import { errorHandler } from './middlewares/error.middleware.js'
import { logger } from './utils/logger.js'
import { getRedisClient } from './config/redis.js'
import { connectDatabase } from './config/db.js'

const app = express()

// Dynamic CORS configuration accepting localhost and 127.0.0.1 across all dev ports
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5174',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  config.corsOrigin,
].filter(Boolean)

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (curl, mobile apps, server-to-server)
      if (!origin) return callback(null, true)

      // Accept development origins or pattern-matched localhost / 127.0.0.1
      const isAllowed =
        config.nodeEnv === 'development' ||
        allowedOrigins.includes(origin) ||
        /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)

      if (isAllowed) {
        return callback(null, origin) // Echo exact matching origin
      }

      return callback(null, false)
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['Set-Cookie'],
  })
)

// Preflight options handler
app.options('*', cors())

app.use(express.json())
app.use(cookieParser())

// Initialize Database & Redis connections
connectDatabase()
getRedisClient()

// Application routes
app.use('/api/health', healthRouter)
app.use('/api/auth', authRouter)
app.use('/api/scan', scanRouter)
app.use('/api/repositories', repositoryRouter)

// Error handling middleware
app.use(errorHandler)

app.listen(config.port, () => {
  logger.info(`VulnScan Backend server running on port ${config.port} [${config.nodeEnv}]`)
})

export default app
