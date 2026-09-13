import express from 'express'
import cors from 'cors'
import { config } from './config/env.js'
import { healthRouter } from './routes/health.routes.js'
import { scanRouter } from './routes/scan.routes.js'
import { errorHandler } from './middlewares/error.middleware.js'
import { logger } from './utils/logger.js'

const app = express()

app.use(
  cors({
    origin: config.corsOrigin,
    credentials: true,
  })
)
app.use(express.json())

// Application routes
app.use('/api/health', healthRouter)
app.use('/api/scan', scanRouter)

// Error handling middleware
app.use(errorHandler)

app.listen(config.port, () => {
  logger.info(`VulnScan Backend server running on port ${config.port} [${config.nodeEnv}]`)
})

export default app
