import { Redis } from 'ioredis'
import { config } from './env.js'
import { logger } from '../utils/logger.js'

let redisClient: Redis | null = null

export function getRedisClient(): Redis | null {
  if (redisClient) {
    return redisClient
  }

  try {
    redisClient = new Redis(config.redisUrl, {
      maxRetriesPerRequest: 2,
      retryStrategy(times) {
        if (times > 3) {
          return null // Stop retrying if Redis is not available
        }
        return Math.min(times * 100, 2000)
      },
      lazyConnect: true,
    })

    redisClient.on('connect', () => {
      logger.info(`Redis client connected to ${config.redisUrl}`)
    })

    redisClient.on('error', (err) => {
      logger.warn(`Redis connection warning: ${err.message}`)
    })

    // Attempt initial connect without blocking startup
    redisClient.connect().catch((err) => {
      logger.warn(`Initial Redis connection skipped: ${err.message}`)
    })

    return redisClient
  } catch (error: any) {
    logger.warn(`Failed to initialize Redis: ${error.message}`)
    return null
  }
}
