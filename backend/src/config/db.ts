import { PrismaClient } from '@prisma/client'
import { logger } from '../utils/logger.js'

export const prisma = new PrismaClient()

export async function connectDatabase(): Promise<boolean> {
  try {
    await prisma.$connect()
    logger.info('[Database] Connected successfully to PostgreSQL')
    return true
  } catch (error: any) {
    logger.error(`[Database] Failed to connect to PostgreSQL: ${error.message}`)
    return false
  }
}