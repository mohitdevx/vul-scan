import dotenv from 'dotenv'

dotenv.config()

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://vulnscan:my_secret_password@localhost:5432/vulnscan?schema=public',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  githubToken: process.env.GITHUB_TOKEN || '',
  workspaceDir: process.env.WORKSPACE_DIR || './tmp/scans',
  jwtSecret: process.env.JWT_SECRET || 'vulnscan_dev_jwt_secret_change_in_production_key_12345',
  ollamaBaseUrl: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
  aiModel: process.env.AI_MODEL || 'qwen2.5-coder:1.5b',
  aiValidationEnabled: process.env.AI_VALIDATION_ENABLED !== 'false',
}
