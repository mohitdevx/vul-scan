import dotenv from 'dotenv'

dotenv.config()

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  githubToken: process.env.GITHUB_TOKEN || '',
  workspaceDir: process.env.WORKSPACE_DIR || './tmp/scans',
  jwtSecret: process.env.JWT_SECRET || 'vulnscan_dev_jwt_secret_change_in_production_key_12345',
}
