import dotenv from 'dotenv'

dotenv.config()

export const config = {
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://vulnscan:my_secret_password@localhost:5432/vulnscan?schema=public',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  githubToken: process.env.GITHUB_TOKEN || '',
  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  workspaceDir: process.env.WORKSPACE_DIR || './tmp/scans',
  jwtSecret: process.env.JWT_SECRET || 'vulnscan_dev_jwt_secret_change_in_production_key_12345',
  
  // Universal AI Provider Configuration:
  // Works with ChatGPT (OpenAI), DeepSeek, NVIDIA NIM, Groq, OpenRouter, and Ollama.
  // Set AI_BASE_URL (or OLLAMA_BASE_URL) to switch models/providers instantly.
  aiBaseUrl: (process.env.AI_BASE_URL || process.env.AI_API_BASE_URL || process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').trim(),
  aiApiKey: (process.env.AI_API_KEY || process.env.OPENAI_API_KEY || process.env.DEEPSEEK_API_KEY || process.env.NVIDIA_API_KEY || process.env.GROQ_API_KEY || '').trim(),
  aiModel: (process.env.AI_MODEL || 'qwen2.5-coder:3b').trim(),
  aiValidationEnabled: process.env.AI_VALIDATION_ENABLED !== 'false',

  // Backward compatibility alias
  ollamaBaseUrl: (process.env.AI_BASE_URL || process.env.AI_API_BASE_URL || process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').trim(),
}
