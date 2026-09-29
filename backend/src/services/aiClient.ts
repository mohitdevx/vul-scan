import { config } from '../config/env.js'
import { logger } from '../utils/logger.js'

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface ChatCompletionOptions {
  messages: ChatMessage[]
  temperature?: number
  maxTokens?: number
  jsonMode?: boolean
  timeoutMs?: number
  model?: string
}

export interface AiHealthStatus {
  available: boolean
  model: string
  provider: string
  baseUrl: string
  error?: string
}

/**
 * Universal AI Client that transparently supports:
 * - OpenAI (ChatGPT): https://api.openai.com/v1
 * - DeepSeek: https://api.deepseek.com/v1 (or https://api.deepseek.com)
 * - NVIDIA NIM: https://integrate.api.nvidia.com/v1
 * - Groq: https://api.groq.com/openai/v1
 * - OpenRouter: https://openrouter.ai/api/v1
 * - Local / Remote Ollama: http://127.0.0.1:11434 (native /api/chat and /v1/chat/completions)
 * - vLLM, LiteLLM, LocalAI, or any custom OpenAI-compatible proxy
 */
export async function sendAiChatCompletion(options: ChatCompletionOptions): Promise<string> {
  const rawBase = config.aiBaseUrl.replace(/\/+$/, '')
  const modelName = options.model || config.aiModel
  const temperature = options.temperature ?? 0.1
  const maxTokens = options.maxTokens ?? 2048
  const timeoutMs = options.timeoutMs ?? 45000

  // Detect whether this is an OpenAI-compatible URL or Ollama native
  const isOpenAiCompatible =
    rawBase.endsWith('/v1') ||
    rawBase.includes('openai.com') ||
    rawBase.includes('deepseek.com') ||
    rawBase.includes('nvidia.com') ||
    rawBase.includes('groq.com') ||
    rawBase.includes('openrouter.ai') ||
    Boolean(config.aiApiKey)

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    if (isOpenAiCompatible) {
      // 1. OpenAI-compatible /v1/chat/completions format
      const endpoint = rawBase.endsWith('/v1')
        ? `${rawBase}/chat/completions`
        : `${rawBase}/v1/chat/completions`

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      if (config.aiApiKey) {
        headers['Authorization'] = `Bearer ${config.aiApiKey}`
      }

      const requestBody: Record<string, any> = {
        model: modelName,
        messages: options.messages,
        temperature,
        max_tokens: maxTokens,
      }

      if (options.jsonMode) {
        requestBody.response_format = { type: 'json_object' }
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      })

      if (!res.ok) {
        const errorText = await res.text()
        throw new Error(`AI Gateway HTTP ${res.status} [${endpoint}]: ${errorText.slice(0, 300)}`)
      }

      const data = (await res.json()) as any
      const content = data.choices?.[0]?.message?.content || data.message?.content || ''
      return typeof content === 'string' ? content : JSON.stringify(content)
    } else {
      // 2. Local Ollama Native format with automatic fallback to /v1
      const endpoint = `${rawBase}/api/chat`
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      if (config.aiApiKey) {
        headers['Authorization'] = `Bearer ${config.aiApiKey}`
      }

      const ollamaBody: Record<string, any> = {
        model: modelName,
        messages: options.messages,
        stream: false,
        options: {
          temperature,
          num_predict: maxTokens,
        },
      }

      if (options.jsonMode) {
        ollamaBody.format = 'json'
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(ollamaBody),
        signal: controller.signal,
      })

      if (res.ok) {
        const data = (await res.json()) as any
        return data.message?.content || data.choices?.[0]?.message?.content || ''
      }

      // If /api/chat returned 404, fallback to /v1/chat/completions
      if (res.status === 404) {
        const v1Endpoint = `${rawBase}/v1/chat/completions`
        const v1Res = await fetch(v1Endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model: modelName,
            messages: options.messages,
            temperature,
            max_tokens: maxTokens,
            ...(options.jsonMode ? { response_format: { type: 'json_object' } } : {}),
          }),
          signal: controller.signal,
        })

        if (!v1Res.ok) {
          const errText = await v1Res.text()
          throw new Error(`AI Gateway HTTP ${v1Res.status} [${v1Endpoint}]: ${errText.slice(0, 300)}`)
        }

        const data = (await v1Res.json()) as any
        return data.choices?.[0]?.message?.content || ''
      }

      const errText = await res.text()
      throw new Error(`AI Gateway HTTP ${res.status} [${endpoint}]: ${errText.slice(0, 300)}`)
    }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Checks AI endpoint connectivity and returns status metadata
 */
export async function checkAiHealth(): Promise<AiHealthStatus> {
  const rawBase = config.aiBaseUrl.replace(/\/+$/, '')
  const modelName = config.aiModel

  const isOpenAiCompatible =
    rawBase.endsWith('/v1') ||
    rawBase.includes('openai.com') ||
    rawBase.includes('deepseek.com') ||
    rawBase.includes('nvidia.com') ||
    rawBase.includes('groq.com') ||
    rawBase.includes('openrouter.ai') ||
    Boolean(config.aiApiKey)

  const provider = rawBase.includes('deepseek.com')
    ? 'DeepSeek'
    : rawBase.includes('openai.com')
    ? 'OpenAI'
    : rawBase.includes('nvidia.com')
    ? 'NVIDIA NIM'
    : rawBase.includes('groq.com')
    ? 'Groq'
    : rawBase.includes('openrouter.ai')
    ? 'OpenRouter'
    : 'Ollama / Universal'

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 4000)

    if (isOpenAiCompatible) {
      const modelsEndpoint = rawBase.endsWith('/v1') ? `${rawBase}/models` : `${rawBase}/v1/models`
      const headers: Record<string, string> = {}
      if (config.aiApiKey) {
        headers['Authorization'] = `Bearer ${config.aiApiKey}`
      }

      const res = await fetch(modelsEndpoint, {
        headers,
        signal: controller.signal,
      })
      clearTimeout(timer)

      if (res.ok || res.status === 200 || res.status === 401) {
        return {
          available: res.ok,
          model: modelName,
          provider,
          baseUrl: rawBase,
          error: res.ok ? undefined : `Authentication failed (HTTP ${res.status}). Check AI_API_KEY.`,
        }
      }

      return {
        available: true,
        model: modelName,
        provider,
        baseUrl: rawBase,
      }
    } else {
      // Local Ollama probe
      const res = await fetch(`${rawBase}/api/tags`, {
        signal: controller.signal,
      })
      clearTimeout(timer)

      if (!res.ok) {
        return {
          available: false,
          model: modelName,
          provider: 'Ollama',
          baseUrl: rawBase,
          error: `HTTP ${res.status}`,
        }
      }

      const data = (await res.json()) as { models?: Array<{ name: string }> }
      const models = data.models || []
      const hasModel = models.some(m => m.name === modelName || m.name.startsWith(modelName))

      return {
        available: true,
        model: modelName,
        provider: 'Ollama',
        baseUrl: rawBase,
        error: hasModel ? undefined : `Model '${modelName}' not found in local Ollama repository.`,
      }
    }
  } catch (err: any) {
    return {
      available: false,
      model: modelName,
      provider,
      baseUrl: rawBase,
      error: err.message || 'Cannot connect to AI endpoint',
    }
  }
}
