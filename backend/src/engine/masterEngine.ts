import type { SecurityEngine, EngineContext, Finding, Severity } from './types.js'
import { logger } from '../utils/logger.js'

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
}

/**
 * Global Master Engine Controller
 * Manages lifecycle, registration, and dispatching for all security scanning engines.
 * Adding a new engine is as simple as:
 *   masterEngine.register(myNewEngine)
 */
export class MasterEngineController {
  private engines: Map<string, SecurityEngine> = new Map()

  /**
   * Register a security engine
   * @param engine Engine implementing SecurityEngine interface
   */
  public register(engine: SecurityEngine): this {
    if (!engine || !engine.id) {
      throw new Error('[MasterEngine] Engine registration failed: missing engine id')
    }

    const key = engine.id.toLowerCase()
    if (this.engines.has(key)) {
      logger.warn(`[MasterEngine] Engine '${key}' is already registered. Overwriting with new instance.`)
    }

    if (engine.enabled === undefined) {
      engine.enabled = true
    }

    this.engines.set(key, engine)
    logger.info(`[MasterEngine] Registered engine: ${engine.name} [ID: ${engine.id}] (v${engine.version || '1.0.0'})`)
    return this
  }

  /**
   * Unregister an engine by id
   */
  public unregister(id: string): boolean {
    const key = id.toLowerCase()
    const deleted = this.engines.delete(key)
    if (deleted) {
      logger.info(`[MasterEngine] Unregistered engine: ${id}`)
    }
    return deleted
  }

  /**
   * Get an engine by id
   */
  public getEngine(id: string): SecurityEngine | undefined {
    return this.engines.get(id.toLowerCase())
  }

  /**
   * List all registered engines
   */
  public getEngines(): SecurityEngine[] {
    return Array.from(this.engines.values())
  }

  /**
   * Enable a registered engine
   */
  public enable(id: string): boolean {
    const engine = this.getEngine(id)
    if (engine) {
      engine.enabled = true
      return true
    }
    return false
  }

  /**
   * Disable a registered engine without removing it
   */
  public disable(id: string): boolean {
    const engine = this.getEngine(id)
    if (engine) {
      engine.enabled = false
      return true
    }
    return false
  }

  /**
   * Clear all registered engines
   */
  public clear(): void {
    this.engines.clear()
  }

  /**
   * Execute AST analysis across all active registered engines.
   * Isolates failures, aggregates, deduplicates, and sorts findings.
   */
  public analyze(ast: any, ctx: EngineContext): Finding[] {
    if (!ast) return []

    const allFindings: Finding[] = []
    const activeEngines = Array.from(this.engines.values()).filter(e => e.enabled !== false)

    for (const engine of activeEngines) {
      try {
        const engineFindings = engine.analyze(ast, ctx)
        if (Array.isArray(engineFindings)) {
          allFindings.push(...engineFindings)
        }
      } catch (err: any) {
        logger.error(`[MasterEngine] Error in engine '${engine.name}' analyzing ${ctx.filePath}: ${err.message}`)
      }
    }

    return this.deduplicateAndSort(allFindings)
  }

  /**
   * Deduplicate duplicate findings at the exact file line and sink,
   * keeping the highest severity finding.
   */
  private deduplicateAndSort(findings: Finding[]): Finding[] {
    const map = new Map<string, Finding>()

    for (const f of findings) {
      const key = `${f.filePath}:${f.line}:${f.sink || f.ruleId}`
      const existing = map.get(key)
      if (!existing) {
        map.set(key, f)
      } else {
        // Keep the one with higher severity
        const existingWeight = SEVERITY_WEIGHT[existing.severity] || 0
        const currentWeight = SEVERITY_WEIGHT[f.severity] || 0
        if (currentWeight > existingWeight) {
          map.set(key, f)
        }
      }
    }

    const deduplicated = Array.from(map.values())

    // Sort by Severity (CRITICAL -> HIGH -> MEDIUM -> LOW), then by line number
    return deduplicated.sort((a, b) => {
      const weightDiff = (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0)
      if (weightDiff !== 0) return weightDiff
      return a.line - b.line
    })
  }
}

// Global master engine singleton
export const masterEngine = new MasterEngineController()
