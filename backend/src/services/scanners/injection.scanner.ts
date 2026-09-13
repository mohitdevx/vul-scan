import type { IScanner } from './base.scanner.js'
import type { VulnerabilityResult } from '../../types/index.js'

export class InjectionScanner implements IScanner {
  readonly name = 'InjectionScanner'

  async scan(_directoryPath: string): Promise<VulnerabilityResult[]> {
    // Scanner implementation placeholder for Command and SQL injection
    return []
  }
}
