import type { IScanner } from './base.scanner.js'
import type { VulnerabilityResult } from '../../types/index.js'

export class XSSScanner implements IScanner {
  readonly name = 'XSSScanner'

  async scan(_directoryPath: string): Promise<VulnerabilityResult[]> {
    // Scanner implementation placeholder
    return []
  }
}
