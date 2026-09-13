import type { IScanner } from './base.scanner.js'
import type { VulnerabilityResult } from '../../types/index.js'

export class AuthScanner implements IScanner {
  readonly name = 'AuthScanner'

  async scan(_directoryPath: string): Promise<VulnerabilityResult[]> {
    // Scanner implementation placeholder for auth flow verification
    return []
  }
}
