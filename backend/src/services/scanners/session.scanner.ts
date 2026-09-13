import type { IScanner } from './base.scanner.js'
import type { VulnerabilityResult } from '../../types/index.js'

export class SessionScanner implements IScanner {
  readonly name = 'SessionScanner'

  async scan(_directoryPath: string): Promise<VulnerabilityResult[]> {
    // Scanner implementation placeholder for session management issues
    return []
  }
}
