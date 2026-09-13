import type { VulnerabilityResult } from '../../types/index.js'

export interface IScanner {
  readonly name: string
  scan(directoryPath: string): Promise<VulnerabilityResult[]>
}
