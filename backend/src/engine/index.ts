import { masterEngine } from './masterEngine.js'
import { xssEngine } from './xssEngine.js'

// Register core engines - adding new engines in the future requires just:
// masterEngine.register(newEngine)
masterEngine.register(xssEngine)

export { masterEngine, xssEngine }
export * from './masterEngine.js'
export * from './xssEngine.js'
export * from './types.js'
export * from './parser.js'
export * from './scanner.js'
export * from './astUtils.js'
