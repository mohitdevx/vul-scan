import { masterEngine } from './masterEngine.js'
import { xssEngine } from './xssEngine.js'
import { sqliEngine } from './sqliEngine.js'

// Register core engines - adding new engines in the future requires just:
// masterEngine.register(newEngine)
masterEngine.register(xssEngine)
masterEngine.register(sqliEngine)

export { masterEngine, xssEngine, sqliEngine }
export * from './masterEngine.js'
export * from './xssEngine.js'
export * from './sqliEngine.js'
export * from './types.js'
export * from './parser.js'
export * from './scanner.js'
export * from './astUtils.js'

