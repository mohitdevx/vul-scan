import { masterEngine } from './masterEngine.js'
import { xssEngine } from './xssEngine.js'
import { sqliEngine } from './sqliEngine.js'
import { cmdiEngine } from './cmdiEngine.js'

// Register core engines - adding new engines in the future requires just:
// masterEngine.register(newEngine)
masterEngine.register(xssEngine)
masterEngine.register(sqliEngine)
masterEngine.register(cmdiEngine)

export { masterEngine, xssEngine, sqliEngine, cmdiEngine }
export * from './masterEngine.js'
export * from './xssEngine.js'
export * from './sqliEngine.js'
export * from './cmdiEngine.js'
export * from './types.js'
export * from './parser.js'
export * from './scanner.js'
export * from './astUtils.js'
export * from './api/index.js'
