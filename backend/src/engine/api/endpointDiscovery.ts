import fs from 'node:fs/promises'
import path from 'node:path'
import traverseModule from '@babel/traverse'
import { parseSourceCode } from '../parser.js'
import type { DiscoveredEndpoint, EndpointDiscoveryResult, HttpMethod, ApiParameter } from './types.js'

const traverse = (traverseModule as any).default || traverseModule

const HTTP_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

const KNOWN_AUTH_PATTERNS = [
  'auth',
  'authenticate',
  'requireauth',
  'verifyjwt',
  'verifytoken',
  'isauthenticated',
  'protect',
  'authguard',
  'jwtguard',
  'requireuser',
  'requirerole',
  'isadmin',
  'ensureauth',
  'passport',
]

function isAuthMiddleware(name: string): boolean {
  const lower = name.toLowerCase().replace(/[^a-z0-9]/g, '')
  return KNOWN_AUTH_PATTERNS.some(pat => lower.includes(pat))
}

/**
 * Extracts route parameters (:param) from a route path string
 */
function extractPathParams(routePath: string): ApiParameter[] {
  const params: ApiParameter[] = []
  const matches = routePath.matchAll(/:([a-zA-Z0-9_]+)/g)
  for (const m of matches) {
    params.push({
      name: m[1],
      in: 'path',
      required: true,
      type: 'string',
    })
  }
  return params
}

/**
 * Inspects AST node for request body/query parameter access in handler body
 */
/**
 * Lightweight recursive AST walker that safely traverses any AST node or sub-tree
 */
function walkAst(node: any, visitor: (node: any) => void) {
  if (!node || typeof node !== 'object') return
  visitor(node)
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'tokens' || key === 'comments') continue
    const val = node[key]
    if (Array.isArray(val)) {
      for (const item of val) {
        walkAst(item, visitor)
      }
    } else if (val && typeof val === 'object' && val.type) {
      walkAst(val, visitor)
    }
  }
}

/**
 * Inspects AST node for request body/query parameter access in handler body
 */
function extractHandlerParameters(handlerAst: any, pathParams: ApiParameter[]): ApiParameter[] {
  const params: ApiParameter[] = [...pathParams]
  const seen = new Set<string>(pathParams.map(p => `path:${p.name}`))

  walkAst(handlerAst, (node) => {
    // req.query.foo or req.body.bar or req.params.baz or req.headers['x-api-key']
    if (node.type === 'MemberExpression') {
      const obj = node.object
      const prop = node.property

      if (obj && obj.type === 'MemberExpression' && obj.object && obj.object.name === 'req') {
        const location = obj.property?.name
        let paramName = ''
        if (prop?.type === 'Identifier') {
          paramName = prop.name
        } else if (prop?.type === 'Literal' || prop?.type === 'StringLiteral') {
          paramName = String(prop.value)
        }

        if (paramName && (location === 'query' || location === 'body' || location === 'params' || location === 'headers')) {
          const locType = location === 'params' ? 'path' : location === 'headers' ? 'header' : (location as 'query' | 'body')
          const key = `${locType}:${paramName}`
          if (!seen.has(key)) {
            seen.add(key)
            params.push({
              name: paramName,
              in: locType,
              required: locType === 'path',
              type: 'unknown',
            })
          }
        }
      }
    }

    // const { username, password } = req.body
    if (node.type === 'VariableDeclarator' && node.id?.type === 'ObjectPattern' && node.init?.type === 'MemberExpression') {
      if (node.init.object?.name === 'req') {
        const loc = node.init.property?.name
        if (loc === 'body' || loc === 'query' || loc === 'params') {
          const locType = loc === 'params' ? 'path' : (loc as 'query' | 'body')
          for (const prop of node.id.properties || []) {
            const name = prop.key?.name || prop.value?.name
            if (name) {
              const key = `${locType}:${name}`
              if (!seen.has(key)) {
                seen.add(key)
                params.push({
                  name,
                  in: locType,
                  required: locType === 'path',
                  type: 'unknown',
                })
              }
            }
          }
        }
      }
    }
  })

  return params
}

/**
 * Extracts endpoints from Next.js App Router (app/api/.../route.ts)
 */
function extractNextJsAppRouterEndpoints(
  ast: any,
  filePath: string,
  lines: string[]
): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = []
  const normPath = filePath.replace(/\\/g, '/')
  const apiIdx = normPath.indexOf('/api/')
  if (apiIdx === -1 && !normPath.includes('app/api')) return endpoints

  let routePath = normPath.substring(normPath.indexOf('app/api') + 3)
  routePath = routePath.replace(/\/route\.(ts|js|tsx|jsx)$/, '').replace(/\[([^\]]+)\]/g, ':$1')
  if (!routePath.startsWith('/')) routePath = '/' + routePath

  walkAst(ast, (node) => {
    if (node.type === 'ExportNamedDeclaration') {
      const decl = node.declaration
      if (decl && decl.type === 'FunctionDeclaration' && decl.id) {
        const fnName = decl.id.name.toUpperCase()
        if (HTTP_METHODS.includes(fnName as HttpMethod)) {
          const line = decl.loc?.start?.line || node.loc?.start?.line || 1
          const endLine = decl.loc?.end?.line || line + 15
          const scopeCode = lines.slice(Math.max(0, line - 1), Math.min(lines.length, endLine)).join('\n')
          const pathParams = extractPathParams(routePath)
          const params = extractHandlerParameters(decl, pathParams)

          endpoints.push({
            id: `EP-${endpoints.length + 1}`,
            method: fnName as HttpMethod,
            path: routePath,
            filePath,
            line,
            framework: 'nextjs',
            handlerName: decl.id.name,
            authRequired: scopeCode.toLowerCase().includes('auth') || scopeCode.toLowerCase().includes('session'),
            authMiddlewares: [],
            parameters: params,
            codeSnippet: lines[line - 1] || '',
            enclosingScopeCode: scopeCode,
          })
        }
      }
    }
  })

  return endpoints
}

/**
 * Discovers endpoints in an Express / Koa / Fastify / Hono router file
 */
function extractStandardRouterEndpoints(
  ast: any,
  filePath: string,
  lines: string[]
): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = []

  walkAst(ast, (node) => {
    if (node.type === 'CallExpression') {
      const callee = node.callee
      if (callee && callee.type === 'MemberExpression') {
        const methodName = callee.property?.name?.toUpperCase()
        const isHttp = HTTP_METHODS.includes(methodName as HttpMethod) || methodName === 'ALL' || methodName === 'USE'

        if (isHttp && node.arguments && node.arguments.length >= 1) {
          const firstArg = node.arguments[0]
          let routePath = ''

          if (firstArg.type === 'Literal' || firstArg.type === 'StringLiteral') {
            routePath = String(firstArg.value)
          } else if (firstArg.type === 'TemplateLiteral' && firstArg.quasis?.length === 1) {
            routePath = firstArg.quasis[0].value.raw
          }

          if (routePath && routePath.startsWith('/')) {
            const line = node.loc?.start?.line || 1
            const endLine = node.loc?.end?.line || line + 20
            const scopeCode = lines.slice(Math.max(0, line - 1), Math.min(lines.length, endLine)).join('\n')

            const middlewares: string[] = []
            let authRequired = false

            for (let i = 1; i < node.arguments.length; i++) {
              const arg = node.arguments[i]
              const argName = arg.name || arg.id?.name || (arg.callee?.name ? `${arg.callee.name}()` : '')
              if (argName) {
                middlewares.push(argName)
                if (isAuthMiddleware(argName)) {
                  authRequired = true
                }
              }
            }

            if (!authRequired && (scopeCode.toLowerCase().includes('req.user') || scopeCode.toLowerCase().includes('verifyjwt'))) {
              authRequired = true
            }

            const pathParams = extractPathParams(routePath)
            const params = extractHandlerParameters(node, pathParams)

            const method: HttpMethod = methodName === 'USE' || methodName === 'ALL' ? 'ALL' : (methodName as HttpMethod)

            endpoints.push({
              id: `EP-${endpoints.length + 1}`,
              method,
              path: routePath,
              filePath,
              line,
              framework: filePath.includes('nest') ? 'nestjs' : filePath.includes('fastify') ? 'fastify' : 'express',
              handlerName: middlewares[middlewares.length - 1] || 'anonymousHandler',
              authRequired,
              authMiddlewares: middlewares.filter(isAuthMiddleware),
              parameters: params,
              codeSnippet: lines[line - 1] || '',
              enclosingScopeCode: scopeCode,
            })
          }
        }
      }
    }
  })

  return endpoints
}

/**
 * Discovers and maps all API endpoints in a given file
 */
export function discoverEndpointsInFile(filePath: string, fileContent: string): DiscoveredEndpoint[] {
  const ast = parseSourceCode(fileContent, filePath)
  if (!ast) return []

  const lines = fileContent.split('\n')
  const nextEndpoints = extractNextJsAppRouterEndpoints(ast, filePath, lines)
  if (nextEndpoints.length > 0) {
    return nextEndpoints
  }

  return extractStandardRouterEndpoints(ast, filePath, lines)
}

/**
 * Discovers all API endpoints across an entire codebase repository
 */
export function discoverCodebaseEndpoints(files: { path: string; content: string }[]): EndpointDiscoveryResult {
  const allEndpoints: DiscoveredEndpoint[] = []
  const frameworksDetected = new Set<string>()

  let epCounter = 1
  for (const file of files) {
    const isCodeFile = /\.(ts|js|mjs|cjs|jsx|tsx)$/i.test(file.path)
    if (!isCodeFile) continue

    const endpoints = discoverEndpointsInFile(file.path, file.content)
    for (const ep of endpoints) {
      ep.id = `EP-${epCounter++}`
      frameworksDetected.add(ep.framework)
      allEndpoints.push(ep)
    }
  }

  const methodCounts: Record<HttpMethod, number> = {
    GET: 0,
    POST: 0,
    PUT: 0,
    DELETE: 0,
    PATCH: 0,
    OPTIONS: 0,
    HEAD: 0,
    ALL: 0,
  }

  let authenticatedCount = 0
  let publicCount = 0

  for (const ep of allEndpoints) {
    methodCounts[ep.method] = (methodCounts[ep.method] || 0) + 1
    if (ep.authRequired) {
      authenticatedCount++
    } else {
      publicCount++
    }
  }

  return {
    endpoints: allEndpoints,
    totalEndpoints: allEndpoints.length,
    frameworksDetected: Array.from(frameworksDetected),
    filesAnalyzed: files.length,
    summary: {
      authenticatedCount,
      publicCount,
      methodCounts,
    },
  }
}

const IGNORED_API_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'coverage',
  'vendor',
  'fixtures',
  'test',
  'tests',
  '__tests__',
])

async function collectApiFiles(dir: string, baseDir: string): Promise<{ path: string; content: string }[]> {
  const result: { path: string; content: string }[] = []
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name)
      const relPath = path.relative(baseDir, fullPath)
      const lowerName = entry.name.toLowerCase()

      if (entry.isDirectory()) {
        if (!IGNORED_API_DIRS.has(lowerName) && !entry.name.startsWith('.')) {
          const subFiles = await collectApiFiles(fullPath, baseDir)
          result.push(...subFiles)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext)) {
          try {
            const content = await fs.readFile(fullPath, 'utf-8')
            result.push({ path: relPath, content })
          } catch {
            // Ignore unreadable files
          }
        }
      }
    }
  } catch {
    // Ignore directory reading errors
  }
  return result
}

export async function discoverEndpoints(
  dirPath: string
): Promise<{
  endpoints: DiscoveredEndpoint[]
  frameworks: string[]
  totalFilesScanned: number
  summary: {
    authenticatedCount: number
    publicCount: number
    methodCounts: Record<HttpMethod, number>
  }
}> {
  const files = await collectApiFiles(dirPath, dirPath)
  const result = discoverCodebaseEndpoints(files)
  return {
    endpoints: result.endpoints,
    frameworks: result.frameworksDetected,
    totalFilesScanned: files.length,
    summary: result.summary,
  }
}
