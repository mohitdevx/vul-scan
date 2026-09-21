import traverseModule from '@babel/traverse'
import type { Finding, EngineContext, SecurityEngine } from './types.js'
import { extractSnippet } from './parser.js'
import {
  evaluateStaticString,
  isSanitizedExpression,
  isDynamicOrTainted,
  isHttpSource,
  isDomSource,
  isDatabaseSource,
  isExplicitStringExpression,
} from './astUtils.js'

const traverse = (traverseModule as any).default || traverseModule

const DANGEROUS_DOM_SINKS = new Set([
  'innerhtml',
  'outerhtml',
  'insertadjacenthtml',
])

const DANGEROUS_ATTRIBUTES = new Set([
  'src',
  'href',
  'srcdoc',
  'formaction',
  'action',
  'data',
  'onclick',
  'onerror',
  'onload',
])

const DANGEROUS_MARKDOWN_ENGINES = new Set([
  'marked',
  'markdownit',
  'markdown-it',
  'showdown',
])

const NON_DOM_OBJECT_NAMES = new Set([
  'formdata',
  'form',
  'params',
  'searchparams',
  'urlsearchparams',
  'headers',
  'header',
  'cookie',
  'cookies',
  'list',
  'stack',
  'arr',
  'array',
  'buffer',
  'platformbuffer',
  'platformformdata',
  'this',
  'self',
  'res',
  'req',
  'response',
  'request',
  'reply',
  'app',
  'router',
  'fs',
  'path',
  'stream',
])

export const xssEngine: SecurityEngine = {
  id: 'xss',
  name: 'Cross-Site Scripting (XSS) Engine',
  ruleId: 'engine/ast-xss-advanced',
  cwe: 'CWE-79',
  version: '2.0.0',

  analyze(ast: any, ctx: EngineContext): Finding[] {
    const findings: Finding[] = []
    let counter = 1

    // Map of curried / closure-generated sinks: e.g. inject = createRenderer(c)('innerHTML')
    const curriedSinkIdentifiers = new Set<string>()

    // Map of helper wrapper functions: e.g. function setSafeContent(el, content) { el.innerHTML = content; }
    const helperFunctionSinks = new Map<string, { paramIndex: number; sinkName: string; line: number }>()

    // Pre-pass: Discover curried closure sinks and function wrapper sinks
    traverse(ast, {
      // Catch curried sink assignments: const inject = createRenderer(container)('innerHTML')
      VariableDeclarator(path: any) {
        const { id, init } = path.node
        if (id && id.type === 'Identifier' && init && init.type === 'CallExpression') {
          const checkCallForSink = (callNode: any): boolean => {
            if (!callNode || callNode.type !== 'CallExpression') return false
            for (const arg of callNode.arguments || []) {
              const strVal = evaluateStaticString(arg, path.scope)
              if (strVal && DANGEROUS_DOM_SINKS.has(strVal.toLowerCase())) {
                return true
              }
            }
            if (callNode.callee && callNode.callee.type === 'CallExpression') {
              return checkCallForSink(callNode.callee)
            }
            return false
          }

          if (checkCallForSink(init)) {
            curriedSinkIdentifiers.add(id.name)
          }
        }
      },

      // Catch helper wrapper functions that write to DOM sinks:
      // function setContent(element, content) { element.innerHTML = content; }
      FunctionDeclaration(path: any) {
        const fnName = path.node.id?.name
        if (!fnName) return

        const params = path.node.params.map((p: any) => p.name)

        path.traverse({
          AssignmentExpression(subPath: any) {
            const { left, right } = subPath.node
            if (left && left.type === 'MemberExpression') {
              const prop = evaluateStaticString(left.property, subPath.scope) || left.property?.name
              if (prop && DANGEROUS_DOM_SINKS.has(prop.toLowerCase())) {
                if (right && right.type === 'Identifier') {
                  const paramIdx = params.indexOf(right.name)
                  if (paramIdx !== -1) {
                    helperFunctionSinks.set(fnName, {
                      paramIndex: paramIdx,
                      sinkName: `element.${prop}`,
                      line: subPath.node.loc?.start.line || 1,
                    })
                  }
                }
              }
            }
          },
        })
      },
    })

    // Main Traversal: Detect Reflected, Stored, DOM, Cookie, and Framework XSS
    traverse(ast, {
      // =========================================================================
      // CATEGORY 1 & 3: Member Sinks (innerHTML, outerHTML, document.cookie, etc.)
      // =========================================================================
      AssignmentExpression(path: any) {
        const { left, right } = path.node
        if (!left || left.type !== 'MemberExpression') return

        const scope = path.scope

        // Resolve property name statically (supports ['inner', 'HTML'].join(''), 'inner' + 'HTML', etc.)
        let propName = evaluateStaticString(left.property, scope)
        if (!propName && left.property) {
          propName = left.property.name || left.property.value
        }

        const normalizedProp = (propName || '').toLowerCase()

        // 1. DOM innerHTML / outerHTML Sinks
        if (DANGEROUS_DOM_SINKS.has(normalizedProp)) {
          const taint = isDynamicOrTainted(right, scope)
          if (taint.tainted && !isSanitizedExpression(right)) {
            const line = left.loc?.start.line || 1
            const col = left.loc?.start.column || 1
            const objName = left.object?.name || 'element'

            const isComputed = left.computed && left.property?.type !== 'StringLiteral'
            const ruleName = isComputed
              ? 'Cross-Site Scripting (DOM innerHTML via Computed Property)'
              : `Cross-Site Scripting (DOM ${propName})`

            findings.push({
              id: `XSS-${counter++}`,
              ruleId: isComputed ? 'ast/xss-dom-computed' : 'ast/xss-innerhtml',
              ruleName,
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `${objName}.${propName}`,
              message: `Unsanitized dynamic value assigned to DOM sink '${objName}.${propName}'${
                taint.sourceDesc ? ` via ${taint.sourceDesc}` : ''
              }. Allows arbitrary HTML/JavaScript execution.`,
              remediation: `Use 'element.textContent' for plain text, or sanitize untrusted content using 'DOMPurify.sanitize()' before assigning to ${propName}.`,
            })
          }
        }

        // 2. Cookie Manipulation Sink: document.cookie = ...
        if (
          normalizedProp === 'cookie' &&
          left.object &&
          (left.object.name === 'document' || left.object.property?.name === 'document')
        ) {
          const taint = isDynamicOrTainted(right, scope)
          const lineContent = ctx.lines[left.loc?.start.line - 1] || ''
          const fileContent = ctx.fileContent || ''
          const isExplicitlyEncoded =
            isSanitizedExpression(right) ||
            lineContent.toLowerCase().includes('encodeuricomponent') ||
            fileContent.toLowerCase().includes('encodeuricomponent')

          if (taint.tainted && !isExplicitlyEncoded) {
            const line = left.loc?.start.line || 1
            const col = left.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-cookie-injection',
              ruleName: 'Cookie Poisoning / Cookie-Based XSS Injection',
              cwe: 'CWE-79',
              severity: 'MEDIUM',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: 'document.cookie',
              message: `Untrusted user input written directly to 'document.cookie'${
                taint.sourceDesc ? ` via ${taint.sourceDesc}` : ''
              }. May allow session fixation or cookie-based script execution.`,
              remediation: `Sanitize and encode all values before setting cookies. Use 'encodeURIComponent()' and ensure sensitive cookies use HttpOnly flags from the server.`,
            })
          }
        }

        // 3. Navigation / Location Sinks: location.href = ... or window.location = ...
        const isLocationTarget =
          (normalizedProp === 'href' && (left.object?.name === 'location' || left.object?.property?.name === 'location')) ||
          (left.object?.name === 'location' && !left.property?.name) ||
          (left.property?.name === 'location' && left.object?.name === 'window')

        if (isLocationTarget) {
          const taint = isDynamicOrTainted(right, scope)
          const domSource = isDomSource(right, scope).isSource
          const staticStr = evaluateStaticString(right, scope)
          const lineContent = ctx.lines[left.loc?.start.line - 1] || ''
          const hasJsScheme =
            (staticStr && staticStr.toLowerCase().startsWith('javascript:')) ||
            (isExplicitStringExpression(right, scope) && lineContent.includes('javascript:'))

          // A navigation sink is ONLY a CWE-79 DOM XSS vulnerability if:
          // 1. It explicitly assigns or concatenates a 'javascript:' pseudo-protocol
          // 2. OR the target URL originates directly from untrusted DOM input (location.search, location.hash)
          if ((hasJsScheme || domSource) && taint.tainted) {
            const line = left.loc?.start.line || 1
            const col = left.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-dom-navigation',
              ruleName: 'DOM-based XSS via Client Navigation Sink',
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `location.${propName || 'href'}`,
              message: `Dynamic URL assigned to browser navigation sink with controllable scheme or DOM source. Allows immediate script execution if 'javascript:' scheme is supplied.`,
              remediation: `Validate target URL with a whitelist or ensure the scheme begins strictly with 'http:' or 'https:'. Reject 'javascript:' pseudo-protocols.`,
            })
          }
        }
      },

      // =========================================================================
      // CATEGORY 1, 2, 3: Call Expression Sinks (res.send, document.write, helper calls, markdown)
      // =========================================================================
      CallExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (!callee) return
        const scope = path.scope

        // 1. Curried Closure Sink: e.g. inject(cardMarkup)
        if (callee.type === 'Identifier' && curriedSinkIdentifiers.has(callee.name)) {
          const firstArg = args[0]
          const taint = isDynamicOrTainted(firstArg, scope)
          if (taint.tainted && !isSanitizedExpression(firstArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-curried-closure',
              ruleName: 'Cross-Site Scripting (Deferred Curried DOM Closure)',
              cwe: 'CWE-79',
              severity: 'CRITICAL',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `${callee.name}(...)`,
              message: `Curried factory closure '${callee.name}' configured with an unsafe DOM sink was invoked with unsanitized dynamic markup.`,
              remediation: `Sanitize untrusted content with 'DOMPurify.sanitize()' before passing to renderer closures.`,
            })
          }
        }

        // 2. Inter-procedural helper call: e.g. setSafeContent(target, userFeedback)
        if (callee.type === 'Identifier' && helperFunctionSinks.has(callee.name)) {
          const helperInfo = helperFunctionSinks.get(callee.name)!
          const targetArg = args[helperInfo.paramIndex]
          if (targetArg) {
            const taint = isDynamicOrTainted(targetArg, scope)
            if (taint.tainted && !isSanitizedExpression(targetArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-interprocedural-helper',
                ruleName: 'Cross-Site Scripting via Tainted Helper Delegation',
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${callee.name} -> ${helperInfo.sinkName}`,
                message: `Tainted payload passed into helper function '${callee.name}' which writes to '${helperInfo.sinkName}' on line ${helperInfo.line}.`,
                remediation: `Sanitize inputs using 'DOMPurify.sanitize()' either before calling the helper or directly within the helper definition.`,
              })
            }
          }
        }

        // 3. document.write / document.writeln
        if (
          callee.type === 'MemberExpression' &&
          callee.object?.name === 'document' &&
          (callee.property?.name === 'write' || callee.property?.name === 'writeln')
        ) {
          const firstArg = args[0]
          const taint = isDynamicOrTainted(firstArg, scope)
          if (taint.tainted && !isSanitizedExpression(firstArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-document-write',
              ruleName: 'Cross-Site Scripting (document.write)',
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `document.${callee.property.name}`,
              message: `Dangerous DOM write sink 'document.${callee.property.name}' invoked with unescaped dynamic content.`,
              remediation: `Avoid 'document.write()' completely. Use 'document.createElement()' and assign values with 'textContent'.`,
            })
          }
        }

        // 4. element.insertAdjacentHTML('beforeend', content)
        if (
          callee.type === 'MemberExpression' &&
          callee.property?.name === 'insertAdjacentHTML'
        ) {
          const htmlArg = args[1]
          const taint = isDynamicOrTainted(htmlArg, scope)
          if (taint.tainted && !isSanitizedExpression(htmlArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-insertadjacenthtml',
              ruleName: 'Cross-Site Scripting (insertAdjacentHTML)',
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: 'element.insertAdjacentHTML',
              message: `Dynamic HTML content injected via 'insertAdjacentHTML' without sanitization.`,
              remediation: `Sanitize HTML strings with 'DOMPurify.sanitize()' before inserting into DOM fragments.`,
            })
          }
        }

        // 5. jQuery HTML injection: $(el).html(dynamic), $(el).append(dynamic)
        if (
          callee.type === 'MemberExpression' &&
          (callee.property?.name === 'html' ||
            callee.property?.name === 'append' ||
            callee.property?.name === 'prepend' ||
            callee.property?.name === 'after' ||
            callee.property?.name === 'before')
        ) {
          const objName = (callee.object?.name || callee.object?.property?.name || '').toLowerCase()
          const isNonDom = NON_DOM_OBJECT_NAMES.has(objName)
          const isMultiArgAppend = args.length >= 2 && callee.property?.name === 'append' // FormData/URLSearchParams take (key, val)

          if (!isNonDom && !isMultiArgAppend) {
            const firstArg = args[0]
            if (firstArg) {
              const taint = isDynamicOrTainted(firstArg, scope)
              if (taint.tainted && !isSanitizedExpression(firstArg)) {
                const line = callee.loc?.start.line || 1
                const col = callee.loc?.start.column || 1
                findings.push({
                  id: `XSS-${counter++}`,
                  ruleId: 'ast/xss-jquery-html',
                  ruleName: 'Cross-Site Scripting via jQuery HTML Sink',
                  cwe: 'CWE-79',
                  severity: 'HIGH',
                  filePath: ctx.filePath,
                  line,
                  column: col,
                  snippet: extractSnippet(ctx.lines, line),
                  sink: `$(...).${callee.property.name}`,
                  message: `Unsanitized content injected into jQuery DOM manipulation sink '.${callee.property.name}()'.`,
                  remediation: `Use '$(...).text()' for plain text or sanitize input with 'DOMPurify.sanitize()' before calling .${callee.property.name}().`,
                })
              }
            }
          }
        }

        // 6. Navigation methods: location.replace(url), location.assign(url)
        if (
          callee.type === 'MemberExpression' &&
          (callee.property?.name === 'replace' || callee.property?.name === 'assign') &&
          callee.object?.name === 'location'
        ) {
          const firstArg = args[0]
          if (firstArg) {
            const taint = isDynamicOrTainted(firstArg, scope)
            const domSource = isDomSource(firstArg, scope).isSource
            const staticStr = evaluateStaticString(firstArg, scope)
            const lineContent = ctx.lines[callee.loc?.start.line - 1] || ''
            const hasJsScheme =
              (staticStr && staticStr.toLowerCase().startsWith('javascript:')) ||
              (isExplicitStringExpression(firstArg, scope) && lineContent.includes('javascript:'))

            // Only flag if explicit javascript: scheme or direct untrusted DOM source is present
            if ((hasJsScheme || domSource) && taint.tainted) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-dom-navigation-call',
                ruleName: 'DOM-based XSS via location navigation',
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `location.${callee.property.name}`,
                message: `Dynamic URL passed to 'location.${callee.property.name}()' with controllable scheme or DOM source. Can execute 'javascript:' schemes.`,
                remediation: `Validate navigation URLs against an allowed origin list or verify that the protocol is strictly 'https:'.`,
              })
            }
          }
        }

        // 7. Reflected XSS: res.send(), res.write(), res.end()
        if (
          callee.type === 'MemberExpression' &&
          (callee.object?.name === 'res' ||
            callee.object?.name === 'response' ||
            callee.object?.name === 'reply') &&
          (callee.property?.name === 'send' ||
            callee.property?.name === 'write' ||
            callee.property?.name === 'end')
        ) {
          const firstArg = args[0]
          if (firstArg) {
            const taint = isDynamicOrTainted(firstArg, scope)
            if (taint.tainted && !isSanitizedExpression(firstArg)) {
              const rawLine = ctx.lines[callee.loc?.start.line - 1] || ''
              const isHtmlSuspect =
                rawLine.includes('<') ||
                rawLine.includes('>') ||
                rawLine.includes('html') ||
                rawLine.includes('banner') ||
                rawLine.includes('card') ||
                taint.sourceDesc?.includes('HTTP input')

              if (isHtmlSuspect) {
                const line = callee.loc?.start.line || 1
                const col = callee.loc?.start.column || 1

                const isStored = taint.sourceDesc?.includes('Persistent database')
                findings.push({
                  id: `XSS-${counter++}`,
                  ruleId: isStored ? 'ast/xss-stored-response' : 'ast/xss-reflected-response',
                  ruleName: isStored
                    ? 'Stored Cross-Site Scripting (Database-to-Response)'
                    : 'Reflected Cross-Site Scripting (Server Response)',
                  cwe: 'CWE-79',
                  severity: isStored ? 'CRITICAL' : 'HIGH',
                  filePath: ctx.filePath,
                  line,
                  column: col,
                  snippet: extractSnippet(ctx.lines, line),
                  sink: `${callee.object.name}.${callee.property.name}`,
                  message: `${
                    isStored ? 'Persistent database content' : 'Untrusted request input'
                  } reflected directly into HTTP response body without contextual encoding${
                    taint.sourceDesc ? ` (${taint.sourceDesc})` : ''
                  }.`,
                  remediation: `Use safe template engines with auto-escaping enabled, set 'Content-Type: application/json', or sanitize with 'validator.escape()'.`,
                })
              }
            }
          }
        }

        // 8. Markdown Renderers without Sanitization: marked(untrusted), showdown.makeHtml(untrusted)
        if (callee.type === 'Identifier' && DANGEROUS_MARKDOWN_ENGINES.has(callee.name.toLowerCase())) {
          const firstArg = args[0]
          const taint = isDynamicOrTainted(firstArg, scope)
          if (taint.tainted && !isSanitizedExpression(firstArg)) {
            const line = callee.loc?.start.line || 1
            const col = callee.loc?.start.column || 1
            findings.push({
              id: `XSS-${counter++}`,
              ruleId: 'ast/xss-stored-markdown',
              ruleName: 'Stored/DOM XSS via Unsanitized Markdown Parser',
              cwe: 'CWE-79',
              severity: 'HIGH',
              filePath: ctx.filePath,
              line,
              column: col,
              snippet: extractSnippet(ctx.lines, line),
              sink: `${callee.name}(...)`,
              message: `Markdown parser '${callee.name}' converts dynamic content into raw HTML without guaranteed sanitization.`,
              remediation: `Always pipe Markdown output through 'DOMPurify.sanitize(marked.parse(content))' before rendering.`,
            })
          }
        }

        // 9. Dangerous DOM Attribute Setter: setAttribute('src'|'href'|..., dynamic)
        if (
          callee.type === 'MemberExpression' &&
          callee.property?.name === 'setAttribute' &&
          args.length >= 2
        ) {
          const attrName = evaluateStaticString(args[0], scope)
          if (attrName && DANGEROUS_ATTRIBUTES.has(attrName.toLowerCase())) {
            const valueArg = args[1]
            const taint = isDynamicOrTainted(valueArg, scope)
            if (taint.tainted && !isSanitizedExpression(valueArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-dom-setattribute',
                ruleName: `DOM XSS via Dangerous Attribute '${attrName}'`,
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `setAttribute('${attrName}', ...)`,
                message: `Dynamic value assigned to dangerous DOM attribute '${attrName}' which can trigger script execution or navigation.`,
                remediation: `Validate and encode attribute values. For URLs, ensure the scheme starts with 'https:'.`,
              })
            }
          }
        }

        // 10. eval(dynamic)
        if (callee.type === 'Identifier' && callee.name === 'eval') {
          const firstArg = args[0]
          if (firstArg) {
            const taint = isDynamicOrTainted(firstArg, scope)
            if (taint.tainted && !isSanitizedExpression(firstArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-eval-call',
                ruleName: 'Cross-Site Scripting / Arbitrary Script Evaluation (eval)',
                cwe: 'CWE-79',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: 'eval(...)',
                message: `Dynamic untrusted value passed directly to 'eval()'. Allows immediate client-side script execution.`,
                remediation: `Remove 'eval()'. Parse data strictly using 'JSON.parse()' or typed schema decoders.`,
              })
            }
          }
        }

        // 11. setTimeout / setInterval with dynamic STRING argument
        // IMPORTANT: Only flags when firstArg is proven to be a string expression!
        // Function callbacks (e.g. resolve, res, onDismiss, cb) are never flagged!
        if (
          callee.type === 'Identifier' &&
          (callee.name === 'setTimeout' || callee.name === 'setInterval')
        ) {
          const firstArg = args[0]
          if (firstArg && isExplicitStringExpression(firstArg, scope)) {
            const taint = isDynamicOrTainted(firstArg, scope)
            if (taint.tainted && !isSanitizedExpression(firstArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-timer-code-execution',
                ruleName: `DOM XSS via '${callee.name}' String Argument`,
                cwe: 'CWE-79',
                severity: 'HIGH',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `${callee.name}(string, ...)`,
                message: `Passing dynamic strings to '${callee.name}()' triggers implicit script evaluation.`,
                remediation: `Always pass a callback function reference '() => ...' as the first parameter instead of a string.`,
              })
            }
          }
        }

        // 12. Angular DomSanitizer bypass methods
        if (
          callee.type === 'MemberExpression' &&
          callee.property &&
          (callee.property.name === 'bypassSecurityTrustHtml' ||
            callee.property.name === 'bypassSecurityTrustScript' ||
            callee.property.name === 'bypassSecurityTrustResourceUrl')
        ) {
          const firstArg = args[0]
          if (firstArg) {
            const taint = isDynamicOrTainted(firstArg, scope)
            if (taint.tainted && !isSanitizedExpression(firstArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-angular-bypass',
                ruleName: `Cross-Site Scripting via Angular DomSanitizer Bypass (${callee.property.name})`,
                cwe: 'CWE-79',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: `DomSanitizer.${callee.property.name}`,
                message: `Angular security bypass '${callee.property.name}' used on untrusted dynamic content, actively disabling framework defenses.`,
                remediation: `Avoid bypassing Angular sanitizer. If raw HTML is mandatory, pass it through 'DOMPurify.sanitize()'.`,
              })
            }
          }
        }
      },

      // Dynamic Function Constructor: new Function(...)
      NewExpression(path: any) {
        const { callee, arguments: args } = path.node
        if (callee && callee.name === 'Function' && args && args.length > 0) {
          const lastArg = args[args.length - 1]
          if (isExplicitStringExpression(lastArg, path.scope)) {
            const taint = isDynamicOrTainted(lastArg, path.scope)
            if (taint.tainted && !isSanitizedExpression(lastArg)) {
              const line = callee.loc?.start.line || 1
              const col = callee.loc?.start.column || 1
              findings.push({
                id: `XSS-${counter++}`,
                ruleId: 'ast/xss-function-constructor',
                ruleName: 'Cross-Site Scripting via Dynamic Function Constructor',
                cwe: 'CWE-79',
                severity: 'CRITICAL',
                filePath: ctx.filePath,
                line,
                column: col,
                snippet: extractSnippet(ctx.lines, line),
                sink: 'new Function(...)',
                message: `Dynamic untrusted string passed into 'new Function()' constructor creates executable code at runtime.`,
                remediation: `Never instantiate functions from runtime strings. Use static function references.`,
              })
            }
          }
        }
      },

      // =========================================================================
      // CATEGORY 5: Framework-specific sinks (React dangerouslySetInnerHTML, etc.)
      // =========================================================================
      JSXAttribute(path: any) {
        if (path.node.name?.name === 'dangerouslySetInnerHTML') {
          const value = path.node.value
          if (value?.type === 'JSXExpressionContainer') {
            const expr = value.expression
            if (expr?.type === 'ObjectExpression') {
              const htmlProp = expr.properties?.find(
                (p: any) => p.key?.name === '__html' || p.key?.value === '__html'
              )
              if (htmlProp) {
                // If expression is sanitized or passes through a dedicated HTML processor/sanitizer, skip!
                if (isSanitizedExpression(htmlProp.value)) {
                  return
                }
                const taint = isDynamicOrTainted(htmlProp.value, path.scope)
                if (taint.tainted && !isSanitizedExpression(htmlProp.value)) {
                  const line = path.node.loc?.start.line || 1
                  const col = path.node.loc?.start.column || 1
                  findings.push({
                    id: `XSS-${counter++}`,
                    ruleId: 'ast/xss-dangerouslysetinnerhtml',
                    ruleName: 'Cross-Site Scripting (React dangerouslySetInnerHTML)',
                    cwe: 'CWE-79',
                    severity: 'HIGH',
                    filePath: ctx.filePath,
                    line,
                    column: col,
                    snippet: extractSnippet(ctx.lines, line),
                    sink: 'dangerouslySetInnerHTML',
                    message: `React component uses 'dangerouslySetInnerHTML' with dynamic content without sanitization.`,
                    remediation: `Render text as standard JSX child strings or wrap HTML with 'DOMPurify.sanitize()'.`,
                  })
                }
              }
            }
          }
        }
      },
    })

    return findings
  },
}
