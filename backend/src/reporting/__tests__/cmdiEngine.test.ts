import test from 'node:test'
import assert from 'node:assert/strict'
import { parseSourceCode } from '../../engine/parser.js'
import { masterEngine, cmdiEngine } from '../../engine/index.js'
import type { EngineContext } from '../../engine/types.js'

function runScan(code: string, fileName = 'src/service.ts') {
  const ast = parseSourceCode(code, fileName)
  assert.ok(ast, 'AST parsing should succeed')
  const ctx: EngineContext = {
    filePath: fileName,
    fileContent: code,
    lines: code.split('\n'),
  }
  return cmdiEngine.analyze(ast, ctx)
}

test('Command Injection (CMDi) Engine Suite', async (t) => {
  await t.test('1. Detects raw string concatenation in child_process.exec', () => {
    const code = `
      import { exec } from 'child_process';
      export function ping(req, res) {
        const cmd = 'ping -c 1 ' + req.query.host;
        exec(cmd, (err, stdout) => {
          res.send(stdout);
        });
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].severity, 'CRITICAL')
    assert.ok(findings[0].ruleId.includes('cmdi'))
    assert.ok(findings[0].sink.includes('exec'))
  })

  await t.test('2. Detects template literal interpolation in child_process.exec', () => {
    const code = `
      import cp from 'child_process';
      export async function download(req) {
        cp.exec(\`curl -O \${req.body.url}\`, (err, stdout) => {
          console.log(stdout);
        });
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-template-literal')
  })

  await t.test('3. Detects synchronous shell execution in execSync', () => {
    const code = `
      import { execSync } from 'child_process';
      export function getGitLog(req) {
        const branch = req.params.branch;
        const output = execSync('git log ' + branch);
        return output.toString();
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].severity, 'CRITICAL')
  })

  await t.test('4. Detects shelljs.exec with tainted input', () => {
    const code = `
      import shell from 'shelljs';
      export function cleanup(req) {
        shell.exec('rm -rf /tmp/' + req.query.dirName);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.ok(findings[0].sink.includes('shell.exec'))
  })

  await t.test('5. Detects execa.command with dynamic template literal', () => {
    const code = `
      import execa from 'execa';
      export async function runScript(req) {
        return execa.command(\`npm run \${req.body.scriptName}\`);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
  })

  await t.test('6. Detects spawn with shell: true and tainted arguments', () => {
    const code = `
      import { spawn } from 'child_process';
      export function listFiles(req) {
        spawn('ls', ['-la', req.query.folder], { shell: true });
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-spawn-shell-option')
  })

  await t.test('7. Detects execFile with shell: true and dynamic arguments', () => {
    const code = `
      import { execFile } from 'child_process';
      export function runCat(req) {
        const options = { shell: true };
        execFile('cat', [req.body.filename], options);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-spawn-shell-option')
  })

  await t.test('8. Detects shell invocation with -c flag and tainted command string', () => {
    const code = `
      import { spawn } from 'child_process';
      export function executeSh(req) {
        spawn('sh', ['-c', 'echo ' + req.query.message]);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.ok(findings[0].message.includes('sh -c'))
  })

  await t.test('9. Detects dynamic executable binary passed to spawn', () => {
    const code = `
      import { spawn } from 'child_process';
      export function runUserBin(req) {
        const userBinary = req.query.binaryPath;
        spawn(userBinary, ['--help']);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-dynamic-executable')
  })

  await t.test('10. Detects inter-procedural helper function delegation', () => {
    const code = `
      import { exec } from 'child_process';
      function executeSystemCmd(cmd) {
        exec(cmd);
      }
      export function handleRequest(req, res) {
        executeSystemCmd('traceroute ' + req.body.target);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-interprocedural-helper')
  })

  await t.test('11. Detects command variable dynamically assembled via compound assignment', () => {
    const code = `
      import { exec } from 'child_process';
      export function buildReport(req) {
        let cmd = 'python3 generate_report.py';
        cmd += ' --format ' + req.query.format;
        exec(cmd);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].ruleId, 'ast/cmdi-stored-variable')
  })

  await t.test('12. Detects destructuring from request body', () => {
    const code = `
      import { exec } from 'child_process';
      export function handleAction(req) {
        const { targetServer } = req.body;
        exec(\`nslookup \${targetServer}\`);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-78')
    assert.equal(findings[0].severity, 'CRITICAL')
  })

  await t.test('13. ACCURACY VERIFICATION: Safe spawn with argument array and NO shell produces ZERO findings', () => {
    const code = `
      import { spawn } from 'child_process';
      export function safeGitCheckout(req) {
        // Safe: arguments are passed via array directly to execve(2), no shell interpolation
        spawn('git', ['checkout', req.body.branch]);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Safe spawn without shell must NOT produce findings')
  })

  await t.test('14. ACCURACY VERIFICATION: Safe static command execution produces ZERO findings', () => {
    const code = `
      import { exec, execSync } from 'child_process';
      const STATIC_CMD = 'npm test';
      export function runBuild() {
        exec('git status');
        execSync(STATIC_CMD);
        const a = 'ls';
        const b = ' -la';
        exec(a + b);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Pure static commands must NOT produce findings')
  })

  await t.test('15. ACCURACY VERIFICATION: Safe numeric/boolean casts produce ZERO findings', () => {
    const code = `
      import { exec } from 'child_process';
      export function killProcess(req) {
        const pid = parseInt(req.query.pid, 10);
        exec('kill -9 ' + pid);
        const limit = Number(req.body.limit);
        exec(\`head -n \${limit} /var/log/syslog\`);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Safe numeric casts must NOT produce findings')
  })

  await t.test('16. ACCURACY VERIFICATION: Safe shell quoting sanitizers produce ZERO findings', () => {
    const code = `
      import { exec } from 'child_process';
      import { quote } from 'shell-quote';
      export function search(req) {
        const safeQuery = quote([req.query.q]);
        exec('grep -r ' + safeQuery + ' /app/data');
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Sanitized shell arguments must NOT produce findings')
  })

  await t.test('17. ACCURACY VERIFICATION: Safe regex validation guard produces ZERO findings', () => {
    const code = `
      import { exec } from 'child_process';
      export function runCustom(req, res) {
        const branch = req.query.branch;
        if (!/^[a-zA-Z0-9_-]+$/.test(branch)) {
          return res.status(400).send('Invalid branch name');
        }
        exec(\`git checkout \${branch}\`);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Validated inputs via strict regex must NOT produce findings')
  })

  await t.test('18. ACCURACY VERIFICATION: Safe allowlist dictionary lookup produces ZERO findings', () => {
    const code = `
      import { exec } from 'child_process';
      const SCRIPT_MAP = {
        test: 'npm test',
        build: 'npm run build',
        lint: 'npm run lint',
      };
      export function executeAction(req) {
        const command = SCRIPT_MAP[req.query.action];
        if (command) {
          exec(command);
        }
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 0, 'Static dictionary lookups must NOT produce findings')
  })

  await t.test('19. ACCURACY VERIFICATION: Internal build / maintainer script (Axios bin/repo.js) produces ZERO false positives', () => {
    const code = `
      const cp = require('child_process');
      module.exports = function getCommits(options) {
        const since = options.since || 'HEAD~10';
        const until = options.until || 'HEAD';
        return cp.execSync(\`git log --format="%aN" \${since}...\${until}\`).toString();
      };
    `
    // Scanned as a build tool file path (e.g. bin/repo.js)
    const findings = runScan(code, 'bin/repo.js')
    assert.equal(findings.length, 0, 'Internal build scripts without untrusted HTTP sources must NOT produce false positives')
  })

  await t.test('20. MasterEngine registers XSS, SQLi, and CMDi engines seamlessly', () => {
    const registered = masterEngine.getEngines().map(e => e.id)
    assert.ok(registered.includes('xss'), 'MasterEngine should have xss engine')
    assert.ok(registered.includes('sqli'), 'MasterEngine should have sqli engine')
    assert.ok(registered.includes('cmdi'), 'MasterEngine should have cmdi engine')
  })
})
