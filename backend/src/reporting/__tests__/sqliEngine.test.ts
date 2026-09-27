import test from 'node:test'
import assert from 'node:assert/strict'
import { parseSourceCode } from '../../engine/parser.js'
import { masterEngine, sqliEngine } from '../../engine/index.js'
import type { EngineContext } from '../../engine/types.js'


function runScan(code: string, fileName = 'src/service.ts') {
  const ast = parseSourceCode(code, fileName)
  assert.ok(ast, 'AST parsing should succeed')
  const ctx: EngineContext = {
    filePath: fileName,
    fileContent: code,
    lines: code.split('\n'),
  }
  return sqliEngine.analyze(ast, ctx)
}

test('SQL Injection (SQLi) Engine Suite', async (t) => {
  await t.test('1. Detects raw string concatenation in db.query', () => {
    const code = `
      import { db } from './db';
      export async function getUser(req, res) {
        const query = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
        const result = await db.query(query);
        res.json(result);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].severity, 'CRITICAL')
    assert.ok(findings[0].ruleId.includes('sqli'))
    assert.ok(findings[0].message.includes('db.query'))
  })

  await t.test('2. Detects template literal interpolation in db.query', () => {
    const code = `
      import { pool } from './pool';
      export async function getProfile(req, res) {
        const result = await pool.query(\`SELECT * FROM profiles WHERE email = '\${req.body.email}'\`);
        return result;
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].ruleId, 'ast/sqli-template-literal')
  })

  await t.test('3. Detects unsafe Prisma ORM methods ($queryRawUnsafe, $executeRawUnsafe)', () => {
    const code = `
      import { prisma } from './prisma';
      export async function search(req) {
        return prisma.$queryRawUnsafe(\`SELECT * FROM products WHERE name LIKE '%\${req.query.q}%'\`);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].ruleId, 'ast/sqli-template-literal')
  })

  await t.test('4. Detects Prisma.raw() wrapped inside $queryRaw', () => {
    const code = `
      import { prisma, Prisma } from './prisma';
      export async function filter(req) {
        const rawSql = Prisma.raw("SELECT * FROM items WHERE category = '" + req.query.category + "'");
        return prisma.$queryRaw(rawSql);
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.ok(findings[0].ruleId.includes('sqli'))
  })

  await t.test('5. Detects Knex raw where clauses (whereRaw, havingRaw) with concatenated input', () => {
    const code = `
      import knex from 'knex';
      export async function findUser(req) {
        return knex('users').whereRaw("name = '" + req.query.name + "'");
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].ruleId, 'ast/sqli-orm-unsafe-call')
  })

  await t.test('6. Detects TypeORM query builder unparameterized where clauses', () => {
    const code = `
      export async function getOrders(qb, req) {
        return qb.where("order.customerId = " + req.params.customerId).getMany();
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].ruleId, 'ast/sqli-typeorm-where')
  })

  await t.test('7. Detects inter-procedural helper function delegation', () => {
    const code = `
      function executeCustomSql(sqlString) {
        return db.query(sqlString);
      }
      export function handleRequest(req) {
        return executeCustomSql("SELECT * FROM logs WHERE tag = '" + req.query.tag + "'");
      }
    `
    const findings = runScan(code)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].cwe, 'CWE-89')
    assert.equal(findings[0].ruleId, 'ast/sqli-interprocedural-helper')
  })

  await t.test('8. ACCURACY VERIFICATION: Safe parameterized queries produce ZERO findings', () => {
    const safeQueries = `
      import { db, pool, knex, prisma } from './db';
      
      // pg / mysql parameterized array
      await db.query("SELECT * FROM users WHERE id = $1 AND role = $2", [req.query.id, req.query.role]);
      await pool.execute("SELECT * FROM users WHERE id = ?", [req.body.id]);
      
      // Knex parameterized bindings
      await knex.raw("SELECT * FROM users WHERE id = ?", [req.params.id]);
      await knex.raw("SELECT * FROM users WHERE id = :id", { id: req.params.id });
      
      // Prisma standard safe tagged template literal
      await prisma.$queryRaw\`SELECT * FROM users WHERE id = \${req.query.id}\`;
      await prisma.$executeRaw\`UPDATE users SET active = 1 WHERE id = \${req.query.id}\`;
      
      // TypeORM parameterized condition
      await qb.where("user.id = :id", { id: req.params.id }).getOne();
    `
    const findings = runScan(safeQueries)
    assert.equal(findings.length, 0, 'Safe parameterized queries must not trigger false positives')
  })

  await t.test('9. ACCURACY VERIFICATION: Safe numeric/boolean casts produce ZERO findings', () => {
    const safeCasts = `
      import { db } from './db';
      
      export async function getById(req) {
        const id = parseInt(req.query.id, 10);
        await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
        
        const count = Number(req.params.count);
        await db.query("SELECT * FROM items LIMIT " + count);
        
        const offset = Math.floor(req.query.page) * 20;
        await db.query(\`SELECT * FROM items OFFSET \${offset}\`);
        
        const isActive = Boolean(req.body.active);
        await db.query(\`SELECT * FROM users WHERE active = \${isActive}\`);
      }
    `
    const findings = runScan(safeCasts)
    assert.equal(findings.length, 0, 'Safe numeric and boolean casts must not trigger false positives')
  })

  await t.test('10. ACCURACY VERIFICATION: Safe constant folding & static queries produce ZERO findings', () => {
    const staticQueries = `
      import { db } from './db';
      
      const BASE_QUERY = "SELECT * FROM users WHERE status = 'ACTIVE'";
      const ORDER = " ORDER BY created_at DESC";
      
      export async function getActiveUsers() {
        const sql = BASE_QUERY + ORDER;
        return db.query(sql);
      }
      
      export async function countUsers() {
        return db.query(\`SELECT COUNT(*) FROM users\`);
      }
    `
    const findings = runScan(staticQueries)
    assert.equal(findings.length, 0, 'Static SQL queries must not trigger false positives')
  })

  await t.test('11. ACCURACY VERIFICATION: Safe SQL escaping functions produce ZERO findings', () => {
    const escapedQueries = `
      import { db } from './db';
      import mysql from 'mysql2';
      import sqlstring from 'sqlstring';
      
      export async function safeSearch(req) {
        const escaped = mysql.escape(req.query.term);
        await db.query("SELECT * FROM articles WHERE title = " + escaped);
        
        const safeInput = sqlstring.escape(req.body.input);
        await db.query(\`SELECT * FROM comments WHERE content = \${safeInput}\`);
      }
    `
    const findings = runScan(escapedQueries)
    assert.equal(findings.length, 0, 'Escaped SQL inputs must not trigger false positives')
  })

  await t.test('12. MasterEngine registers both XSS and SQLi engines seamlessly', () => {
    const engines = masterEngine.getEngines()
    assert.ok(engines.some(e => e.id === 'xss'))
    assert.ok(engines.some(e => e.id === 'sqli'))
    
    const combinedCode = `
      // XSS vulnerability
      element.innerHTML = req.query.userInput;
      
      // SQLi vulnerability
      db.query("SELECT * FROM users WHERE id = " + req.params.id);
    `
    const ast = parseSourceCode(combinedCode, 'app.ts')
    const ctx: EngineContext = {
      filePath: 'app.ts',
      fileContent: combinedCode,
      lines: combinedCode.split('\n'),
    }
    const findings = masterEngine.analyze(ast, ctx)
    assert.equal(findings.length, 2)
    assert.ok(findings.some(f => f.cwe === 'CWE-79'))
    assert.ok(findings.some(f => f.cwe === 'CWE-89'))
  })
})
