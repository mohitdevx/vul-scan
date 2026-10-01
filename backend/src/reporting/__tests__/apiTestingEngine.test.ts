import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  discoverEndpointsInFile,
  discoverCodebaseEndpoints,
  generateRequestlyRuleSuite,
  RequestlyMcpClient,
  runDeterministicApiAudit,
} from '../../engine/api/index.js'

describe('API Testing & Security Engine Suite', () => {
  it('1. Discovers Express router endpoints with parameters and auth middlewares', () => {
    const code = `
      const express = require('express');
      const router = express.Router();
      const { requireAuth } = require('../middlewares/auth');

      router.get('/api/users/:id', requireAuth, async (req, res) => {
        const userId = req.params.id;
        const user = await db.users.findById(userId);
        res.json(user);
      });

      router.post('/api/users', async (req, res) => {
        const { username, email } = req.body;
        const newUser = await db.users.create(req.body);
        res.status(201).json(newUser);
      });

      module.exports = router;
    `

    const endpoints = discoverEndpointsInFile('src/routes/user.routes.js', code)
    assert.strictEqual(endpoints.length, 2)

    const getEp = endpoints.find(e => e.method === 'GET')
    assert.ok(getEp)
    assert.strictEqual(getEp.path, '/api/users/:id')
    assert.strictEqual(getEp.authRequired, true)
    assert.ok(getEp.parameters.some(p => p.name === 'id' && p.in === 'path'))

    const postEp = endpoints.find(e => e.method === 'POST')
    assert.ok(postEp)
    assert.strictEqual(postEp.path, '/api/users')
    assert.strictEqual(postEp.authRequired, false)
  })

  it('2. Discovers Next.js App Router API endpoints', () => {
    const code = `
      import { NextResponse } from 'next/server';

      export async function GET(request: Request) {
        return NextResponse.json({ status: 'ok' });
      }

      export async function POST(request: Request) {
        const body = await request.json();
        return NextResponse.json(body, { status: 201 });
      }
    `

    const endpoints = discoverEndpointsInFile('src/app/api/health/route.ts', code)
    assert.strictEqual(endpoints.length, 2)
    assert.ok(endpoints.some(e => e.method === 'GET' && e.path === '/api/health'))
    assert.ok(endpoints.some(e => e.method === 'POST' && e.path === '/api/health'))
  })

  it('3. Generates Requestly security testing rules and group suite', () => {
    const endpoints = [
      {
        id: 'EP-1',
        method: 'GET' as const,
        path: '/api/accounts/:id',
        filePath: 'routes/account.js',
        line: 10,
        framework: 'express' as const,
        authRequired: true,
        authMiddlewares: ['requireAuth'],
        parameters: [{ name: 'id', in: 'path' as const, required: true }],
        codeSnippet: "router.get('/api/accounts/:id', ...)",
        enclosingScopeCode: '...',
      },
      {
        id: 'EP-2',
        method: 'POST' as const,
        path: '/api/settings',
        filePath: 'routes/settings.js',
        line: 25,
        framework: 'express' as const,
        authRequired: false,
        authMiddlewares: [],
        parameters: [],
        codeSnippet: "router.post('/api/settings', ...)",
        enclosingScopeCode: '...',
      },
    ]

    const suite = generateRequestlyRuleSuite(endpoints, 'https://api.example.com')
    assert.ok(suite.rules.length >= 4)
    assert.ok(suite.rules.some(r => r.name.includes('[API1 BOLA Test]')))
    assert.ok(suite.rules.some(r => r.name.includes('[API2 Auth Bypass Test]')))
    assert.ok(suite.rules.some(r => r.name.includes('[API3 Mass Assignment Test]')))

    const mcpClient = new RequestlyMcpClient()
    const mcpConfig = mcpClient.getMcpConfigJson()
    assert.ok(mcpConfig.mcpServers['requestly-security-suite'])
  })

  it('4. Detects BOLA and Mass Assignment flaws via deterministic audit', () => {
    const vulnerableEndpoint = {
      id: 'EP-VULN-1',
      method: 'GET' as const,
      path: '/api/documents/:id',
      filePath: 'src/routes/doc.js',
      line: 12,
      framework: 'express' as const,
      authRequired: true,
      authMiddlewares: ['auth'],
      parameters: [{ name: 'id', in: 'path' as const, required: true }],
      codeSnippet: "router.get('/api/documents/:id', auth, async (req, res) => {",
      enclosingScopeCode: `
        router.get('/api/documents/:id', auth, async (req, res) => {
          const doc = await db.documents.findUnique({ where: { id: req.params.id } });
          res.json(doc);
        });
      `,
    }

    const findings = runDeterministicApiAudit(vulnerableEndpoint)
    assert.ok(findings.length > 0)
    assert.ok(findings.some(f => f.category.includes('Broken Object Level Authorization')))
  })
})
