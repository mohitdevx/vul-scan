# VulnScan

> Deterministic AST static analysis paired with local AI verification and 1-click automated pull request remediation.

VulnScan is a modern static application security testing (SAST) platform designed for JavaScript and TypeScript codebases. It combines precise abstract syntax tree (AST) taint-flow analysis with local LLM verification to detect vulnerabilities, eliminate false positives, and dispatch production-ready fix PRs directly to GitHub repositories.

---

## Key Features

- **Deterministic AST & Taint Flow Analysis**
  Deep traversal of AST nodes using Babel parser. Accurately maps sources (`req.query`, `req.body`, `window.location`) to dangerous sinks (`exec`, `eval`, `innerHTML`, SQL query builders) while checking sanitization barriers.
- **Local AI Verification & Triage**
  Optional verification pipeline using local LLMs (via Ollama and Qwen 2.5 Coder). Filters out unreachable paths and contextually harmless code before alerting engineers.
- **1-Click Fix & GitHub PR Dispatch**
  Generates contextual diffs and code patches. Review, edit patches in-place, and open automated Pull Requests on GitHub directly from the web interface.
- **Multi-Format Security Reporting**
  Generates structured HTML, Markdown, and JSON executive summaries and technical vulnerability breakdowns with CWE and OWASP mappings.
- **Minimalist Engineering Interface**
  Clean, high-craft dark mode interface built with React 19, Tailwind CSS v4, and Inter Variable typography. Zero neon glows or marketing bloat.

---

## Architecture

```mermaid
flowchart TD
    subgraph Client ["Frontend (React 19 + Vite + Tailwind v4)"]
        UI[Web Dashboard]
        LiveScan[Real-time Scan Progress]
        FixEditor[In-Place Patch Editor & PR Modal]
    end

    subgraph API ["Backend Service (Node.js + Express + TypeScript)"]
        Router[REST API Layer]
        Auth[JWT & GitHub OAuth]
        Queue[Redis Scan Queue]
    end

    subgraph Engine ["SAST Engine & Verification"]
        ASTParser[AST Parser & Visitor]
        TaintEngine[Taint Flow Analyzer]
        Ollama[Local LLM Verification Engine]
    end

    subgraph Storage ["Data Layer"]
        DB[(PostgreSQL + Prisma)]
        RedisCache[(Redis Cache & State)]
    end

    UI --> Router
    Router --> Queue
    Queue --> ASTParser
    ASTParser --> TaintEngine
    TaintEngine --> Ollama
    Ollama --> Router
    Router --> DB
    Router --> RedisCache
    FixEditor -->|Octokit / GitHub API| GitHub[(GitHub Repository)]
```

---

## Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 19, TypeScript, Vite 8, Tailwind CSS v4, Remix Icons, Inter Variable |
| **Backend** | Node.js (v20+), Express.js, TypeScript, Zod, tsx |
| **Database & ORM** | PostgreSQL, Prisma ORM, Redis (ioredis) |
| **Analysis Engine** | `@babel/parser`, `@babel/traverse`, AST Taint Tracking |
| **AI Verification** | LangChain Core, `@langchain/ollama` (Qwen 2.5 Coder) |
| **Monorepo Tooling**| `pnpm` workspaces, Docker & Docker Compose |

---

## Repository Structure

```text
vul-scan/
├── backend/
│   ├── prisma/                # Prisma schema & migrations
│   ├── src/
│   │   ├── config/            # Environment & database clients
│   │   ├── controllers/       # Scan, repo, and auth controllers
│   │   ├── engine/            # AST parsing & taint tracking engines
│   │   ├── middlewares/       # JWT auth & error handling
│   │   ├── reporting/         # HTML, Markdown & JSON report generators
│   │   ├── routes/            # REST API endpoints
│   │   └── services/          # GitHub, Ollama & workspace services
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/        # Atomic UI components (atoms, molecules, organisms)
│   │   ├── pages/             # Dashboard, Scan, Report & Auth pages
│   │   ├── services/          # Axios/fetch API layer
│   │   └── index.css          # Centralized Tailwind v4 theme variables
│   └── package.json
├── docker-compose.yml         # Production multi-container composition
├── docker-compose.dev.yml     # Local database & Redis services
├── pnpm-workspace.yaml        # Monorepo workspace configuration
└── package.json               # Root scripts
```

---

## Quick Start

### Prerequisites

- **Node.js**: `v20.0.0` or higher
- **pnpm**: `v11.0.0` or higher
- **Docker & Docker Compose** (for PostgreSQL and Redis)
- **Ollama** *(optional)*: For local AI validation (`ollama pull qwen2.5-coder:1.5b`)

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/<your-username>/vul-scan.git
cd vul-scan
pnpm install
```

### 2. Configure Environment Variables

Copy the example environment template to create `.env`:

```bash
cp .env.example .env
```

Key environment configuration:

```env
# Database & Cache
POSTGRES_USER=vulnscan
POSTGRES_PASSWORD=vulnscan_password
POSTGRES_DB=vulnscan
DATABASE_URL=postgresql://vulnscan:vulnscan_password@localhost:5432/vulnscan?schema=public
REDIS_URL=redis://localhost:6379

# Backend
PORT=4000
JWT_SECRET=your_super_secret_jwt_key
WORKSPACE_DIR=./tmp/scans
GITHUB_TOKEN=your_github_pat_for_prs

# Local AI Engine (Optional)
OLLAMA_BASE_URL=http://127.0.0.1:11434
AI_MODEL=qwen2.5-coder:1.5b
AI_VALIDATION_ENABLED=true

# Frontend
VITE_API_BASE_URL=http://localhost:4000
```

### 3. Start Database & Redis

Start local PostgreSQL and Redis containers:

```bash
pnpm docker:dev
```

Push the database schema with Prisma:

```bash
pnpm db:push
pnpm db:generate
```

### 4. Run Development Server

Start both backend and frontend concurrently:

```bash
pnpm dev
```

- **Frontend**: [http://localhost:5173](http://localhost:5173)
- **Backend API**: [http://localhost:4000](http://localhost:4000)
- **Health Check**: [http://localhost:4000/api/health](http://localhost:4000/api/health)

---

## Running with Docker Compose

To start the entire stack (PostgreSQL, Redis, Backend API, and Frontend) in isolated containers:

```bash
pnpm docker:up
```

To stop all services:

```bash
pnpm docker:down
```

---

## Vulnerability Detection Scope

| Category | Examples / Sinks Analyzed |
|---|---|
| **Cross-Site Scripting (XSS)** | `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `outerHTML`, unescaped JSX interpolations |
| **Command Injection** | `child_process.exec`, `child_process.execSync`, `child_process.spawn`, `eval`, `Function` constructors |
| **SQL & Database Injection** | Raw query interpolations, unsanitized ORM inputs, NoSQL `$where` sinks |
| **Authentication & Sessions** | Missing JWT verification, hardcoded secrets, weak cookie flags (`httpOnly`, `secure`, `sameSite`) |
| **Path Traversal** | Unsanitized `fs.readFile`, `path.join` with untrusted input paths |

---

## API Overview

### Scans & Analysis
- `POST /api/scans` — Trigger a scan for a repository URL or local path.
- `GET /api/scans` — List historical scans for the authenticated user.
- `GET /api/scans/:id` — Retrieve scan results, status, metrics, and findings.
- `POST /api/scans/:id/reverify` — Re-run AI validation pipeline over existing AST findings.
- `GET /api/scans/:id/report` — Export scan report (supports `format=html`, `format=markdown`, or `format=json`).

### Remediation & Pull Requests
- `POST /api/scans/:id/findings/:findingId/pr` — Open a GitHub Pull Request with the specified (or customized) patch.

### Authentication
- `POST /api/auth/register` — Create a local user account.
- `POST /api/auth/login` — Authenticate and receive JWT cookie.
- `GET /api/auth/me` — Get current user profile.

---

## Testing & Quality Checks

```bash
# Run unit & reporting tests
pnpm test

# Build frontend and backend
pnpm build

# Lint frontend codebase
pnpm --filter frontend lint
```

---

## License

This project is licensed under the MIT License.
