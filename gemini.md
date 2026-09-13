# Project Directives & Design System: VulnScan

This document serves as the foundational source of truth for design, styling, architecture, and coding conventions across the `vuln-scan` repository.

---

## 1. Core UI / UX Design Directives

### 1.1 No Gradients, Glowing, or Flickering
- **Zero Gradients**: Do NOT use linear, radial, or conic gradients on backgrounds, borders, texts, or cards. Use clean, solid, flat surfaces and subtle 1px borders.
- **Zero Glowing Effects**: Avoid neon drop shadows, outer box-glows (`box-shadow: 0 0 20px ...`), text-glows, or pulsating illuminated rings.
- **Zero Flickering / Distracting Animations**: Do NOT include strobe, bouncing, or flickering animations. Transitions must be minimal, crisp, and functional (e.g., standard 150ms opacity/color transitions on interactive states).

### 1.2 Professional & Aesthetic Security Engineering Interface
- **Anti-"Vibe Coded" / Anti-AI Look**: The application must look like enterprise-grade developer tooling (e.g., GitHub Advanced Security, Linear, Semgrep, Datadog), not an overstyled generic AI template or crypto landing page.
- **High Information Density & Clarity**: Prioritize scan telemetry, file path breadcrumbs, code diff snippets, CWE / OWASP tags, and actionable remediation steps.
- **Typography & Layout**: Clean sans-serif and monospace fonts for technical data, crisp borders, predictable navigation, and structured tables/lists.

### 1.3 Limited Palette & Tailwind v4 Theme Variables
- **Centralized Colors**: ALL colors must be declared and maintained in `frontend/src/index.css` under the `@theme` block or CSS variables.
- **Restrained Palette**:
  - `canvas`: `#090d16` (deep dark background)
  - `surface`: `#111827` (card / container surface)
  - `surface-hover`: `#1f2937`
  - `surface-muted`: `#1a2234`
  - `border`: `#2d3748`
  - `border-subtle`: `#1e293b`
  - `text-primary`: `#f8fafc`
  - `text-secondary`: `#94a3b8`
  - `text-muted`: `#64748b`
  - `primary`: `#2563eb` (focused action color)
  - Severity Badges:
    - Critical: `#dc2626`
    - High: `#ea580c`
    - Medium: `#d97706`
    - Low: `#0284c7`
    - Clean / Pass: `#16a34a`
- No ad-hoc hex codes scattered in component JSX. Only use Tailwind theme tokens (e.g., `bg-surface`, `text-text-primary`, `border-border`).

### 1.4 Responsive Design
- The layout must adapt seamlessly from mobile devices (`<640px`), tablets (`640px - 1024px`), to wide desktop security dashboards (`>1024px`).
- Tables and code viewer panes must support horizontal overflow scrolling cleanly without breaking parent containers.

### 1.5 Iconography
- Standard icon library: **Remix Icons** (`@remixicon/react`).
- Maintain consistent icon sizing (`w-4 h-4` for compact metadata, `w-5 h-5` for standard actions) and neutral stroke weights.

### 1.6 Atomic Design & Component Reusability
- **Small & Reusable Components**: Break UI elements down into small, modular, single-responsibility components. Componentize any visual or functional element that repeats.
- **Atomic Hierarchy**:
  - **Atoms**: Base primitives (e.g., `Button`, `Badge`, `SeverityPill`, `Input`, `CodeSnippet`, `StatusDot`).
  - **Molecules**: Compound units combining atoms (e.g., `SearchBar`, `MetricStatCard`, `SeverityFilterGroup`, `RepoInputForm`).
  - **Organisms**: Complex sections (e.g., `FindingsTable`, `ScanProgressPanel`, `VulnerabilityDetailDrawer`, `CodeViewer`).
- **Pre-Creation Verification Requirement**: Before authoring any new markup or UI feature, inspect existing component folders (`frontend/src/components/`) to check if a component already exists or can be cleanly extended with props. Never duplicate repeated JSX, styling, or badge logic inline.


---

## 2. Technical Stack & Architecture

- **Frontend**:
  - React 19 + TypeScript
  - Vite 8
  - Tailwind CSS v4 (configured via `@tailwindcss/vite` and `index.css`)
  - Remix Icons (`@remixicon/react`)
- **Backend**:
  - Node.js (v20+) + TypeScript
  - Express.js
  - Zod for payload and schema validations
  - Modular scanner engine architecture
- **Vulnerability Scanner Modules**:
  - `XSSScanner`: Detects reflected, stored, and DOM XSS vulnerabilities (e.g., `dangerouslySetInnerHTML`, unescaped template renders).
  - `InjectionScanner`: Identifies Command Injection (`exec`, `spawn`, `child_process`) and SQL Injection patterns.
  - `AuthScanner`: Detects insecure API authentication flows (missing JWT verification, hardcoded tokens, weak CORS).
  - `SessionScanner`: Checks session fixation, insecure cookie flags (`httpOnly`, `secure`, `sameSite`), and weak session stores.

---

## 3. Engineering & Delivery Rules

1. Package Manager: **pnpm** (v11+) workspace monorepo. Never commit `package-lock.json` or `yarn.lock`.
2. Keep configuration files uniform and strictly typed.
3. Adhere to Prettier formatting standards across the monorepo.
4. Test all builds via `pnpm run build` prior to verifying setup milestones.
5. Keep Docker containers isolated, lightweight, and multi-stage ready.

