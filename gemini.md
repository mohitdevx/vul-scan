# Project Directives & Design System: VulnScan

This document serves as the foundational source of truth for design, styling, architecture, and coding conventions across the `vuln-scan` repository.

---

## 1. Core UI / UX Design Directives

### 1.1 No Gradients, Glowing, Flickering, or Colored Dots
- **Zero Gradients**: Do NOT use linear, radial, or conic gradients on backgrounds, borders, texts, or cards. Use clean, solid, flat surfaces and subtle 1px borders.
- **Zero Glowing Effects**: Avoid neon drop shadows, outer box-glows (`box-shadow: 0 0 20px ...`), text-glows, or pulsating illuminated rings.
- **Zero Flickering / Distracting Animations**: Do NOT include strobe, bouncing, or flickering animations. Transitions must be minimal, crisp, and functional.
- **Zero Colored Status Dots**: Do NOT add decorative green, red, orange, or colored dots anywhere in headers, badges, or cards.

### 1.2 Understated, Professional Engineering Interface
- **Anti-"Vibe Coded" & Anti-AI Marketing Look**: Do NOT add generic cheesy marketing slogans (e.g. "Static Code Security Analysis", "OWASP Top 10 & CWE Verified", "Next-Gen AI Security"). Focus strictly on clean, functional developer utility.
- **High Typography Craft & Restraint**: Uses **Inter Variable** bundled locally with native system-ui fallback stack (`system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`). Enforces `font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11'` and explicit font inheritance for form inputs, buttons, and textareas.
- **Toaster / Notifications**: Minimalist, compact, Sonner/Radix-style toasts. Deep dark surface, hairline neutral border, clean typography, no gaudy colored borders or huge icons.

### 1.3 Limited Palette & Tailwind v4 Theme Variables
- **Centralized Colors**: ALL colors must be declared and maintained in `frontend/src/index.css` under the `@theme` block.
- **Restrained Monochromatic Palette**:
  - `canvas`: `#09090b` (pure deep neutral dark)
  - `surface`: `#121215` (flat card / modal surface)
  - `surface-hover`: `#18181b`
  - `surface-muted`: `#202024`
  - `border`: `#27272a` (subtle 1px border)
  - `border-subtle`: `#1c1c1f`
  - `text-primary`: `#f4f4f5` (crisp white)
  - `text-secondary`: `#a1a1aa` (neutral zinc)
  - `text-muted`: `#71717a`
  - `primary`: `#ffffff` (crisp solid white with dark text for high contrast action)
- No ad-hoc hex codes or rainbow badges.

### 1.4 Responsive Design
- The layout must adapt seamlessly from mobile devices (`<640px`), tablets (`640px - 1024px`), to wide desktop views (`>1024px`).

### 1.5 Iconography
- Standard icon library: **Remix Icons** (`@remixicon/react`).
- Maintain consistent icon sizing (`w-4 h-4` for compact metadata, `w-5 h-5` for standard actions) and neutral stroke weights.

### 1.6 Atomic Design & Component Reusability
- **Small & Reusable Components**: Break UI elements down into small, modular, single-responsibility components. Componentize any visual or functional element that repeats.
- **Atomic Hierarchy**:
  - **Atoms**: Base primitives (e.g., `Button`, `Badge`, `SeverityPill`, `Input`, `CodeSnippet`, `StatusDot`).
  - **Molecules**: Compound units combining atoms (e.g., `SearchBar`, `MetricStatCard`, `SeverityFilterGroup`, `RepoInputForm`, `TerminalWindow`).
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
3. Run full development environment from root via `pnpm dev`.
4. Adhere to Prettier formatting standards across the monorepo.
5. Test all builds via `pnpm run build` prior to verifying setup milestones.
6. Keep Docker containers isolated, lightweight, and multi-stage ready.


