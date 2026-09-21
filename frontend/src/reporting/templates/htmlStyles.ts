/**
 * CSS Styles for the Standalone HTML Security Report
 * Pure CSS with CSS variables, responsive grid/flex layout, syntax highlighting, and accessibility.
 */

export const HTML_REPORT_STYLES = `
:root {
  --bg-canvas: #09090b;
  --bg-surface: #121215;
  --bg-surface-elevated: #18181b;
  --bg-surface-hover: #202024;
  --border-subtle: #1f1f23;
  --border-default: #27272a;
  --border-bright: #3f3f46;

  --text-primary: #f4f4f5;
  --text-secondary: #a1a1aa;
  --text-muted: #71717a;
  --text-disabled: #52525b;

  --severity-critical: #ef4444;
  --severity-critical-bg: rgba(239, 68, 68, 0.12);
  --severity-critical-border: rgba(239, 68, 68, 0.3);

  --severity-high: #f97316;
  --severity-high-bg: rgba(249, 115, 22, 0.12);
  --severity-high-border: rgba(249, 115, 22, 0.3);

  --severity-medium: #eab308;
  --severity-medium-bg: rgba(234, 179, 8, 0.12);
  --severity-medium-border: rgba(234, 179, 8, 0.3);

  --severity-low: #3b82f6;
  --severity-low-bg: rgba(59, 130, 246, 0.12);
  --severity-low-border: rgba(59, 130, 246, 0.3);

  --severity-info: #71717a;
  --severity-info-bg: rgba(113, 113, 122, 0.12);
  --severity-info-border: rgba(113, 113, 122, 0.3);

  --status-clean: #10b981;
  --status-clean-bg: rgba(16, 185, 129, 0.12);
  --status-clean-border: rgba(16, 185, 129, 0.3);

  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background-color: var(--bg-canvas);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

a {
  color: var(--text-primary);
  text-decoration: underline;
  text-underline-offset: 3px;
}
a:hover {
  color: #fff;
}

/* Header Navbar */
.report-header {
  position: sticky;
  top: 0;
  z-index: 100;
  background-color: rgba(9, 9, 11, 0.92);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border-default);
  padding: 12px 24px;
}
.report-header-inner {
  max-width: 1440px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.header-brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-logo {
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 15px;
  letter-spacing: -0.02em;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 6px;
}
.brand-version {
  font-size: 11px;
  font-family: var(--font-mono);
  padding: 2px 6px;
  background: var(--bg-surface-elevated);
  border: 1px solid var(--border-default);
  border-radius: 4px;
  color: var(--text-muted);
}
.header-meta {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-secondary);
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-family: var(--font-mono);
  font-weight: 500;
  cursor: pointer;
  border: 1px solid var(--border-default);
  background: var(--bg-surface);
  color: var(--text-secondary);
  transition: all 0.15s ease;
  text-decoration: none;
}
.btn:hover {
  background: var(--bg-surface-hover);
  color: var(--text-primary);
  border-color: var(--border-bright);
}
.btn-primary {
  background: #fff;
  color: #09090b;
  border-color: #fff;
}
.btn-primary:hover {
  background: #e4e4e7;
  color: #09090b;
}

/* Posture Summary Ribbon */
.posture-ribbon {
  max-width: 1440px;
  margin: 24px auto 0;
  padding: 0 24px;
}
.posture-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-default);
  border-radius: 12px;
  padding: 20px 24px;
  display: grid;
  grid-template-columns: 1.5fr 2fr;
  gap: 24px;
  align-items: center;
}
.posture-left {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.posture-badge-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.posture-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 999px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.posture-title {
  font-size: 18px;
  font-weight: 700;
  color: #fff;
  letter-spacing: -0.01em;
}
.posture-desc {
  font-size: 12px;
  color: var(--text-secondary);
  max-width: 520px;
}
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
}
.metric-box {
  background: var(--bg-canvas);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 10px 12px;
  text-align: center;
}
.metric-label {
  font-size: 10px;
  font-family: var(--font-mono);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
}
.metric-value {
  font-size: 20px;
  font-family: var(--font-mono);
  font-weight: 700;
  margin-top: 2px;
}

/* Main Layout */
.report-main {
  max-width: 1440px;
  margin: 24px auto 48px;
  padding: 0 24px;
  display: grid;
  grid-template-columns: 360px 1fr;
  gap: 24px;
  align-items: start;
}

/* Sidebar / Findings Ledger */
.findings-sidebar {
  position: sticky;
  top: 72px;
  background: var(--bg-surface);
  border: 1px solid var(--border-default);
  border-radius: 12px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  max-height: calc(100vh - 96px);
}
.sidebar-toolbar {
  padding: 12px;
  border-bottom: 1px solid var(--border-default);
  display: flex;
  flex-direction: column;
  gap: 8px;
  background: rgba(18, 18, 21, 0.95);
}
.search-input {
  width: 100%;
  background: var(--bg-canvas);
  border: 1px solid var(--border-default);
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 12px;
  font-family: var(--font-mono);
  color: var(--text-primary);
  outline: none;
}
.search-input:focus {
  border-color: var(--border-bright);
}
.filter-pills {
  display: flex;
  align-items: center;
  gap: 4px;
  overflow-x: auto;
  padding-bottom: 2px;
}
.filter-pill {
  font-size: 11px;
  font-family: var(--font-mono);
  padding: 3px 8px;
  border-radius: 4px;
  background: transparent;
  color: var(--text-muted);
  border: none;
  cursor: pointer;
  white-space: nowrap;
}
.filter-pill:hover {
  color: var(--text-secondary);
}
.filter-pill.active {
  background: var(--bg-surface-hover);
  color: #fff;
  font-weight: 600;
}
.findings-list {
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}
.finding-nav-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px 14px;
  border-bottom: 1px solid var(--border-subtle);
  text-decoration: none;
  color: var(--text-secondary);
  transition: all 0.15s ease;
  position: relative;
}
.finding-nav-item:hover {
  background: var(--bg-surface-hover);
  color: var(--text-primary);
}
.finding-nav-item.active {
  background: var(--bg-surface-elevated);
  color: #fff;
  border-left: 3px solid var(--severity-high);
}
.finding-nav-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 11px;
  font-family: var(--font-mono);
}
.finding-nav-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.3;
}
.finding-nav-meta {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Findings Details Content */
.findings-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.finding-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-default);
  border-radius: 12px;
  overflow: hidden;
  scroll-margin-top: 80px;
}
.finding-card-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-default);
  background: rgba(24, 24, 27, 0.4);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.finding-header-left {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.finding-badge-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid transparent;
}
.finding-card-title {
  font-size: 16px;
  font-weight: 700;
  color: #fff;
}
.finding-location-bar {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 2px;
}
.finding-body {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.section-kicker {
  font-size: 11px;
  font-family: var(--font-mono);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  margin-bottom: 6px;
}

/* Taint Flow Visual Diagram */
.taint-flow-container {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding: 16px;
  background: var(--bg-canvas);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}
.taint-step-card {
  background: var(--bg-surface-elevated);
  border: 1px solid var(--border-default);
  border-radius: 6px;
  padding: 8px 12px;
  min-width: 140px;
  flex: 1;
}
.taint-step-type {
  font-size: 9.5px;
  font-family: var(--font-mono);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}
.taint-step-expr {
  font-size: 12px;
  font-family: var(--font-mono);
  font-weight: 600;
  color: var(--text-primary);
  margin-top: 2px;
  word-break: break-all;
}
.taint-step-desc {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}
.taint-arrow {
  color: var(--text-muted);
  font-size: 16px;
  font-weight: bold;
}

/* Code Evidence Box */
.code-evidence-box {
  background: #09090c;
  border: 1px solid var(--border-default);
  border-radius: 8px;
  overflow: hidden;
  font-family: var(--font-mono);
  font-size: 12px;
}
.code-header {
  padding: 8px 14px;
  background: rgba(18, 18, 21, 0.8);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 11px;
}
.code-table {
  width: 100%;
  border-collapse: collapse;
}
.code-table td {
  padding: 2px 8px;
  vertical-align: top;
}
.code-gutter {
  width: 44px;
  text-align: right;
  color: var(--text-disabled);
  user-select: none;
}
.code-gutter.flagged {
  color: var(--severity-critical);
  font-weight: 700;
}
.code-line-content {
  white-space: pre-wrap;
  word-break: break-all;
}
.code-row.flagged {
  background: rgba(239, 68, 68, 0.08);
  border-left: 2px solid var(--severity-critical);
}

/* Syntax Highlighting Tokens */
.token-keyword { color: #c792ea; }
.token-string { color: #c3e88d; }
.token-number { color: #f78c6c; }
.token-sink { color: #ff5370; font-weight: 700; }
.token-sink-highlight { background: rgba(239, 68, 68, 0.25); color: #fca5a5; padding: 1px 4px; border-radius: 3px; font-weight: 700; }
.token-comment { color: #546e7a; font-style: italic; }

/* AI Advisory Box */
.ai-advisory-box {
  background: rgba(18, 18, 21, 0.5);
  border-left: 3px solid var(--status-clean);
  border-radius: 0 8px 8px 0;
  padding: 14px 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.ai-meta-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--text-muted);
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border-subtle);
}
.ai-reasoning-text {
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--text-secondary);
}

/* Remediation Box */
.remediation-box {
  background: var(--bg-canvas);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 14px 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.remediation-code {
  background: #09090c;
  border: 1px solid var(--border-default);
  border-radius: 6px;
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-primary);
  white-space: pre-wrap;
}

/* Responsive */
@media (max-width: 1024px) {
  .posture-card {
    grid-template-columns: 1fr;
  }
  .report-main {
    grid-template-columns: 1fr;
  }
  .findings-sidebar {
    position: static;
    max-height: 380px;
  }
}
@media (max-width: 640px) {
  .metrics-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .header-meta {
    display: none;
  }
  .taint-flow-container {
    flex-direction: column;
    align-items: stretch;
  }
  .taint-arrow {
    text-align: center;
    transform: rotate(90deg);
  }
}
`
