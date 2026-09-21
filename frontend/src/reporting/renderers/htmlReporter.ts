import type { ReportRenderer } from '../renderer.js'
import type { SecurityReport, TaintFlow } from '../types.js'
import { getSeverityMeta } from '../severity.js'
import { escapeHtml, escapeAttribute, sanitizeElementId, highlightCodeLineHtml } from '../utils/escape.js'
import { HTML_REPORT_STYLES } from '../templates/htmlStyles.js'
import { HTML_REPORT_SCRIPTS } from '../templates/htmlScripts.js'

export class HtmlReporter implements ReportRenderer<string> {
  public readonly name = 'HtmlReporter'
  public readonly format = 'html'
  public readonly contentType = 'text/html; charset=utf-8'

  public render(report: SecurityReport): string {
    const { metadata, summary, findings, methodology } = report
    const dist = summary.distribution

    const pageTitle = `VulScan Security Assessment - ${escapeHtml(metadata.target.repositoryName)} (${escapeHtml(metadata.target.branch)})`

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="VulScan SAST Security Assessment Report for ${escapeAttribute(metadata.target.repositoryName)}">
  <title>${pageTitle}</title>
  <style>
${HTML_REPORT_STYLES}
  </style>
</head>
<body>

  <!-- Top Sticky Header -->
  <header class="report-header">
    <div class="report-header-inner">
      <div class="header-brand">
        <div class="brand-logo">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent-rose);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span>VulScan</span>
        </div>
      </div>

      <div class="header-meta">
        <span><strong>Target:</strong> ${escapeHtml(metadata.target.repositoryName)} [${escapeHtml(metadata.target.branch)}]</span>
        <span>•</span>
        <span><strong>Scanned:</strong> ${new Date(metadata.scan.timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</span>
        <span>•</span>
        <span><strong>Duration:</strong> ${metadata.scan.durationMs}ms</span>
      </div>

      <div class="header-actions">
        <button type="button" class="btn" onclick="window.print()" title="Print report or save as PDF">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect width="12" height="8" x="6" y="14"/></svg>
          <span>Print</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Posture Summary Ribbon -->
  <section class="posture-ribbon">
    <div class="posture-card">
      <div class="posture-left">
        <div class="posture-badge-row">
          <span class="posture-pill" style="background: ${dist.critical > 0 || dist.high > 0 ? 'var(--severity-high-bg)' : dist.medium > 0 ? 'var(--severity-medium-bg)' : 'var(--status-clean-bg)'}; color: ${dist.critical > 0 ? 'var(--severity-critical)' : dist.high > 0 ? 'var(--severity-high)' : dist.medium > 0 ? 'var(--severity-medium)' : 'var(--status-clean)'}; border: 1px solid ${dist.critical > 0 || dist.high > 0 ? 'var(--severity-high-border)' : dist.medium > 0 ? 'var(--severity-medium-border)' : 'var(--status-clean-border)'};">
            ${escapeHtml(summary.statusVerdict)}
          </span>
        </div>
        <div class="posture-title">${escapeHtml(summary.postureLabel)}</div>
        <div class="posture-desc">${escapeHtml(summary.executiveBrief)}</div>
      </div>

      <div class="metrics-grid">
        <div class="metric-box">
          <div class="metric-label">Critical</div>
          <div class="metric-value" style="color: var(--severity-critical);">${dist.critical}</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">High</div>
          <div class="metric-value" style="color: var(--severity-high);">${dist.high}</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">Medium</div>
          <div class="metric-value" style="color: var(--severity-medium);">${dist.medium}</div>
        </div>
        <div class="metric-box">
          <div class="metric-label">Low / Info</div>
          <div class="metric-value" style="color: var(--severity-low);">${dist.low + dist.info}</div>
        </div>
      </div>
    </div>
  </section>

  <!-- Main Report Explorer -->
  <main class="report-main">
    <!-- Left Sticky Finding Index -->
    <aside class="sidebar-nav">
      <div class="sidebar-search">
        <input
          id="finding-search-input"
          type="text"
          placeholder="Filter findings by rule, CWE, file..."
          aria-label="Filter findings"
        />
      </div>

      <div class="sidebar-filters">
        <button type="button" class="filter-btn active" data-filter="ALL">All (${findings.length})</button>
        <button type="button" class="filter-btn" data-filter="HIGH_CRITICAL">High/Crit (${dist.critical + dist.high})</button>
        <button type="button" class="filter-btn" data-filter="MEDIUM">Med (${dist.medium})</button>
        <button type="button" class="filter-btn" data-filter="CONFIRMED">Confirmed (${summary.confirmedCount})</button>
      </div>

      <div id="findings-nav-list" class="findings-nav-list">
        ${findings.map((f, idx) => {
          const meta = getSeverityMeta(f.severity)
          const safeId = sanitizeElementId(f.id)
          return `
            <a
              href="#${safeId}"
              class="finding-nav-item ${idx === 0 ? 'active' : ''}"
              data-severity="${escapeAttribute(f.severity)}"
              data-status="${escapeAttribute(f.status)}"
              data-search="${escapeAttribute(`${f.id} ${f.rule.name} ${f.rule.cwe} ${f.location.file} ${f.taintFlow.sink.expression} ${f.taintFlow.source.expression}`)}"
            >
              <div class="finding-nav-header">
                <span style="color: ${meta.color}; font-weight: 700; display: inline-flex; align-items: center; gap: 5px;">
                  <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:${meta.color};"></span>
                  ${escapeHtml(f.severity)}
                </span>
                <span class="badge" style="background: var(--bg-canvas); color: var(--text-secondary); border-color: var(--border-subtle);">${escapeHtml(f.rule.cwe)}</span>
              </div>
              <div class="finding-nav-title">${escapeHtml(f.rule.name)}</div>
              <div class="finding-nav-meta">${escapeHtml(f.location.file)}:${f.location.line}</div>
            </a>
          `
        }).join('')}
      </div>
    </aside>

    <!-- Right Content: Detailed Finding Articles -->
    <section class="findings-content">

      <div id="no-filter-results" style="display: none; padding: 48px; background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: 12px; text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: 13px;">
        No findings match the current filter or search criteria.
      </div>

      ${findings.length === 0 ? `
        <div class="finding-card" style="padding: 48px; text-align: center;">
          <div style="display: flex; justify-content: center; margin-bottom: 16px;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          </div>
          <h2 style="font-size: 18px; color: #fff; margin-bottom: 8px;">Clean Security Posture</h2>
          <p style="color: var(--text-secondary); max-width: 480px; margin: 0 auto; font-size: 13px;">
            Security analysis evaluated ${metadata.scan.filesAnalyzed} files across branch <code>${escapeHtml(metadata.target.branch)}</code> with 0 security findings.
          </p>
        </div>
      ` : findings.map((f) => {
        const meta = getSeverityMeta(f.severity)
        const safeId = sanitizeElementId(f.id)
        const isFp = Boolean(f.analysis?.isFalsePositive || f.analysis?.verdict === 'FALSE_POSITIVE')

        return `
          <article
            id="${safeId}"
            class="finding-card"
            data-severity="${escapeAttribute(f.severity)}"
            data-status="${escapeAttribute(f.status)}"
            data-search="${escapeAttribute(`${f.id} ${f.rule.name} ${f.rule.cwe} ${f.location.file} ${f.taintFlow.sink.expression} ${f.taintFlow.source.expression}`)}"
          >
            <!-- Card Header -->
            <div class="finding-card-header">
              <div class="finding-header-left">
                <div class="finding-badge-row">
                  <span class="badge" style="background: ${meta.badgeBg}; color: ${meta.badgeText}; border-color: ${meta.badgeBorder}; display: inline-flex; align-items: center; gap: 5px;">
                    <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:${meta.color};"></span>
                    ${escapeHtml(f.severity)}
                  </span>
                  <span class="badge" style="background: var(--bg-surface-elevated); color: var(--text-secondary); border-color: var(--border-default);">
                    ${escapeHtml(f.rule.cwe)}
                  </span>
                  <span class="badge" style="background: var(--bg-surface-elevated); color: var(--text-muted); border-color: var(--border-default);">
                    ${escapeHtml(f.rule.id)}
                  </span>
                  ${f.analysis ? `
                    <span class="badge" style="background: ${isFp ? 'var(--bg-canvas)' : 'var(--status-clean-bg)'}; color: ${isFp ? 'var(--text-muted)' : 'var(--status-clean)'}; border-color: ${isFp ? 'var(--border-default)' : 'var(--status-clean-border)'};">
                      ${isFp ? 'False Positive' : `Confirmed (${f.analysis.confidence}%)`}
                    </span>
                  ` : ''}
                </div>
                <h3 class="finding-card-title">${escapeHtml(f.id)} — ${escapeHtml(f.rule.name)}</h3>
                <div class="finding-location-bar">
                  <span style="display: inline-flex; align-items: center; gap: 4px;">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
                    ${escapeHtml(f.location.file)}:${f.location.line}:${f.location.column || 1}
                  </span>
                  <span>•</span>
                  <span>Sink: <code style="color: var(--severity-critical); font-family: var(--font-mono);">${escapeHtml(f.taintFlow.sink.expression)}</code></span>
                </div>
              </div>

              <div>
                <button
                  type="button"
                  class="btn copy-btn"
                  data-copy-text="${escapeAttribute(`${f.location.file}:${f.location.line}`)}"
                  title="Copy location"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                  <span>Copy Path</span>
                </button>
              </div>
            </div>

            <!-- Card Body -->
            <div class="finding-body">
              <!-- Description -->
              <div>
                <div class="section-kicker">Vulnerability Description</div>
                <p style="color: var(--text-secondary); font-size: 13px; line-height: 1.6;">
                  ${escapeHtml(f.rawMessage)}
                </p>
              </div>

              <!-- Taint Flow Visual Diagram -->
              <div>
                <div class="section-kicker">Data Flow & Taint Path</div>
                ${this.renderTaintFlowHtml(f.taintFlow)}
              </div>

              <!-- Code Evidence -->
              <div>
                <div class="section-kicker">Flagged Code Evidence</div>
                ${this.renderCodeEvidenceHtml(f.evidence, f.location.line, f.location.file)}
              </div>

              <!-- Security Verification Section -->
              ${f.analysis ? `
                <div>
                  <div class="section-kicker">Security Advisory & Verification (${escapeHtml(f.analysis.model)})</div>
                  <div class="ai-advisory-box">
                    <div class="ai-meta-bar">
                      <span><strong>Verdict:</strong> ${escapeHtml(f.analysis.verdict)}</span>
                      <span><strong>Confidence:</strong> ${f.analysis.confidence}%</span>
                      <span><strong>Scope:</strong> Source Code</span>
                    </div>
                    <div class="ai-reasoning-text">
                      ${escapeHtml(f.analysis.reasoning)}
                    </div>
                  </div>
                </div>
              ` : ''}

              <!-- Impact Section -->
              <div>
                <div class="section-kicker">Security Impact</div>
                <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 8px;">
                  ${escapeHtml(f.impact.description)}
                </p>
                <ul style="padding-left: 20px; color: var(--text-secondary); font-size: 12.5px; display: flex; flex-direction: column; gap: 4px;">
                  ${f.impact.consequences.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
                </ul>
              </div>

              <!-- Remediation Section -->
              <div>
                <div class="section-kicker">Recommended Remediation</div>
                <div class="remediation-box">
                  <p style="color: var(--text-primary); font-size: 13px; font-weight: 500;">
                    ${escapeHtml(f.remediation.explanation)}
                  </p>
                  ${f.remediation.code ? `
                    <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted); margin-top: 4px;">Hardened Implementation Pattern:</div>
                    <pre class="remediation-code">${escapeHtml(f.remediation.code)}</pre>
                  ` : ''}
                </div>
              </div>
            </div>
          </article>
        `
      }).join('')}

      <!-- Methodology Section -->
      <section class="finding-card" style="padding: 24px;">
        <h3 style="font-size: 16px; color: #fff; margin-bottom: 8px;">Assessment Methodology & Detection Scope</h3>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
          ${escapeHtml(methodology.description)}
        </p>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          ${methodology.rules.map(r => `
            <div style="padding: 12px; background: var(--bg-canvas); border: 1px solid var(--border-subtle); border-radius: 8px;">
              <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: #fff;">
                <code>${escapeHtml(r.id)}</code> — ${escapeHtml(r.name)} (${escapeHtml(r.cwe)})
              </div>
              <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
                ${escapeHtml(r.description)}
              </div>
            </div>
          `).join('')}
        </div>
      </section>

    </section>
  </main>

  <!-- Script block -->
  <script>
${HTML_REPORT_SCRIPTS}
  </script>
</body>
</html>`
  }

  private renderTaintFlowHtml(flow: TaintFlow): string {
    let html = `<div class="taint-flow-container">`

    // Source card
    html += `
      <div class="taint-step-card">
        <div class="taint-step-type">SOURCE</div>
        <div class="taint-step-expr">${escapeHtml(flow.source.expression)}</div>
        <div class="taint-step-desc">${escapeHtml(flow.source.description || 'External Input')}</div>
      </div>
    `

    // Transformations
    if (flow.transformations && flow.transformations.length > 0) {
      flow.transformations.forEach(t => {
        html += `<div class="taint-arrow">→</div>`
        html += `
          <div class="taint-step-card">
            <div class="taint-step-type">TRANSFORMATION: ${escapeHtml(t.label || 'DATA FLOW')}</div>
            <div class="taint-step-expr">${escapeHtml(t.expression)}</div>
            <div class="taint-step-desc">${escapeHtml(t.description || 'Data transformation')}</div>
          </div>
        `
      })
    }

    // Sink card
    html += `<div class="taint-arrow">→</div>`
    html += `
      <div class="taint-step-card" style="border-color: var(--severity-high-border);">
        <div class="taint-step-type" style="color: var(--severity-high);">SINK</div>
        <div class="taint-step-expr" style="color: var(--severity-critical);">${escapeHtml(flow.sink.expression)}</div>
        <div class="taint-step-desc">${escapeHtml(flow.sink.description || 'Execution boundary')}</div>
      </div>
    `

    html += `</div>`
    return html
  }

  private renderCodeEvidenceHtml(evidence: any, highlightLine: number, filePath: string): string {
    const rawCode = String(evidence.code || '').trim()
    const rawLines = rawCode.split('\n')
    const startLine = Number(evidence.startLine) || 1

    let tableRows = ''
    rawLines.forEach((lineText, idx) => {
      const lineNum = startLine + idx
      const isFlagged = lineNum === highlightLine
      const rowClass = isFlagged ? 'code-row flagged' : 'code-row'
      const gutterClass = isFlagged ? 'code-gutter flagged' : 'code-gutter'

      const highlightedLineHtml = highlightCodeLineHtml(lineText, isFlagged ? evidence.highlightToken : undefined)

      tableRows += `
        <tr class="${rowClass}">
          <td class="${gutterClass}">${lineNum}</td>
          <td class="code-line-content">${highlightedLineHtml}</td>
        </tr>
      `
    })

    return `
      <div class="code-evidence-box">
        <div class="code-header">
          <span style="display: inline-flex; align-items: center; gap: 5px;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/></svg>
            ${escapeHtml(filePath)}:${highlightLine}
          </span>
          <span>JavaScript</span>
        </div>
        <table class="code-table">
          <tbody>
            ${tableRows}
          </tbody>
        </table>
      </div>
    `
  }
}
