import type { BinaryReport, SectionInfo, CapabilityInfo } from '../types/index.js'

export function toHTML(report: BinaryReport): string {
  const sections = report.sections.map(s => htmlSectionRow(s)).join('\n')
  const capabilities = report.capabilities.map(c => htmlCapabilityRow(c)).join('\n')
  const imports = report.imports.map(i => htmlImportRow(i)).join('\n')
  const exports = report.exports.map(e => htmlExportRow(e)).join('\n')
  const stringsByType = groupBy(report.strings, s => s.type)

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HexLens Report — ${escapeHtml(report.file.name)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 24px; margin-bottom: 8px; color: #58a6ff; }
  h2 { font-size: 18px; margin: 24px 0 12px; color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 8px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; margin: 16px 0; }
  .meta-item { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 12px; }
  .meta-item .label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }
  .meta-item .value { font-size: 16px; font-weight: 600; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th { text-align: left; padding: 8px 12px; background: #161b22; border-bottom: 2px solid #21262d; font-size: 12px; text-transform: uppercase; color: #8b949e; }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }
  tr:hover td { background: #1c2128; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
  .badge-high { background: #da3633; color: #fff; }
  .badge-med { background: #d29922; color: #fff; }
  .badge-low { background: #238636; color: #fff; }
  .hash { font-family: 'SF Mono', Monaco, monospace; font-size: 13px; color: #8b949e; }
  .collapsible { cursor: pointer; user-select: none; }
  .collapsible::before { content: '▶ '; font-size: 12px; }
  .collapsible.open::before { content: '▼ '; }
  .collapsible-content { display: none; }
  .collapsible.open + .collapsible-content { display: block; }
  .tag { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; margin: 0 2px; }
  .tag-network { background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb55; }
  .tag-security { background: #da363333; color: #ff7b72; border: 1px solid #da363355; }
  .tag-system { background: #d2992233; color: #d29922; border: 1px solid #d2992255; }
  .tag-data { background: #23863633; color: #3fb950; border: 1px solid #23863655; }
  .tag-hardware { background: #bc8cff33; color: #bc8cff; border: 1px solid #bc8cff55; }
  .progress { width: 100%; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; margin-top: 4px; }
  .progress-bar { height: 100%; background: linear-gradient(90deg, #238636, #2ea043); border-radius: 4px; transition: width 0.3s; }
  .progress-bar.warn { background: linear-gradient(90deg, #d29922, #e3b341); }
  .progress-bar.danger { background: linear-gradient(90deg, #da3633, #f85149); }
  footer { text-align: center; color: #484f58; font-size: 12px; margin-top: 40px; padding: 20px; border-top: 1px solid #21262d; }
</style>
</head>
<body>
<div class="container">
<h1>HexLens Report</h1>
<p style="color: #8b949e;">${escapeHtml(report.file.name)} — ${report.format} ${report.architecture}</p>

<div class="meta">
  <div class="meta-item"><div class="label">Format</div><div class="value">${report.format}</div></div>
  <div class="meta-item"><div class="label">Architecture</div><div class="value">${report.architecture}</div></div>
  <div class="meta-item"><div class="label">Operating System</div><div class="value">${report.operatingSystem}</div></div>
  <div class="meta-item"><div class="label">File Size</div><div class="value">${report.file.size.toLocaleString()} bytes</div></div>
  <div class="meta-item"><div class="label">Entry Point</div><div class="value hash">0x${report.entryPoint.toString(16).padStart(8, '0')}</div></div>
  <div class="meta-item"><div class="label">Stripped</div><div class="value">${report.stripped ? 'Yes' : 'No'}</div></div>
  ${report.compiler ? `<div class="meta-item"><div class="label">Compiler</div><div class="value">${escapeHtml(report.compiler.name)} <span class="badge badge-low">${report.compiler.confidence}%</span></div></div>` : ''}
  ${report.language ? `<div class="meta-item"><div class="label">Language</div><div class="value">${escapeHtml(report.language.name)} <span class="badge badge-low">${report.language.confidence}%</span></div></div>` : ''}
  ${report.packer ? `<div class="meta-item"><div class="label">Packer</div><div class="value">${escapeHtml(report.packer.name)} <span class="badge badge-high">${report.packer.confidence}%</span></div></div>` : ''}
  ${report.optimization ? `<div class="meta-item"><div class="label">Optimization</div><div class="value">${report.optimization}</div></div>` : ''}
</div>

<h2>Hashes</h2>
<table>
<tr><th>Algorithm</th><th>Hash</th></tr>
<tr><td>SHA256</td><td class="hash">${report.file.sha256}</td></tr>
<tr><td>SHA1</td><td class="hash">${report.file.sha1}</td></tr>
<tr><td>MD5</td><td class="hash">${report.file.md5}</td></tr>
</table>

<h2>Capabilities (${report.capabilities.length})</h2>
<table>
<tr><th>Capability</th><th>Category</th><th>Confidence</th></tr>
${capabilities}
</table>

<h2>Sections (${report.sections.length})</h2>
<table>
<tr><th>Name</th><th>Size</th><th>Entropy</th><th>Permissions</th></tr>
${sections}
</table>

${report.imports.length > 0 ? `
<h2>Imports (${report.imports.length}) <span class="collapsible" onclick="this.classList.toggle('open')"></span></h2>
<div class="collapsible-content">
<table>
<tr><th>Module</th><th>Function</th></tr>
${imports}
</table>
</div>` : ''}

${report.exports.length > 0 ? `
<h2>Exports (${report.exports.length}) <span class="collapsible" onclick="this.classList.toggle('open')"></span></h2>
<div class="collapsible-content">
<table>
<tr><th>Name</th><th>Address</th></tr>
${exports}
</table>
</div>` : ''}

${report.libraries.length > 0 ? `
<h2>Libraries</h2>
<table>
<tr><th>Library</th><th>Confidence</th></tr>
${report.libraries.map(l => `<tr><td>${escapeHtml(l.name)}</td><td><div class="progress"><div class="progress-bar${l.confidence > 80 ? '' : l.confidence > 50 ? ' warn' : ' danger'}" style="width:${l.confidence}%"></div></div> ${l.confidence}%</td></tr>`).join('\n')}
</table>` : ''}

${report.security ? `
<h2>Security</h2>
<table>
<tr><th>Feature</th><th>Status</th></tr>
${[['ASLR', report.security.aslr], ['DEP', report.security.dep], ['CFG', report.security.cfg], ['NX', report.security.nx], ['PIE', report.security.pie], ['RELRO', report.security.relro], ['Stack Canaries', report.security.stackCanaries], ['SafeSEH', report.security.safeSEH], ['Signed', report.security.signed], ['Timestamp Anomaly', report.security.timestampAnomaly], ['Overlay', report.security.overlay]].map(([name, enabled]) => `<tr><td>${name}</td><td>${enabled ? '✅ Enabled' : '❌ Disabled'}</td></tr>`).join('\n')}
</table>` : ''}

${report.metrics ? `
<h2>Binary Metrics</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Function Count</td><td>${report.metrics.functionCount}</td></tr>
<tr><td>Avg Function Size</td><td>${report.metrics.averageFunctionSize} bytes</td></tr>
<tr><td>Complexity Score</td><td>${report.metrics.complexityScore}/100</td></tr>
<tr><td>Symbol Density</td><td>${report.metrics.symbolDensity.toFixed(1)}%</td></tr>
<tr><td>Optimization Estimate</td><td>${report.metrics.optimizationEstimate}</td></tr>
</table>` : ''}

<h2>String Summary</h2>
<table>
<tr><th>Type</th><th>Count</th></tr>
${Object.entries(stringsByType).map(([type, items]) => `<tr><td>${type}</td><td>${items.length}</td></tr>`).join('\n')}
</table>

<footer>Generated by HexLens v0.1.0</footer>
</div>
</body>
</html>`
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function htmlSectionRow(s: SectionInfo): string {
  const entropyClass = s.entropy > 7.5 ? 'badge-high' : s.entropy > 6 ? 'badge-med' : 'badge-low'
  return `<tr><td>${escapeHtml(s.name)}</td><td>${s.size.toLocaleString()}</td><td><span class="badge ${entropyClass}">${s.entropy.toFixed(2)}</span></td><td>${s.permissions}</td></tr>`
}

function htmlCapabilityRow(c: CapabilityInfo): string {
  const cls = c.confidence > 70 ? 'badge-high' : c.confidence > 40 ? 'badge-med' : 'badge-low'
  const tagClass = `tag-${c.category.toLowerCase()}`
  return `<tr><td>${escapeHtml(c.name)}</td><td><span class="tag ${tagClass}">${c.category}</span></td><td><span class="badge ${cls}">${c.confidence}%</span></td></tr>`
}

function htmlImportRow(i: { module: string; name: string }): string {
  return `<tr><td>${escapeHtml(i.module)}</td><td>${escapeHtml(i.name)}</td></tr>`
}

function htmlExportRow(e: { name: string; address: number }): string {
  return `<tr><td>${escapeHtml(e.name)}</td><td class="hash">0x${e.address.toString(16)}</td></tr>`
}

function groupBy<T>(arr: T[], fn: (item: T) => string): Record<string, T[]> {
  const result: Record<string, T[]> = {}
  for (const item of arr) {
    const key = fn(item)
    if (!result[key]) result[key] = []
    result[key].push(item)
  }
  return result
}
