import type { ScanFile, ScanSummary } from '../scan/index.js'
import { toMarkdown } from './markdown.js'
import { toSARIF } from './sarif.js'
import { toYAML } from './yaml.js'

export interface ScanFormatOptions {
  color?: boolean
  pretty?: boolean
}

export function toScanTable(summary: ScanSummary, options: ScanFormatOptions = {}): string {
  const lines: string[] = []
  const files = summary.files
  const counts = countRisks(files)

  lines.push('')
  lines.push(` HexLens Batch Scan — ${files.length} ${files.length === 1 ? 'binary' : 'binaries'}`)
  lines.push(` ${summary.root}`)
  lines.push('')

  if (files.length === 0) {
    lines.push(' No supported binaries found.')
    if (summary.skipped > 0) lines.push(' Use --all to include unrecognized files.')
    lines.push('')
    appendFooter(lines, summary)
    return lines.join('\n')
  }

  const pathWidth = Math.min(60, Math.max(4, ...files.map(f => f.relativePath.length), 4))
  const sizeWidth = Math.max(6, ...files.map(f => formatBytes(f.report.file.size).length))
  const formatWidth = Math.max(4, ...files.map(f => f.report.format.length))
  const archWidth = Math.max(4, ...files.map(f => f.report.architecture.length))
  const compilerWidth = Math.max(8, ...files.map(f => (f.report.compiler?.name || '-').length))
  const languageWidth = Math.max(4, ...files.map(f => (f.report.language?.name || '-').length))
  const riskWidth = 6
  const flagsWidth = Math.max(5, ...files.map(f => flagCodes(f, true).length))

  const header = [
    'FILE'.padEnd(pathWidth),
    'SIZE'.padStart(sizeWidth),
    'FMT'.padEnd(formatWidth),
    'ARCH'.padEnd(archWidth),
    'COMPILER'.padEnd(compilerWidth),
    'LANG'.padEnd(languageWidth),
    'RISK'.padEnd(riskWidth),
    'FLAGS',
  ].join('  ')
  lines.push(` ${header}`)
  lines.push(` ${'─'.repeat(header.length)}`)

  for (const file of files) {
    const path = truncatePath(file.relativePath, pathWidth)
    const risk = riskLabel(file.risk)
    const row = [
      path.padEnd(pathWidth),
      formatBytes(file.report.file.size).padStart(sizeWidth),
      file.report.format.padEnd(formatWidth),
      file.report.architecture.padEnd(archWidth),
      (file.report.compiler?.name || '-').padEnd(compilerWidth),
      (file.report.language?.name || '-').padEnd(languageWidth),
      colorRisk(risk, riskWidth, options.color !== false),
      flagCodes(file, true).padEnd(flagsWidth),
    ].join('  ')
    lines.push(` ${row}`)
  }

  lines.push('')
  lines.push(` Scanned ${files.length} ${files.length === 1 ? 'file' : 'files'} in ${formatDuration(summary.durationMs)} — ${counts.high} high, ${counts.medium} medium, ${counts.low + counts.none} clean`)
  if (summary.yaraRules) {
    const total = files.reduce((count, file) => count + (file.yaraMatches?.length ?? 0), 0)
    lines.push(` YARA: ${total} rule ${total === 1 ? 'match' : 'matches'} (${summary.yaraRules})`)
  }
  appendFooter(lines, summary)
  lines.push('')

  return lines.join('\n')
}

export function toScanJSON(summary: ScanSummary, pretty = true): string {
  return JSON.stringify({
    root: summary.root,
    scanned: summary.files.length,
    skipped: summary.skipped,
    errors: summary.errors,
    durationMs: summary.durationMs,
    files: summary.files.map(file => ({
      path: file.relativePath,
      risk: file.risk,
      flags: file.flags,
      report: file.report,
      ...(file.yaraMatches ? { yaraMatches: file.yaraMatches } : {}),
    })),
  }, null, pretty ? 2 : undefined)
}

export function toScanCSV(summary: ScanSummary): string {
  const rows: string[][] = [[
    'File', 'Size', 'Format', 'Architecture', 'OS', 'Compiler', 'Language',
    'Packer', 'Risk', 'Flags', 'SHA256',
  ]]

  for (const file of summary.files) {
    rows.push([
      file.relativePath,
      String(file.report.file.size),
      file.report.format,
      file.report.architecture,
      file.report.operatingSystem,
      file.report.compiler?.name || '',
      file.report.language?.name || '',
      file.report.packer?.name || '',
      file.risk,
      flagCodes(file),
      file.report.file.sha256,
    ])
  }

  return rows.map(row => row.map(csvCell).join(',')).join('\n')
}

export function toScanMarkdown(summary: ScanSummary): string {
  const lines: string[] = []
  const counts = countRisks(summary.files)

  lines.push('# HexLens Batch Scan')
  lines.push('')
  lines.push(`**Root:** \`${summary.root}\``)
  lines.push(`**Scanned:** ${summary.files.length} | **High:** ${counts.high} | **Medium:** ${counts.medium} | **Skipped:** ${summary.skipped} | **Errors:** ${summary.errors.length}`)
  lines.push('')
  lines.push('| File | Size | Format | Architecture | Risk | Flags |')
  lines.push('|------|------|--------|--------------|------|-------|')
  for (const file of summary.files) {
    lines.push(`| ${mdCell(file.relativePath)} | ${formatBytes(file.report.file.size)} | ${file.report.format} | ${file.report.architecture} | ${riskLabel(file.risk)} | ${mdCell(flagCodes(file))} |`)
  }
  lines.push('')

  if (summary.errors.length > 0) {
    lines.push('## Errors')
    for (const error of summary.errors) {
      lines.push(`- **${mdCell(error.path)}**: ${mdCell(error.message)}`)
    }
    lines.push('')
  }

  if (summary.files.length > 0) {
    lines.push('## File Details')
    lines.push('')
    for (const file of summary.files) {
      lines.push(`### ${mdCell(file.relativePath)}`)
      lines.push('')
      lines.push(toMarkdown(file.report).replace(/^# /gm, '## '))
      lines.push('')
    }
  }

  return lines.join('\n').trimEnd()
}

export function toScanYAML(summary: ScanSummary): string {
  const lines: string[] = []
  lines.push(`root: "${yamlString(summary.root)}"`)
  lines.push(`scanned: ${summary.files.length}`)
  lines.push(`skipped: ${summary.skipped}`)
  lines.push(`errors: ${summary.errors.length}`)
  lines.push(`durationMs: ${summary.durationMs}`)
  lines.push('files:')
  for (const file of summary.files) {
    lines.push(`  - path: "${yamlString(file.relativePath)}"`)
    lines.push(`    risk: "${file.risk}"`)
    if (file.flags.length === 0) {
      lines.push('    flags: []')
    } else {
      lines.push('    flags:')
      for (const flag of file.flags) {
        lines.push(`      - code: "${yamlString(flag.code)}"`)
        lines.push(`        label: "${yamlString(flag.label)}"`)
        lines.push(`        severity: "${flag.severity}"`)
      }
    }
    lines.push('---')
    lines.push(toYAML(file.report))
  }
  return lines.join('\n')
}

export function toScanSARIF(summary: ScanSummary): string {
  const runs = summary.files.map(file => {
    const parsed = JSON.parse(toSARIF(file.report)) as {
      runs: Array<{
        artifacts?: Array<{ location?: { uri?: string } }>
        results?: Array<{ locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string } } }> }>
        properties?: Record<string, unknown>
      }>
    }
    const run = parsed.runs[0]
    if (run) {
      for (const artifact of run.artifacts || []) {
        if (artifact.location) artifact.location.uri = file.relativePath
      }
      for (const result of run.results || []) {
        for (const location of result.locations || []) {
          if (location.physicalLocation?.artifactLocation) {
            location.physicalLocation.artifactLocation.uri = file.relativePath
          }
        }
      }
      run.properties = { risk: file.risk, flags: file.flags.map(flag => flag.code) }
    }
    return run
  }).filter(Boolean)

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  }, null, 2)
}

export function toScanHTML(summary: ScanSummary): string {
  const counts = countRisks(summary.files)
  const rows = summary.files.map(file => `      <tr>
        <td class="path">${escapeHtml(file.relativePath)}</td>
        <td>${formatBytes(file.report.file.size)}</td>
        <td>${escapeHtml(file.report.format)}</td>
        <td>${escapeHtml(file.report.architecture)}</td>
        <td>${escapeHtml(file.report.compiler?.name || '—')}</td>
        <td>${escapeHtml(file.report.language?.name || '—')}</td>
        <td><span class="risk ${file.risk}">${riskLabel(file.risk)}</span></td>
        <td>${escapeHtml(flagCodes(file) || '—')}</td>
      </tr>`).join('\n')

  const errors = summary.errors.length === 0 ? '' : `
  <h2>Errors</h2>
  <ul>${summary.errors.map(error => `<li><code>${escapeHtml(error.path)}</code> — ${escapeHtml(error.message)}</li>`).join('')}</ul>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HexLens Batch Scan</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
  .container { max-width: 1400px; margin: 0 auto; }
  h1 { color: #58a6ff; font-size: 24px; margin: 0 0 4px; }
  .root { color: #8b949e; font-size: 13px; margin-bottom: 16px; }
  .stats { display: flex; gap: 20px; margin: 16px 0; }
  .stat { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 12px 18px; }
  .stat b { display: block; font-size: 22px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; background: #161b22; border-bottom: 2px solid #21262d; font-size: 12px; text-transform: uppercase; color: #8b949e; }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 13px; }
  tr:hover td { background: #1c2128; }
  .path { font-family: 'SF Mono', Monaco, monospace; }
  .risk { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
  .risk.high { background: #da3633; color: #fff; }
  .risk.medium { background: #d29922; color: #fff; }
  .risk.low { background: #1f6feb; color: #fff; }
  .risk.none { background: #238636; color: #fff; }
  footer { color: #484f58; font-size: 12px; margin-top: 32px; padding-top: 16px; border-top: 1px solid #21262d; }
</style>
</head>
<body>
<div class="container">
  <h1>HexLens Batch Scan</h1>
  <div class="root">${escapeHtml(summary.root)}</div>
  <div class="stats">
    <div class="stat"><b>${summary.files.length}</b>binaries</div>
    <div class="stat"><b>${counts.high}</b>high risk</div>
    <div class="stat"><b>${counts.medium}</b>medium risk</div>
    <div class="stat"><b>${summary.skipped}</b>skipped</div>
  </div>
  <table>
    <thead><tr><th>File</th><th>Size</th><th>Format</th><th>Arch</th><th>Compiler</th><th>Language</th><th>Risk</th><th>Flags</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>${errors}
  <footer>Scanned in ${formatDuration(summary.durationMs)} — HexLens</footer>
</div>
</body>
</html>`
}

export function formatScan(summary: ScanSummary, format: string, options: ScanFormatOptions = {}): string {
  switch (format.toLowerCase()) {
    case 'json':
      return toScanJSON(summary, options.pretty ?? true)
    case 'markdown':
    case 'md':
      return toScanMarkdown(summary)
    case 'html':
      return toScanHTML(summary)
    case 'sarif':
      return toScanSARIF(summary)
    case 'yaml':
    case 'yml':
      return toScanYAML(summary)
    case 'csv':
      return toScanCSV(summary)
    case 'terminal':
    default:
      return toScanTable(summary, options)
  }
}

function appendFooter(lines: string[], summary: ScanSummary): void {
  if (summary.skipped > 0) {
    lines.push(` Skipped ${summary.skipped} unsupported ${summary.skipped === 1 ? 'file' : 'files'} (use --all to include them)`)
  }
  if (summary.errors.length > 0) {
    lines.push(` ${summary.errors.length} ${summary.errors.length === 1 ? 'error' : 'errors'}:`)
    for (const error of summary.errors) {
      lines.push(`   ${error.path} — ${error.message}`)
    }
  }
}

function countRisks(files: ScanFile[]): { high: number; medium: number; low: number; none: number } {
  const counts = { high: 0, medium: 0, low: 0, none: 0 }
  for (const file of files) counts[file.risk]++
  return counts
}

function riskLabel(risk: string): string {
  switch (risk) {
    case 'high': return 'HIGH'
    case 'medium': return 'MED'
    case 'low': return 'LOW'
    default: return '—'
  }
}

function colorRisk(label: string, width: number, color: boolean): string {
  const padded = label.padEnd(width)
  if (!color) return padded
  const codes: Record<string, string> = {
    HIGH: '\x1b[31m',
    MED: '\x1b[33m',
    LOW: '\x1b[34m',
  }
  const code = codes[label]
  return code ? `${code}${padded}\x1b[0m` : padded
}

function flagCodes(file: ScanFile, includeYara = false): string {
  const codes = file.flags.map(flag => flag.code)
  if (includeYara && file.yaraMatches) {
    for (const match of file.yaraMatches) codes.push(`YARA:${match.rule}`)
  }
  return codes.join(', ')
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

function truncatePath(path: string, width: number): string {
  if (path.length <= width) return path
  return `…${path.slice(-(width - 1))}`
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`
}

function mdCell(value: string): string {
  return value.replace(/\|/g, '\\|')
}

function yamlString(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
