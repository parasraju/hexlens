import type { BinaryReport, SectionInfo, CapabilityInfo, DetectedItem } from '../types/index.js'

export function toTerminal(report: BinaryReport): string {
  const lines: string[] = []
  const sep = '─'.repeat(60)

  lines.push('')
  lines.push(` HexLens Report — ${report.file.name}`)
  lines.push(sep)
  lines.push(` Format:       ${report.format}`)
  lines.push(` Architecture: ${report.architecture}`)
  lines.push(` OS:           ${report.operatingSystem}`)
  lines.push(` Size:         ${report.file.size.toLocaleString()} bytes`)
  lines.push(` SHA256:       ${report.file.sha256.substring(0, 32)}...`)
  lines.push(` Entry Point:  0x${report.entryPoint.toString(16).padStart(8, '0')}`)
  lines.push(` Stripped:     ${report.stripped}`)

  if (report.compiler) {
    lines.push(` Compiler:     ${report.compiler.name} (${report.compiler.confidence}%)`)
  }
  if (report.language) {
    lines.push(` Language:     ${report.language.name} (${report.language.confidence}%)`)
  }
  if (report.optimization) {
    lines.push(` Optimization: ${report.optimization}`)
  }
  if (report.packer) {
    lines.push(` ${color('red', '⚠ Packed:')}  ${report.packer.name} (${report.packer.confidence}%)`)
  }

  if (report.libraries.length > 0) {
    lines.push('')
    lines.push(` ${color('cyan', 'Libraries')}`)
    lines.push(sep)
    for (const lib of report.libraries.slice(0, 10)) {
      lines.push(`  ${lib.name} (${lib.confidence}%)`)
    }
    if (report.libraries.length > 10) lines.push(`  ... ${report.libraries.length - 10} more`)
  }

  if (report.capabilities.length > 0) {
    lines.push('')
    lines.push(` ${color('yellow', 'Capabilities')}`)
    lines.push(sep)
    for (const cap of report.capabilities.slice(0, 15)) {
      const tag = getCapabilityTag(cap)
      lines.push(`  ${tag} ${cap.name} (${cap.confidence}%)`)
    }
  }

  if (report.sections.length > 0) {
    lines.push('')
    lines.push(` ${color('magenta', 'Sections')}`)
    lines.push(sep)
    lines.push('  Name                      Size        Entr  Perms')
    for (const s of report.sections.slice(0, 20)) {
      const name = s.name.padEnd(24).substring(0, 24)
      const size = s.size.toString().padStart(10)
      const entr = s.entropy.toFixed(2).padStart(6)
      lines.push(`  ${name} ${size} ${entr} ${s.permissions}`)
    }
  }

  if (report.security) {
    lines.push('')
    lines.push(` ${color('green', 'Security')}`)
    lines.push(sep)
    const sec = report.security
    const checks = [
      ['ASLR', sec.aslr] as [string, boolean], ['DEP', sec.dep] as [string, boolean], ['CFG', sec.cfg] as [string, boolean],
      ['NX', sec.nx] as [string, boolean], ['PIE', sec.pie] as [string, boolean], ['RELRO', sec.relro] as [string, boolean],
      ['Stack Canaries', sec.stackCanaries] as [string, boolean], ['SafeSEH', sec.safeSEH] as [string, boolean],
      ['Signed', sec.signed] as [string, boolean],
      ['TS Anomaly', sec.timestampAnomaly] as [string, boolean], ['Overlay', sec.overlay] as [string, boolean],
    ]
    for (const [name, enabled] of checks) {
      lines.push(`  ${enabled ? '✓' : '✗'} ${name.padEnd(16)}`)
    }
  }

  if (report.metrics) {
    lines.push('')
    lines.push(` ${color('blue', 'Metrics')}`)
    lines.push(sep)
    lines.push(`  Functions:    ${report.metrics.functionCount}`)
    lines.push(`  Avg Fn Size:  ${report.metrics.averageFunctionSize} B`)
    lines.push(`  Complexity:   ${report.metrics.complexityScore}/100`)
    lines.push(`  Optim:        ${report.metrics.optimizationEstimate}`)
  }

  lines.push('')
  lines.push(sep)
  lines.push('')

  return lines.join('\n')
}

function color(c: string, s: string): string {
  const codes: Record<string, string> = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m',
  }
  return `${codes[c] || ''}${s}${codes.reset || ''}`
}

function getCapabilityTag(cap: CapabilityInfo): string {
  const highRisk = ['Code Injection', 'Keylogging', 'Anti-Debug', 'Driver Loading', 'Service Installation']
  const medRisk = ['Persistence', 'Screen Capture', 'Process Creation', 'Registry']
  if (highRisk.includes(cap.name)) return color('red', '🔴')
  if (medRisk.includes(cap.name)) return color('yellow', '🟡')
  return '🟢'
}
