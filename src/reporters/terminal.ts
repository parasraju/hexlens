import type { BinaryReport, CapabilityInfo, YaraMatch } from '../types/index.js'
import { securityChecks } from '../detectors/security.js'

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
  if (report.format === 'Unknown') {
    lines.push('')
    lines.push(` ${color('yellow', 'Not a recognized binary.')}`)
    lines.push(' This file does not match PE, ELF, Mach-O, WASM, DEX, or .NET.')
    lines.push('')
    lines.push(sep)
    lines.push('')
    return lines.join('\n')
  }
  lines.push(` Entry Point:  0x${report.entryPoint.toString(16).padStart(8, '0')}`)
  if (report.metadata.truncated === true) {
    lines.push('')
    lines.push(` ${color('yellow', 'Truncated or malformed header.')}`)
    lines.push(' Not enough of the file is present to parse program headers or sections.')
  }
  lines.push(` Stripped:     ${report.stripped}`)

  if (report.metadata.imphash) {
    lines.push(` Imphash:      ${report.metadata.imphash}`)
  }

  const assembly = report.metadata.assembly as { name?: string; version?: string; runtime?: string } | undefined
  if (assembly && (assembly.name || assembly.runtime)) {
    lines.push(` Assembly:     ${assembly.name || '?'} ${assembly.version ? `v${assembly.version}` : ''}`)
    if (assembly.runtime) lines.push(` CLR:          ${assembly.runtime}`)
  }

  const dex = report.metadata.dex as { version?: string; classes?: number; methods?: number } | undefined
  if (dex) {
    lines.push(` DEX Version:  ${dex.version}`)
    lines.push(` Classes:      ${dex.classes}  Methods: ${dex.methods}`)
  }

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

  if (report.resources.length > 0) {
    lines.push('')
    lines.push(` ${color('magenta', 'Resources')}`)
    lines.push(sep)
    lines.push('  Name                     Type          Size')
    for (const r of report.resources.slice(0, 15)) {
      const name = (r.name || '').padEnd(24).substring(0, 24)
      const type = (r.type || '').padEnd(14).substring(0, 14)
      lines.push(`  ${name} ${type} ${r.size}`)
    }
    if (report.resources.length > 15) lines.push(`  ... ${report.resources.length - 15} more`)
  }

  if (report.security) {
    const checks = securityChecks(report.format, report.security)
    if (checks.length > 0) {
      lines.push('')
      lines.push(` ${color('green', 'Security')}`)
      lines.push(sep)
      for (const check of checks) {
        const mark = check.enabled ? color('green', '✓') : color('red', '✗')
        lines.push(`  ${mark} ${check.name.padEnd(16)}`)
      }
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

export function formatYaraMatches(matches: YaraMatch[]): string {
  const lines: string[] = []
  const sep = '─'.repeat(60)

  lines.push('')
  lines.push(` ${color('red', 'YARA Matches')}`)
  lines.push(sep)

  if (matches.length === 0) {
    lines.push('  No YARA rules matched.')
  } else {
    for (const match of matches) {
      lines.push(`  ${match.rule}`)
      for (const string of match.strings.slice(0, 5)) {
        lines.push(`    ${string.identifier} @ 0x${string.offset.toString(16)} (${string.length} bytes)`)
      }
    }
  }

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
