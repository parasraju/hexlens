import type { BinaryReport } from '../types/index.js'

export function toMarkdown(report: BinaryReport): string {
  const lines: string[] = []

  lines.push(`# HexLens Report: ${report.file.name}`)
  lines.push('')
  lines.push(`**Format:** ${report.format} | **Architecture:** ${report.architecture} | **OS:** ${report.operatingSystem}`)
  lines.push('')
  lines.push('## File Information')
  lines.push(`- **Size:** ${report.file.size.toLocaleString()} bytes`)
  lines.push(`- **SHA256:** \`${report.file.sha256}\``)
  lines.push(`- **MD5:** \`${report.file.md5}\``)
  lines.push(`- **SHA1:** \`${report.file.sha1}\``)
  lines.push(`- **Entry Point:** 0x${report.entryPoint.toString(16)}`)
  lines.push(`- **Stripped:** ${report.stripped}`)
  if (report.timestamp > 0) {
    lines.push(`- **Timestamp:** ${new Date(report.timestamp * 1000).toISOString()}`)
  }
  lines.push('')

  if (report.compiler) {
    lines.push('## Compiler')
    lines.push(`- **${report.compiler.name}** (confidence: ${report.compiler.confidence}%)`)
    for (const e of report.compiler.evidence) {
      lines.push(`  - ${e}`)
    }
    lines.push('')
  }

  if (report.language) {
    lines.push('## Language')
    lines.push(`- **${report.language.name}** (confidence: ${report.language.confidence}%)`)
    for (const e of report.language.evidence) {
      lines.push(`  - ${e}`)
    }
    lines.push('')
  }

  if (report.optimization) {
    lines.push(`- **Optimization:** ${report.optimization}`)
    lines.push('')
  }

  if (report.packer) {
    lines.push('## Packer')
    lines.push(`- **${report.packer.name}** (confidence: ${report.packer.confidence}%)`)
    for (const e of report.packer.evidence) {
      lines.push(`  - ${e}`)
    }
    lines.push('')
  }

  if (report.libraries.length > 0) {
    lines.push('## Libraries')
    lines.push('| Library | Confidence |')
    lines.push('|---------|-----------|')
    for (const lib of report.libraries) {
      lines.push(`| ${lib.name} | ${lib.confidence}% |`)
    }
    lines.push('')
  }

  if (report.imports.length > 0) {
    lines.push(`## Imports (${report.imports.length})`)
    const grouped = new Map<string, string[]>()
    for (const imp of report.imports) {
      if (!grouped.has(imp.module)) grouped.set(imp.module, [])
      grouped.get(imp.module)!.push(imp.name)
    }
    for (const [module, functions] of grouped) {
      lines.push(`- **${module}**`)
      for (const fn of functions.slice(0, 20)) {
        lines.push(`  - ${fn}`)
      }
      if (functions.length > 20) lines.push(`  - ... and ${functions.length - 20} more`)
    }
    lines.push('')
  }

  if (report.exports.length > 0) {
    lines.push(`## Exports (${report.exports.length})`)
    for (const exp of report.exports.slice(0, 30)) {
      lines.push(`- ${exp.name} @ 0x${exp.address.toString(16)}`)
    }
    if (report.exports.length > 30) lines.push(`- ... and ${report.exports.length - 30} more`)
    lines.push('')
  }

  if (report.capabilities.length > 0) {
    lines.push('## Capabilities')
    lines.push('| Capability | Category | Confidence |')
    lines.push('|-----------|----------|-----------|')
    for (const cap of report.capabilities) {
      lines.push(`| ${cap.name} | ${cap.category} | ${cap.confidence}% |`)
    }
    lines.push('')
  }

  if (report.security) {
    lines.push('## Security')
    lines.push('| Feature | Status |')
    lines.push('|---------|--------|')
    const sec = report.security
    const checks = [
      ['ASLR', sec.aslr], ['DEP', sec.dep], ['CFG', sec.cfg],
      ['NX', sec.nx], ['PIE', sec.pie], ['RELRO', sec.relro],
      ['Stack Canaries', sec.stackCanaries], ['SafeSEH', sec.safeSEH],
      ['Signed', sec.signed], ['Timestamp Anomaly', sec.timestampAnomaly],
      ['Overlay', sec.overlay],
    ]
    for (const [name, enabled] of checks) {
      lines.push(`| ${name} | ${enabled ? '✅' : '❌'} |`)
    }
    lines.push('')
  }

  if (report.strings.length > 0) {
    lines.push(`## Strings (${report.strings.length} total)`)
    const byType = new Map<string, number>()
    for (const s of report.strings) {
      byType.set(s.type, (byType.get(s.type) || 0) + 1)
    }
    for (const [type, count] of byType) {
      lines.push(`- **${type}**: ${count}`)
    }
    lines.push('')
  }

  if (report.sections.length > 0) {
    lines.push('## Sections')
    lines.push('| Name | Size | Entropy | Permissions |')
    lines.push('|------|------|---------|------------|')
    for (const s of report.sections) {
      lines.push(`| ${s.name} | ${s.size.toLocaleString()} | ${s.entropy.toFixed(2)} | ${s.permissions} |`)
    }
    lines.push('')
  }

  if (report.metrics) {
    lines.push('## Binary Metrics')
    lines.push(`- **Function Count:** ${report.metrics.functionCount}`)
    lines.push(`- **Avg Function Size:** ${report.metrics.averageFunctionSize} bytes`)
    lines.push(`- **Symbol Density:** ${report.metrics.symbolDensity.toFixed(1)}%`)
    lines.push(`- **Instruction Density:** ${report.metrics.instructionDensity.toFixed(1)}%`)
    lines.push(`- **Complexity Score:** ${report.metrics.complexityScore}/100`)
    lines.push(`- **Optimization:** ${report.metrics.optimizationEstimate}`)
    lines.push('')
  }

  return lines.join('\n')
}
