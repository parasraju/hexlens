import type { BinaryReport, DetectedItem, SectionInfo, ImportInfo, ExportInfo, StringInfo, SecurityInfo, BinaryMetrics, CapabilityInfo } from '../types/index.js'

function yamlVal(v: unknown, indent: number): string {
  const pad = '  '.repeat(indent)
  if (v === null || v === undefined) return `${pad}null`
  if (typeof v === 'string') return `${pad}"${v.replace(/"/g, '\\"')}"`
  if (typeof v === 'boolean' || typeof v === 'number') return `${pad}${v}`
  if (Array.isArray(v)) {
    if (v.length === 0) return `${pad}[]`
    const items = v.map(item => `${pad}- ${yamlVal(item, indent + 1).trimStart()}`)
    return items.join('\n')
  }
  if (typeof v === 'object') return yamlObj(v as Record<string, unknown>, indent)
  return `${pad}${v}`
}

function yamlObj(obj: Record<string, unknown>, indent: number): string {
  const pad = '  '.repeat(indent)
  return Object.entries(obj).map(([k, val]) => {
    if (val === null || val === undefined) return `${pad}${k}: null`
    if (typeof val === 'object' && !Array.isArray(val)) {
      return `${pad}${k}:\n${yamlObj(val as Record<string, unknown>, indent + 1)}`
    }
    return `${pad}${k}: ${yamlVal(val, indent + 1).trimStart()}`
  }).join('\n')
}

export function toYAML(report: BinaryReport): string {
  const lines: string[] = []

  lines.push(yamlObj({ file: report.file as unknown as Record<string, unknown> }, 0))
  lines.push(`format: "${report.format}"`)
  lines.push(`architecture: "${report.architecture}"`)
  lines.push(`operatingSystem: "${report.operatingSystem}"`)
  lines.push(`endianness: "${report.endianness}"`)
  if (report.compiler) lines.push(yamlObj({ compiler: report.compiler as unknown as Record<string, unknown> }, 0))
  if (report.language) lines.push(yamlObj({ language: report.language as unknown as Record<string, unknown> }, 0))
  if (report.packer) lines.push(yamlObj({ packer: report.packer as unknown as Record<string, unknown> }, 0))
  if (report.obfuscation) lines.push(yamlObj({ obfuscation: report.obfuscation as unknown as Record<string, unknown> }, 0))
  if (report.optimization) lines.push(`optimization: "${report.optimization}"`)
  lines.push(`stripped: ${report.stripped}`)
  lines.push(`timestamp: ${report.timestamp}`)
  lines.push(`entryPoint: "0x${report.entryPoint.toString(16)}"`)
  lines.push(`domains:\n${report.domains.map(d => `  - "${d}"`).join('\n')}`)
  if (report.security) lines.push(yamlObj({ security: report.security as unknown as Record<string, unknown> }, 0))
  if (report.libraries.length > 0) lines.push(yamlObj({ libraries: report.libraries }, 0))
  if (report.capabilities.length > 0) lines.push(yamlObj({ capabilities: report.capabilities }, 0))
  if (report.imports.length > 0) lines.push(yamlObj({ imports: report.imports }, 0))
  if (report.exports.length > 0) lines.push(yamlObj({ exports: report.exports }, 0))
  if (report.sections.length > 0) lines.push(yamlObj({ sections: report.sections }, 0))
  if (report.strings.length > 0) lines.push(yamlObj({ strings: report.strings }, 0))
  if (report.metrics) lines.push(yamlObj({ metrics: report.metrics as unknown as Record<string, unknown> }, 0))
  if (report.graphs) lines.push(yamlObj({ graphs: report.graphs as unknown as Record<string, unknown> }, 0))
  if (report.metadata && Object.keys(report.metadata).length > 0) lines.push(yamlObj({ metadata: report.metadata }, 0))

  return lines.join('\n')
}
