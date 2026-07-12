import type { BinaryReport } from '../types/index.js'

export function toCSV(report: BinaryReport): string {
  const rows: string[][] = []

  rows.push(['Section', 'Property', 'Value'])

  rows.push(['file', 'name', report.file.name])
  rows.push(['file', 'size', String(report.file.size)])
  rows.push(['file', 'sha256', report.file.sha256])
  rows.push(['file', 'md5', report.file.md5])
  rows.push(['file', 'sha1', report.file.sha1])
  rows.push(['format', '', report.format])
  rows.push(['architecture', '', report.architecture])
  rows.push(['os', '', report.operatingSystem])
  rows.push(['endianness', '', report.endianness])
  rows.push(['timestamp', '', String(report.timestamp)])
  rows.push(['entry_point', '', `0x${report.entryPoint.toString(16)}`])
  rows.push(['stripped', '', String(report.stripped)])

  if (report.compiler) {
    rows.push(['compiler', 'name', report.compiler.name])
    rows.push(['compiler', 'confidence', String(report.compiler.confidence)])
  }

  if (report.language) {
    rows.push(['language', 'name', report.language.name])
    rows.push(['language', 'confidence', String(report.language.confidence)])
  }

  if (report.packer) {
    rows.push(['packer', 'name', report.packer.name])
    rows.push(['packer', 'confidence', String(report.packer.confidence)])
  }

  if (report.obfuscation) {
    rows.push(['obfuscation', 'name', report.obfuscation.name])
    rows.push(['obfuscation', 'confidence', String(report.obfuscation.confidence)])
  }

  if (report.optimization) {
    rows.push(['optimization', '', report.optimization])
  }

  for (const cap of report.capabilities) {
    rows.push(['capability', cap.name, String(cap.confidence)])
  }

  for (const sec of Object.entries(report.security || {})) {
    rows.push(['security', sec[0], String(sec[1])])
  }

  for (const lib of report.libraries) {
    rows.push(['library', lib.name, String(lib.confidence)])
  }

  for (const imp of report.imports) {
    rows.push(['import', `${imp.module}!${imp.name}`, ''])
  }

  for (const exp of report.exports) {
    rows.push(['export', exp.name, `0x${exp.address.toString(16)}`])
  }

  for (const sec of report.sections) {
    rows.push(['section', `${sec.name}@0x${sec.rva.toString(16)}`, String(sec.size)])
  }

  for (const domain of report.domains) {
    rows.push(['domain', domain, ''])
  }

  if (report.metrics) {
    rows.push(['metrics', 'functionCount', String(report.metrics.functionCount)])
    rows.push(['metrics', 'complexityScore', String(report.metrics.complexityScore)])
    rows.push(['metrics', 'sectionEntropy', String(report.metrics.sectionEntropy)])
  }

  return rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n')
}
