import type { BinaryDiff, DiffDetection, DiffImphash, DiffNameSize, DiffSectionChange } from '../types/index.js'

export function toDiffJSON(result: BinaryDiff, pretty = true): string {
  return JSON.stringify(result, null, pretty ? 2 : undefined)
}

export function toDiffTerminal(result: BinaryDiff): string {
  const lines: string[] = []
  const sep = '─'.repeat(60)

  lines.push('')
  lines.push(` HexLens Diff — ${result.fileA.name} vs ${result.fileB.name}`)
  lines.push(sep)
  lines.push(` A: ${result.fileA.name}  ${result.fileA.size} bytes`)
  lines.push(`    sha256 ${result.fileA.sha256}`)
  lines.push(` B: ${result.fileB.name}  ${result.fileB.size} bytes`)
  lines.push(`    sha256 ${result.fileB.sha256}`)
  lines.push('')

  if (result.identical) {
    lines.push(' Files are identical.')
    lines.push('')
    return lines.join('\n')
  }

  const byteWord = result.bytes.differingBytes === 1 ? 'byte' : 'bytes'
  lines.push(` Files differ: ${result.bytes.differingBytes} ${byteWord} (${result.bytes.similarity}% similar)`)
  lines.push('')
  lines.push(' Byte differences')
  lines.push(sep)
  const shown = result.bytes.differences.length
  const total = result.bytes.differingBytes
  lines.push(`  First ${shown} of ${total} differing offset${total === 1 ? '' : 's'}:`)
  for (const change of result.bytes.differences) {
    const offset = `0x${change.offset.toString(16).padStart(8, '0')}`
    lines.push(`  ${offset}`)
    lines.push(`    A: ${change.contextA || '(past end)'}`)
    lines.push(`    B: ${change.contextB || '(past end)'}`)
  }

  lines.push('')
  lines.push(' Report')
  lines.push(sep)
  pushValue(lines, 'Format', result.report.format.a, result.report.format.b, result.report.format.changed)
  pushValue(lines, 'Architecture', result.report.architecture.a, result.report.architecture.b, result.report.architecture.changed)
  pushImphash(lines, result.report.imphash)
  pushLabels(lines, 'Imports added', result.report.imports.added, '+')
  pushLabels(lines, 'Imports removed', result.report.imports.removed, '-')
  pushLabels(lines, 'Exports added', result.report.exports.added, '+')
  pushLabels(lines, 'Exports removed', result.report.exports.removed, '-')
  pushSections(lines, 'Sections added', result.report.sections.added, '+')
  pushSections(lines, 'Sections removed', result.report.sections.removed, '-')
  pushChangedSections(lines, result.report.sections.changed)
  pushStrings(lines, 'Strings added', result.report.strings.added, result.report.strings.addedTotal, '+')
  pushStrings(lines, 'Strings removed', result.report.strings.removed, result.report.strings.removedTotal, '-')
  pushDetection(lines, 'Compiler', result.report.compiler)
  pushDetection(lines, 'Language', result.report.language)
  pushDetection(lines, 'Packer', result.report.packer)
  pushValue(
    lines,
    'Entry point',
    hexAddress(result.report.entryPoint.a),
    hexAddress(result.report.entryPoint.b),
    result.report.entryPoint.changed,
  )
  lines.push('')
  return lines.join('\n')
}

function pushValue(lines: string[], label: string, a: string, b: string, changed: boolean): void {
  if (!changed) {
    lines.push(` ${label}: unchanged (${a})`)
    return
  }
  lines.push(` ${label}: changed`)
  lines.push(`  A: ${a}`)
  lines.push(`  B: ${b}`)
}

function pushImphash(lines: string[], imphash: DiffImphash): void {
  const left = formatImphash(imphash.missingA, imphash.a)
  const right = formatImphash(imphash.missingB, imphash.b)
  if (imphash.missingA || imphash.missingB) {
    lines.push(' Imphash: missing')
    lines.push(`  A: ${left}`)
    lines.push(`  B: ${right}`)
    return
  }
  if (imphash.same) {
    lines.push(` Imphash: same (${left})`)
    return
  }
  lines.push(' Imphash: different')
  lines.push(`  A: ${left}`)
  lines.push(`  B: ${right}`)
}

function formatImphash(missing: boolean, value: string | null): string {
  if (missing || value === null) return 'missing'
  if (value === '') return 'empty'
  return value
}

function pushLabels(lines: string[], label: string, items: string[], sign: '+' | '-'): void {
  if (items.length === 0) {
    lines.push(` ${label}: none`)
    return
  }
  lines.push(` ${label} (${items.length}):`)
  for (const item of items) lines.push(`  ${sign} ${item}`)
}

function pushSections(lines: string[], label: string, items: DiffNameSize[], sign: '+' | '-'): void {
  if (items.length === 0) {
    lines.push(` ${label}: none`)
    return
  }
  lines.push(` ${label} (${items.length}):`)
  for (const item of items) lines.push(`  ${sign} ${item.name} (${item.size} bytes)`)
}

function pushChangedSections(lines: string[], items: DiffSectionChange[]): void {
  if (items.length === 0) {
    lines.push(' Sections changed: none')
    return
  }
  lines.push(` Sections changed (${items.length}):`)
  for (const item of items) lines.push(`  ~ ${item.name}  ${item.sizeA} -> ${item.sizeB} bytes`)
}

function pushStrings(lines: string[], label: string, items: string[], total: number, sign: '+' | '-'): void {
  if (total === 0) {
    lines.push(` ${label}: none`)
    return
  }
  lines.push(` ${label} (${total}):`)
  for (const item of items) lines.push(`  ${sign} ${item}`)
  if (total > items.length) lines.push(`  ... ${total - items.length} more`)
}

function pushDetection(lines: string[], label: string, detection: DiffDetection): void {
  const left = formatDetection(detection.a)
  const right = formatDetection(detection.b)
  if (!detection.changed) {
    lines.push(` ${label}: unchanged (${left})`)
    return
  }
  lines.push(` ${label}: changed`)
  lines.push(`  A: ${left}`)
  lines.push(`  B: ${right}`)
}

function formatDetection(side: DiffDetection['a']): string {
  if (!side) return 'not detected'
  return `${side.name} (${side.confidence}%)`
}

function hexAddress(value: number): string {
  return `0x${value.toString(16).padStart(8, '0')}`
}
