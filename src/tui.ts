import terminalKit from 'terminal-kit'
import type { BinaryReport } from './types/index.js'

const term = terminalKit.terminal

const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const BLUE = '\x1b[34m'
const MAGENTA = '\x1b[35m'
const CYAN = '\x1b[36m'
const WHITE = '\x1b[37m'
const GRAY = '\x1b[90m'
const BG_ACTIVE = '\x1b[37;44m'
const BG_HEADER = '\x1b[97;100m'

const TABS = ['Overview', 'Sections', 'Imports', 'Exports', 'Strings', 'Capabilities', 'Security', 'Resources'] as const

export async function runTUI(report: BinaryReport): Promise<void> {
  let activeTab = 0
  let scroll = 0
  let searching = false
  let query = ''
  let content: string[] = []

  const buildContent = (tab: number): string[] => {
    switch (TABS[tab]) {
      case 'Sections': return renderSections(report)
      case 'Imports': return renderImports(report)
      case 'Exports': return renderExports(report)
      case 'Strings': return renderStrings(report, searching ? query : '')
      case 'Capabilities': return renderCapabilities(report)
      case 'Security': return renderSecurity(report)
      case 'Resources': return renderResources(report)
      default: return renderOverview(report)
    }
  }

  const render = (): void => {
    const width = typeof term.width === 'number' ? term.width : 80
    const height = typeof term.height === 'number' ? term.height : 24

    term.eraseDisplay()

    drawLine(1, renderTabs(activeTab), width, BG_HEADER)
    drawLine(2, `${report.file.name} — ${report.format} ${report.architecture} · ${report.operatingSystem}`, width, DIM)

    content = buildContent(activeTab)

    const contentTop = 4
    const contentBottom = height - 1
    const visibleRows = Math.max(1, contentBottom - contentTop + 1)
    if (scroll > Math.max(0, content.length - visibleRows)) {
      scroll = Math.max(0, content.length - visibleRows)
    }

    for (let i = 0; i < visibleRows; i++) {
      const idx = scroll + i
      const line = idx < content.length ? content[idx] : ''
      drawLine(contentTop + i, line, width)
    }

    const footer = searching
      ? `Search: ${query}${'\x1b[5m_\x1b[0m'}  — ESC to cancel`
      : `${TABS[activeTab]} · ${scroll + 1}-${Math.min(scroll + visibleRows, content.length)}/${content.length}   ←→ tabs  ↑↓ scroll  / search  q quit`
    drawLine(height, footer, width, GRAY)
  }

  render()

  term.hideCursor(true)
  term.grabInput(true)

  await new Promise<void>(resolve => {
    term.on('key', (name: string) => {
      if (searching) {
        if (name === 'ESCAPE' || name === 'ENTER') {
          searching = false
          query = ''
        } else if (name === 'BACKSPACE') {
          query = query.slice(0, -1)
        } else if (name.length === 1) {
          query += name
        }
        scroll = 0
        render()
        return
      }

      switch (name) {
        case 'CTRL_C':
        case 'ESCAPE':
        case 'q':
        case 'Q':
          cleanup(resolve)
          return
        case 'LEFT':
        case 'SHIFT_TAB':
          activeTab = (activeTab - 1 + TABS.length) % TABS.length
          scroll = 0
          break
        case 'RIGHT':
        case 'TAB':
          activeTab = (activeTab + 1) % TABS.length
          scroll = 0
          break
        case 'DOWN':
          scroll++
          break
        case 'UP':
          scroll = Math.max(0, scroll - 1)
          break
        case 'PAGE_DOWN':
          scroll += Math.max(1, (term.height || 24) - 8)
          break
        case 'PAGE_UP':
          scroll = Math.max(0, scroll - Math.max(1, (term.height || 24) - 8))
          break
        case 'HOME':
          scroll = 0
          break
        case 'END':
          scroll = content.length
          break
        case '/':
          searching = true
          query = ''
          scroll = 0
          break
        default:
          return
      }
      render()
    })
  })
}

function cleanup(resolve: () => void): void {
  term.grabInput(false)
  term.hideCursor(false)
  term.eraseDisplay()
  term.moveTo(1, 1)
  term.styleReset()
  term('\n')
  resolve()
}

function drawLine(y: number, text: string, width: number, style = ''): void {
  term.moveTo(1, y)
  term.eraseLine()
  term(`${style}${padLine(stripAnsi(text), width)}${RESET}`)
}

function padLine(s: string, width: number): string {
  if (s.length > width) return s.slice(0, width)
  return s.padEnd(width, ' ')
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, '')
}

function renderTabs(active: number): string {
  return TABS.map((tab, i) => {
    const label = i === active ? `${BG_ACTIVE} ${tab} ${RESET}` : ` ${tab} `
    return label
  }).join(' ')
}

function renderOverview(report: BinaryReport): string[] {
  const lines: string[] = []
  lines.push(`${BOLD}Overview${RESET}`)
  lines.push('')
  lines.push(`  Format:        ${report.format}`)
  lines.push(`  Architecture:  ${report.architecture}`)
  lines.push(`  OS:            ${report.operatingSystem}`)
  lines.push(`  Size:          ${report.file.size.toLocaleString()} bytes`)
  lines.push(`  Entry Point:   0x${report.entryPoint.toString(16).padStart(8, '0')}`)
  lines.push(`  Stripped:      ${report.stripped}`)
  lines.push(`  SHA256:        ${report.file.sha256}`)
  lines.push(`  MD5:           ${report.file.md5}`)
  if (report.metadata.imphash) lines.push(`  Imphash:       ${report.metadata.imphash}`)

  const assembly = report.metadata.assembly as { name?: string; version?: string; runtime?: string } | undefined
  if (assembly) {
    lines.push('')
    lines.push(`${BOLD}Assembly${RESET}`)
    lines.push(`  Name:          ${assembly.name || '?'}`)
    lines.push(`  Version:       ${assembly.version || '?'}`)
    lines.push(`  CLR:           ${assembly.runtime || '?'}`)
  }
  const dex = report.metadata.dex as { version?: string; classes?: number; methods?: number } | undefined
  if (dex) {
    lines.push('')
    lines.push(`${BOLD}Dalvik${RESET}`)
    lines.push(`  DEX version:   ${dex.version}`)
    lines.push(`  Classes:       ${dex.classes}`)
    lines.push(`  Methods:       ${dex.methods}`)
  }

  if (report.compiler) lines.push(`  Compiler:      ${report.compiler.name} (${report.compiler.confidence}%)`)
  if (report.language) lines.push(`  Language:      ${report.language.name} (${report.language.confidence}%)`)
  if (report.optimization) lines.push(`  Optimization:  ${report.optimization}`)
  if (report.packer) lines.push(`${RED}  ⚠ Packed:      ${report.packer.name} (${report.packer.confidence}%)${RESET}`)

  if (report.libraries.length > 0) {
    lines.push('')
    lines.push(`${BOLD}Libraries${RESET}`)
    for (const lib of report.libraries.slice(0, 20)) {
      lines.push(`  ${lib.name} (${lib.confidence}%)`)
    }
  }

  if (report.metrics) {
    lines.push('')
    lines.push(`${BOLD}Metrics${RESET}`)
    lines.push(`  Function count: ${report.metrics.functionCount}`)
    lines.push(`  Complexity:     ${report.metrics.complexityScore}/100`)
    lines.push(`  Section entropy:${report.metrics.sectionEntropy}`)
    lines.push(`  Optimization:   ${report.metrics.optimizationEstimate}`)
  }

  return lines
}

function renderSections(report: BinaryReport): string[] {
  const lines: string[] = [`${BOLD}${'Name'.padEnd(24)} ${'RVA'.padStart(10)} ${'Size'.padStart(12)} ${'Entr'.padStart(6)} Permissions${RESET}`]
  for (const s of report.sections) {
    lines.push(`${s.name.padEnd(24)} 0x${s.rva.toString(16).padStart(8, '0')} ${s.size.toLocaleString().padStart(12)} ${s.entropy.toFixed(2).padStart(6)} ${s.permissions}`)
  }
  return lines
}

function renderImports(report: BinaryReport): string[] {
  if (report.imports.length === 0) return ['No imports detected.']
  const grouped = new Map<string, string[]>()
  for (const imp of report.imports) {
    if (!grouped.has(imp.module)) grouped.set(imp.module, [])
    grouped.get(imp.module)!.push(imp.name)
  }
  const lines: string[] = []
  for (const [module, funcs] of grouped) {
    lines.push(`${BOLD}${module}${RESET} (${funcs.length})`)
    for (const f of funcs.slice(0, 200)) lines.push(`  ${f}`)
    if (funcs.length > 200) lines.push(`  ... ${funcs.length - 200} more`)
  }
  return lines
}

function renderExports(report: BinaryReport): string[] {
  if (report.exports.length === 0) return ['No exports detected.']
  const lines: string[] = [`${BOLD}${'Address'.padStart(12)}  Name${RESET}`]
  for (const e of report.exports) {
    lines.push(`0x${e.address.toString(16).padStart(10, '0')}  ${e.name}`)
  }
  return lines
}

function renderStrings(report: BinaryReport, filter: string): string[] {
  let items = report.strings
  if (filter) {
    const q = filter.toLowerCase()
    items = items.filter(s => s.value.toLowerCase().includes(q) || s.type.toLowerCase().includes(q))
  }
  if (items.length === 0) return [filter ? `No strings match "${filter}".` : 'No strings detected.']
  const lines: string[] = [`${BOLD}${items.length} strings${RESET}${filter ? ` matching "${filter}"` : ''}`]
  for (const s of items) {
    lines.push(`${s.type.padEnd(12)} ${s.value}`)
  }
  return lines
}

function renderCapabilities(report: BinaryReport): string[] {
  if (report.capabilities.length === 0) return ['No capabilities detected.']
  const lines: string[] = [`${BOLD}${'Confidence'.padStart(12)}  ${'Category'.padEnd(14)} Capability${RESET}`]
  for (const cap of report.capabilities) {
    const tag = cap.confidence > 70 ? RED : cap.confidence > 40 ? YELLOW : GREEN
    lines.push(`${tag}${`${cap.confidence}%`.padStart(12)}${RESET}  ${cap.category.padEnd(14)} ${cap.name}`)
  }
  return lines
}

function renderSecurity(report: BinaryReport): string[] {
  if (!report.security) return ['No security data available.']
  const sec = report.security
  const checks: [string, boolean][] = [
    ['ASLR', sec.aslr], ['DEP', sec.dep], ['CFG', sec.cfg], ['NX', sec.nx],
    ['PIE', sec.pie], ['RELRO', sec.relro], ['Stack Canaries', sec.stackCanaries],
    ['SafeSEH', sec.safeSEH], ['Signed', sec.signed],
    ['Timestamp Anomaly', sec.timestampAnomaly], ['Overlay', sec.overlay],
  ]
  const lines: string[] = [`${BOLD}${'Feature'.padEnd(20)} Status${RESET}`]
  for (const [name, enabled] of checks) {
    const mark = enabled ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`
    lines.push(`${name.padEnd(20)} ${mark}`)
  }
  if (sec.certificateValid !== null) {
    lines.push(`Certificate Valid ${sec.certificateValid}`)
  }
  return lines
}

function renderResources(report: BinaryReport): string[] {
  if (report.resources.length === 0) return ['No resources detected.']
  const lines: string[] = [`${BOLD}${'Name'.padEnd(24)} ${'Type'.padEnd(16)} ${'Size'.padStart(12)}${RESET}`]
  for (const r of report.resources) {
    lines.push(`${r.name.padEnd(24)} ${r.type.padEnd(16)} ${r.size.toLocaleString().padStart(12)}`)
  }
  return lines
}