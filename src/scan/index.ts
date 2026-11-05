import { open, readdir, stat } from 'node:fs/promises'
import { basename, join, relative, resolve, sep } from 'node:path'
import type { BinaryFormat, BinaryReport } from '../types/index.js'
import { detectFormat } from '../parsers/format-detector.js'
import { analyze } from '../analyze.js'

export type ScanRisk = 'high' | 'medium' | 'low' | 'none'
export type ScanFlagSeverity = 'high' | 'medium' | 'low'

export interface ScanFlag {
  code: string
  label: string
  severity: ScanFlagSeverity
}

export interface ScanFile {
  path: string
  relativePath: string
  report: BinaryReport
  flags: ScanFlag[]
  risk: ScanRisk
}

export interface ScanError {
  path: string
  message: string
}

export interface ScanSummary {
  root: string
  files: ScanFile[]
  skipped: number
  errors: ScanError[]
  durationMs: number
}

export interface ScanOptions {
  /** Recurse into subdirectories. Defaults to true. */
  recursive?: boolean
  /** Analyze files with an unrecognized format too. Defaults to false. */
  includeUnknown?: boolean
  /** Include dotfiles and dot-directories. Defaults to false. */
  includeHidden?: boolean
  /** Number of files analyzed in parallel. Defaults to 4. */
  concurrency?: number
}

interface CandidateFile {
  path: string
  relativePath: string
}

const EXCLUDED_DIRS = new Set(['node_modules', '.git'])
const SNIFF_BYTES = 8192

const CAPABILITY_FLAGS: Record<string, ScanFlag> = {
  'Code Injection': { code: 'INJECT', label: 'Code injection APIs', severity: 'high' },
  'Keylogging': { code: 'KEYLOG', label: 'Keylogging APIs', severity: 'high' },
  'Anti-Debug': { code: 'ANTI-DBG', label: 'Anti-debugging checks', severity: 'high' },
  'Driver Loading': { code: 'DRIVER', label: 'Driver loading APIs', severity: 'high' },
  'Service Installation': { code: 'SERVICE', label: 'Service installation APIs', severity: 'high' },
  'Persistence': { code: 'PERSIST', label: 'Persistence mechanisms', severity: 'medium' },
  'Screen Capture': { code: 'SCREEN', label: 'Screen capture APIs', severity: 'medium' },
  'Anti-VM': { code: 'ANTI-VM', label: 'Virtual machine detection', severity: 'medium' },
  'Self-Modifying Code': { code: 'SMC', label: 'Writable + executable sections', severity: 'medium' },
}

/**
 * Analyze every binary under a file or directory path and collect triage flags.
 */
export async function scan(path: string, options: ScanOptions = {}): Promise<ScanSummary> {
  const started = Date.now()
  const root = resolve(path)
  const info = await stat(root)

  if (!info.isFile() && !info.isDirectory()) {
    throw new Error(`Scan path is not a file or directory: ${path}`)
  }

  const candidates = info.isFile()
    ? [{ path: root, relativePath: basename(root) }]
    : await collectFiles(root, root, options)

  const includeUnknown = options.includeUnknown ?? false
  const concurrency = Math.max(1, options.concurrency ?? 4)

  const files: ScanFile[] = []
  const errors: ScanError[] = []
  let skipped = 0
  let cursor = 0

  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++
      if (index >= candidates.length) return

      const candidate = candidates[index]!
      let format: BinaryFormat

      try {
        format = await sniffFormat(candidate.path)
      } catch (err) {
        errors.push({ path: candidate.relativePath, message: errorMessage(err) })
        continue
      }

      if (format === 'Unknown' && !includeUnknown) {
        skipped++
        continue
      }

      try {
        const report = await analyze(candidate.path)
        const flags = buildFlags(report)
        files.push({
          path: candidate.path,
          relativePath: candidate.relativePath,
          report,
          flags,
          risk: riskFromFlags(flags),
        })
      } catch (err) {
        errors.push({ path: candidate.relativePath, message: errorMessage(err) })
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, candidates.length) }, () => worker()))

  files.sort((a, b) => riskWeight(b.risk) - riskWeight(a.risk) || a.relativePath.localeCompare(b.relativePath))
  errors.sort((a, b) => a.path.localeCompare(b.path))

  return {
    root,
    files,
    skipped,
    errors,
    durationMs: Date.now() - started,
  }
}

async function collectFiles(root: string, dir: string, options: ScanOptions): Promise<CandidateFile[]> {
  const recursive = options.recursive ?? true
  const includeHidden = options.includeHidden ?? false
  const entries = await readdir(dir, { withFileTypes: true })
  const files: CandidateFile[] = []

  for (const entry of entries) {
    if (!includeHidden && entry.name.startsWith('.')) continue
    if (entry.isSymbolicLink()) continue

    const fullPath = join(dir, entry.name)

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue
      if (recursive) files.push(...await collectFiles(root, fullPath, options))
      continue
    }

    if (!entry.isFile()) continue
    files.push({ path: fullPath, relativePath: relative(root, fullPath).split(sep).join('/') })
  }

  return files
}

async function sniffFormat(path: string): Promise<BinaryFormat> {
  const handle = await open(path, 'r')
  try {
    const size = Math.min((await handle.stat()).size, SNIFF_BYTES)
    if (size < 4) return 'Unknown'
    const buffer = Buffer.alloc(size)
    await handle.read(buffer, 0, size, 0)
    try {
      return detectFormat(buffer).format
    } catch {
      return 'Unknown'
    }
  } finally {
    await handle.close()
  }
}

function buildFlags(report: BinaryReport): ScanFlag[] {
  const flags: ScanFlag[] = []
  const security = report.security
  const windowsBinary = report.format === 'PE' || report.format === '.NET'
  const securityRelevant = windowsBinary || report.format === 'ELF'

  if (report.packer) {
    flags.push({
      code: 'PACKED',
      label: `Packed with ${report.packer.name}`,
      severity: report.packer.confidence >= 50 ? 'high' : 'medium',
    })
  }

  if (report.obfuscation) {
    flags.push({
      code: 'OBFUSC',
      label: `Obfuscated: ${report.obfuscation.name}`,
      severity: report.obfuscation.confidence >= 50 ? 'high' : 'medium',
    })
  }

  if (windowsBinary && security && !security.signed) {
    flags.push({ code: 'UNSIGNED', label: 'Binary is not digitally signed', severity: 'medium' })
  }

  if (windowsBinary && security && !security.aslr) {
    flags.push({ code: 'NO-ASLR', label: 'ASLR is disabled', severity: 'medium' })
  }

  if (windowsBinary && security && !security.dep) {
    flags.push({ code: 'NO-DEP', label: 'DEP is disabled', severity: 'medium' })
  }

  if (securityRelevant && security && !security.nx) {
    flags.push({ code: 'NO-NX', label: 'NX is not enabled', severity: 'medium' })
  }

  if (securityRelevant && security?.timestampAnomaly) {
    flags.push({ code: 'TS-ANOM', label: 'Suspicious build timestamp', severity: 'medium' })
  }

  if (securityRelevant && security?.overlay) {
    flags.push({ code: 'OVERLAY', label: 'Data appended after the last section', severity: 'medium' })
  }

  if (report.format === 'ELF' && security && !security.pie) {
    flags.push({ code: 'NO-PIE', label: 'Position-independent executable is not enabled', severity: 'low' })
  }

  for (const capability of report.capabilities) {
    const flag = CAPABILITY_FLAGS[capability.name]
    if (flag) flags.push({ ...flag })
  }

  if (report.format === 'Unknown') {
    flags.push({ code: 'UNKNOWN', label: 'Unrecognized file format', severity: 'low' })
  }

  return flags
}

function riskFromFlags(flags: ScanFlag[]): ScanRisk {
  if (flags.some(f => f.severity === 'high')) return 'high'
  if (flags.some(f => f.severity === 'medium')) return 'medium'
  if (flags.some(f => f.severity === 'low')) return 'low'
  return 'none'
}

function riskWeight(risk: ScanRisk): number {
  switch (risk) {
    case 'high': return 3
    case 'medium': return 2
    case 'low': return 1
    default: return 0
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
