import { access, readFile, stat } from 'node:fs/promises'
import { constants } from 'node:fs'
import { basename } from 'node:path'
import { analyze } from '../analyze.js'
import type {
  Architecture,
  BinaryDiff,
  BinaryFormat,
  BinaryReport,
  DetectedItem,
  DiffByteChange,
  DiffBytes,
  DiffDetection,
  DiffFileSide,
  DiffImphash,
  DiffNameSize,
  DiffReportComparison,
  DiffSectionChange,
  ExportInfo,
  ImportInfo,
  SectionInfo,
  StringInfo,
} from '../types/index.js'

const CONTEXT_RADIUS = 4
const MAX_DIFFERENCES = 10
const MAX_LISTED_STRINGS = 20

export class DiffError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DiffError'
  }
}

export function diffExitCode(result: BinaryDiff): 0 | 1 {
  return result.identical ? 0 : 1
}

export async function diff(pathA: string, pathB: string): Promise<BinaryDiff> {
  await assertReadableFile(pathA)
  await assertReadableFile(pathB)

  const [rawA, rawB] = await Promise.all([readBinary(pathA), readBinary(pathB)])
  const [reportA, reportB] = await Promise.all([analyzeOne(pathA), analyzeOne(pathB)])

  return buildDiff(pathA, pathB, rawA, rawB, reportA, reportB)
}

export async function diffOrExit(pathA: string, pathB: string): Promise<
  | { exitCode: 0 | 1; diff: BinaryDiff }
  | { exitCode: 2; error: string }
> {
  try {
    const result = await diff(pathA, pathB)
    return { exitCode: diffExitCode(result), diff: result }
  } catch (err) {
    return { exitCode: 2, error: err instanceof Error ? err.message : String(err) }
  }
}

async function assertReadableFile(path: string): Promise<void> {
  let info: Awaited<ReturnType<typeof stat>>
  try {
    info = await stat(path)
  } catch (err) {
    throw new DiffError(readError(path, err))
  }
  if (!info.isFile()) throw new DiffError(`not a file: ${path}`)
  try {
    await access(path, constants.R_OK)
  } catch (err) {
    throw new DiffError(readError(path, err))
  }
}

async function readBinary(path: string): Promise<Buffer> {
  try {
    return await readFile(path)
  } catch (err) {
    throw new DiffError(readError(path, err))
  }
}

async function analyzeOne(path: string): Promise<BinaryReport> {
  try {
    return await analyze(path)
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new DiffError(`failed to analyze ${path}: ${detail}`)
  }
}

function readError(path: string, err: unknown): string {
  const code = (err as NodeJS.ErrnoException).code
  if (code === 'ENOENT') return `file not found: ${path}`
  if (code === 'EACCES' || code === 'EPERM') return `file not readable: ${path}`
  const detail = err instanceof Error ? err.message : String(err)
  return `cannot read ${path}: ${detail}`
}

export function buildDiff(
  pathA: string,
  pathB: string,
  rawA: Uint8Array,
  rawB: Uint8Array,
  reportA: BinaryReport,
  reportB: BinaryReport,
): BinaryDiff {
  const bytes = diffBytes(rawA, rawB)
  return {
    identical: bytes.identical,
    fileA: fileSide(pathA, rawA, reportA),
    fileB: fileSide(pathB, rawB, reportB),
    bytes,
    report: diffReports(reportA, reportB),
  }
}

function fileSide(path: string, raw: Uint8Array, report: BinaryReport): DiffFileSide {
  return {
    path,
    name: basename(path) || report.file.name,
    size: raw.length,
    sha256: report.file.sha256,
    sha1: report.file.sha1,
    md5: report.file.md5,
  }
}

export function diffBytes(rawA: Uint8Array, rawB: Uint8Array): DiffBytes {
  const sizeA = rawA.length
  const sizeB = rawB.length
  const compared = Math.max(sizeA, sizeB)
  const differences: DiffByteChange[] = []
  let differingBytes = 0

  for (let offset = 0; offset < compared; offset++) {
    const a = offset < sizeA ? rawA[offset]! : undefined
    const b = offset < sizeB ? rawB[offset]! : undefined
    if (a === b) continue
    differingBytes++
    if (differences.length < MAX_DIFFERENCES) {
      differences.push({
        offset,
        a: a === undefined ? null : hexByte(a),
        b: b === undefined ? null : hexByte(b),
        contextA: hexContext(rawA, offset),
        contextB: hexContext(rawB, offset),
      })
    }
  }

  const similarity = compared === 0 ? 100 : round2(((compared - differingBytes) / compared) * 100)

  return {
    sizeA,
    sizeB,
    identical: differingBytes === 0,
    differingBytes,
    similarity,
    differences,
  }
}

function hexContext(data: Uint8Array, offset: number): string {
  if (offset < 0 || offset >= data.length) return ''
  const start = Math.max(0, offset - CONTEXT_RADIUS)
  const end = Math.min(data.length - 1, offset + CONTEXT_RADIUS)
  const parts: string[] = []
  for (let i = start; i <= end; i++) {
    const hex = hexByte(data[i]!)
    parts.push(i === offset ? `[${hex}]` : hex)
  }
  return parts.join(' ')
}

function hexByte(value: number): string {
  return value.toString(16).padStart(2, '0')
}

function round2(value: number): number {
  return Math.round(value * 100) / 100
}

function diffReports(a: BinaryReport, b: BinaryReport): DiffReportComparison {
  const imports = diffLabels(a.imports.map(importLabel), b.imports.map(importLabel))
  const exports = diffLabels(a.exports.map(exportLabel), b.exports.map(exportLabel))
  const strings = diffStrings(a.strings, b.strings)

  return {
    imphash: diffImphash(a, b),
    imports,
    exports,
    sections: diffSections(a.sections, b.sections),
    strings,
    compiler: diffDetection(a.compiler, b.compiler),
    packer: diffDetection(a.packer, b.packer),
    language: diffDetection(a.language, b.language),
    entryPoint: { changed: a.entryPoint !== b.entryPoint, a: a.entryPoint, b: b.entryPoint },
    format: valueChange(a.format, b.format),
    architecture: valueChange(a.architecture, b.architecture),
  }
}

function importLabel(item: ImportInfo): string {
  return `${item.module}.${item.name}`
}

function exportLabel(item: ExportInfo): string {
  return `${item.name} @ 0x${item.address.toString(16)}`
}

function diffLabels(a: string[], b: string[]): { added: string[]; removed: string[] } {
  const counts = (values: string[]) => {
    const map = new Map<string, number>()
    for (const value of values) map.set(value, (map.get(value) ?? 0) + 1)
    return map
  }
  const left = counts(a)
  const right = counts(b)
  const added: string[] = []
  const removed: string[] = []
  for (const key of [...new Set([...left.keys(), ...right.keys()])].sort()) {
    const delta = (right.get(key) ?? 0) - (left.get(key) ?? 0)
    for (let i = 0; i < delta; i++) added.push(key)
    for (let i = 0; i < -delta; i++) removed.push(key)
  }
  return { added, removed }
}

function diffStrings(a: StringInfo[], b: StringInfo[]): DiffReportComparison['strings'] {
  const lists = diffLabels(a.map(item => item.value), b.map(item => item.value))
  return {
    added: lists.added.slice(0, MAX_LISTED_STRINGS),
    removed: lists.removed.slice(0, MAX_LISTED_STRINGS),
    addedTotal: lists.added.length,
    removedTotal: lists.removed.length,
  }
}

function diffSections(
  a: SectionInfo[],
  b: SectionInfo[],
): { added: DiffNameSize[]; removed: DiffNameSize[]; changed: DiffSectionChange[] } {
  const added: DiffNameSize[] = []
  const removed: DiffNameSize[] = []
  const changed: DiffSectionChange[] = []
  const used = new Set<number>()

  for (const section of a) {
    const index = b.findIndex((candidate, i) => !used.has(i) && candidate.name === section.name)
    if (index === -1) {
      removed.push({ name: section.name, size: section.size })
      continue
    }
    used.add(index)
    const other = b[index]!
    if (other.size !== section.size) {
      changed.push({ name: section.name, sizeA: section.size, sizeB: other.size })
    }
  }

  b.forEach((section, index) => {
    if (!used.has(index)) added.push({ name: section.name, size: section.size })
  })

  added.sort((left, right) => left.name.localeCompare(right.name))
  removed.sort((left, right) => left.name.localeCompare(right.name))
  changed.sort((left, right) => left.name.localeCompare(right.name))
  return { added, removed, changed }
}

function diffImphash(a: BinaryReport, b: BinaryReport): DiffImphash {
  const left = readImphash(a)
  const right = readImphash(b)
  return {
    same: !left.missing && !right.missing && left.value === right.value,
    a: left.value,
    b: right.value,
    missingA: left.missing,
    missingB: right.missing,
  }
}

function readImphash(report: BinaryReport): { missing: boolean; value: string | null } {
  if (!Object.prototype.hasOwnProperty.call(report.metadata, 'imphash')) {
    return { missing: true, value: null }
  }
  const value = report.metadata.imphash
  if (typeof value !== 'string') return { missing: true, value: null }
  return { missing: false, value }
}

function diffDetection(a: DetectedItem | null, b: DetectedItem | null): DiffDetection {
  const left = detectionSide(a)
  const right = detectionSide(b)
  const changed = left?.name !== right?.name || left?.confidence !== right?.confidence
  return { changed, a: left, b: right }
}

function detectionSide(item: DetectedItem | null): DiffDetection['a'] {
  if (!item) return null
  return { name: item.name, confidence: item.confidence }
}

function valueChange<T extends BinaryFormat | Architecture | number>(a: T, b: T): { changed: boolean; a: T; b: T } {
  return { changed: a !== b, a, b }
}
