import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan } from '../scan/index.js'
import { toScanCSV, toScanJSON, toScanTable } from '../reporters/scan.js'

function minimalPE(): Uint8Array {
  const buf = new Uint8Array(0x1000)
  buf[0] = 0x4D
  buf[1] = 0x5A
  const peOff = 0x80
  buf[0x3C] = peOff
  buf[peOff] = 0x50
  buf[peOff + 1] = 0x45
  buf[peOff + 2] = 0x00
  buf[peOff + 3] = 0x00
  buf[peOff + 4] = 0x4C
  buf[peOff + 5] = 0x01
  return buf
}

let root = ''

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'hexlens-scan-'))
  await mkdir(join(root, 'nested'))
  await writeFile(join(root, 'sample.exe'), minimalPE())
  await writeFile(join(root, 'nested', 'nested.exe'), minimalPE())
  await writeFile(join(root, 'notes.txt'), 'not a binary')
  await writeFile(join(root, 'nested', 'deep.bin'), 'also not a binary')
  await writeFile(join(root, '.hidden.exe'), minimalPE())
})

afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

describe('scan', () => {
  it('finds binaries recursively and skips unsupported files', async () => {
    const summary = await scan(root)

    expect(summary.files).toHaveLength(2)
    expect(summary.skipped).toBe(2)
    expect(summary.errors).toHaveLength(0)
    expect(summary.files.map(file => file.relativePath).sort()).toEqual([
      'nested/nested.exe',
      'sample.exe',
    ])
    expect(summary.files.every(file => file.report.format === 'PE')).toBe(true)
  })

  it('flags unsigned binaries without exploit mitigations', async () => {
    const summary = await scan(root)
    const flags = summary.files[0]!.flags

    expect(summary.files[0]!.risk).toBe('medium')
    expect(flags.map(flag => flag.code)).toEqual(
      expect.arrayContaining(['UNSIGNED', 'NO-ASLR', 'NO-DEP', 'NO-NX']),
    )
  })

  it('supports non-recursive scans', async () => {
    const summary = await scan(root, { recursive: false })

    expect(summary.files).toHaveLength(1)
    expect(summary.files[0]!.relativePath).toBe('sample.exe')
    expect(summary.skipped).toBe(1)
  })

  it('can include unrecognized files', async () => {
    const summary = await scan(root, { includeUnknown: true })

    expect(summary.files).toHaveLength(4)
    expect(summary.files.some(file => file.report.format === 'Unknown')).toBe(true)
  })

  it('skips hidden files by default and includes them on request', async () => {
    expect((await scan(root)).files.some(file => file.relativePath === '.hidden.exe')).toBe(false)

    const summary = await scan(root, { includeHidden: true })
    expect(summary.files.some(file => file.relativePath === '.hidden.exe')).toBe(true)
  })

  it('raises high-risk flags for suspicious capabilities', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'hexlens-scan-risk-'))
    try {
      const buf = minimalPE()
      buf.set(new TextEncoder().encode('VirtualAllocEx WriteProcessMemory CreateRemoteThread'), 0x200)
      await writeFile(join(dir, 'injector.exe'), buf)

      const summary = await scan(dir)
      expect(summary.files).toHaveLength(1)
      expect(summary.files[0]!.risk).toBe('high')
      expect(summary.files[0]!.flags.map(flag => flag.code)).toContain('INJECT')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('renders a terminal triage table', async () => {
    const summary = await scan(root)
    const table = toScanTable(summary, { color: false })

    expect(table).toContain('HexLens Batch Scan')
    expect(table).toContain('SIZE')
    expect(table).toContain('RISK')
    expect(table).toContain('FLAGS')
    expect(table).toContain('sample.exe')
    expect(table).toContain('UNSIGNED')
    expect(table).toContain('Scanned 2 files')
  })

  it('renders JSON and CSV scan reports', async () => {
    const summary = await scan(root)

    const parsed = JSON.parse(toScanJSON(summary))
    expect(parsed.scanned).toBe(2)
    expect(parsed.files[0].report.format).toBe('PE')
    expect(parsed.files[0].flags.length).toBeGreaterThan(0)

    const csv = toScanCSV(summary)
    expect(csv.split('\n')[0]).toContain('"File","Size","Format"')
    expect(csv).toContain('sample.exe')
  })
})
