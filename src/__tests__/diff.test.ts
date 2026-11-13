import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { diff, diffExitCode, diffOrExit } from '../diff/index.js'
import { toDiffJSON, toDiffTerminal } from '../reporters/diff.js'

const base = Uint8Array.from([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
const changed = Uint8Array.from([0x10, 0x20, 0xff, 0x40, 0x50, 0x61, 0x70, 0x80])

function wasm(imports: { module: string; name: string }[]): Uint8Array {
  const body: number[] = [imports.length]
  for (const item of imports) {
    const moduleBytes = [...Buffer.from(item.module)]
    const nameBytes = [...Buffer.from(item.name)]
    body.push(moduleBytes.length, ...moduleBytes, nameBytes.length, ...nameBytes, 0x00)
  }
  return Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d,
    0x01, 0x00, 0x00, 0x00,
    0x02, body.length,
    ...body,
  ])
}

let root = ''

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'hexlens-diff-'))
  await writeFile(join(root, 'same-a.bin'), base)
  await writeFile(join(root, 'same-b.bin'), base)
  await writeFile(join(root, 'changed.bin'), changed)
  await writeFile(join(root, 'old.bin'), wasm([{ module: 'env', name: 'print' }]))
  await writeFile(join(root, 'new.bin'), wasm([
    { module: 'env', name: 'print' },
    { module: 'env', name: 'extra' },
  ]))
  const manyA = new Uint8Array(12)
  const manyB = new Uint8Array(12).fill(0xff)
  await writeFile(join(root, 'many-a.bin'), manyA)
  await writeFile(join(root, 'many-b.bin'), manyB)
})

afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

describe('diff', () => {
  it('reports the exact offsets and differing-byte count', async () => {
    const result = await diff(join(root, 'same-a.bin'), join(root, 'changed.bin'))

    expect(result.bytes.differingBytes).toBe(2)
    expect(result.bytes.differences.map(change => change.offset)).toEqual([2, 5])
    expect(result.bytes.differences[0]).toMatchObject({ a: '30', b: 'ff' })
    expect(result.bytes.differences[1]).toMatchObject({ a: '60', b: '61' })
    expect(result.bytes.differences[0]!.contextA).toContain('[30]')
    expect(result.bytes.differences[0]!.contextB).toContain('[ff]')
    expect(result.bytes.similarity).toBe(75)
    expect(result.identical).toBe(false)
    expect(diffExitCode(result)).toBe(1)

    const text = toDiffTerminal(result)
    expect(text).toContain('0x00000002')
    expect(text).toContain('0x00000005')
    expect(text).toContain('2 bytes')
  })

  it('lists at most 10 differing offsets while counting every byte', async () => {
    const result = await diff(join(root, 'many-a.bin'), join(root, 'many-b.bin'))

    expect(result.bytes.differingBytes).toBe(12)
    expect(result.bytes.differences).toHaveLength(10)
    expect(result.bytes.differences.map(change => change.offset)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
  })

  it('says identical and exits 0 when the bytes match', async () => {
    const outcome = await diffOrExit(join(root, 'same-a.bin'), join(root, 'same-b.bin'))

    expect(outcome.exitCode).toBe(0)
    if (outcome.exitCode !== 0) return
    expect(outcome.diff.identical).toBe(true)
    expect(outcome.diff.bytes.differingBytes).toBe(0)
    expect(outcome.diff.bytes.similarity).toBe(100)
    expect(outcome.diff.fileA.sha256).toBe(outcome.diff.fileB.sha256)
    expect(outcome.diff.fileA.sha256).toMatch(/^[a-f0-9]{64}$/)

    const text = toDiffTerminal(outcome.diff)
    expect(text).toContain('identical')
    expect(text).toContain(outcome.diff.fileA.sha256)
    expect(text).toContain(outcome.diff.fileB.sha256)
  })

  it('lists an added import and an added string', async () => {
    const result = await diff(join(root, 'old.bin'), join(root, 'new.bin'))

    expect(result.report.imports.added).toContain('env.extra')
    expect(result.report.imports.added).not.toContain('env.print')
    expect(result.report.imports.removed).not.toContain('env.print')
    expect(result.report.strings.added).toContain('extra')
    expect(result.report.strings.removed).not.toContain('print')
    expect(result.report.sections.changed).toContainEqual({ name: 'import', sizeA: 12, sizeB: 23 })
    expect(result.report.imphash.missingA).toBe(false)
    expect(result.report.imphash.missingB).toBe(false)
    expect(result.report.imphash.same).toBe(false)
    expect(diffExitCode(result)).toBe(1)

    const text = toDiffTerminal(result)
    expect(text).toContain('+ env.extra')
    expect(text).toContain('+ extra')
  })

  it('exits non-zero and names a missing file', async () => {
    const missing = join(root, 'missing.bin')
    const outcome = await diffOrExit(missing, join(root, 'same-a.bin'))

    expect(outcome.exitCode).not.toBe(0)
    expect(outcome.exitCode).toBe(2)
    if (outcome.exitCode !== 2) return
    expect(outcome.error).toContain('missing.bin')
    expect(outcome.error).toContain('file not found')
  })

  it('prints byte stats and added/removed arrays as JSON', async () => {
    const result = await diff(join(root, 'old.bin'), join(root, 'new.bin'))
    const parsed = JSON.parse(toDiffJSON(result)) as {
      bytes: { differingBytes: number; similarity: number; sizeA: number; sizeB: number }
      report: {
        imports: { added: string[]; removed: string[] }
        exports: { added: string[]; removed: string[] }
        strings: { added: string[]; removed: string[] }
        sections: { changed: unknown[] }
      }
    }

    expect(parsed.bytes.differingBytes).toBe(result.bytes.differingBytes)
    expect(parsed.bytes.similarity).toBe(result.bytes.similarity)
    expect(parsed.bytes.sizeA).toBe(result.fileA.size)
    expect(parsed.bytes.sizeB).toBe(result.fileB.size)
    expect(parsed.report.imports.added).toContain('env.extra')
    expect(Array.isArray(parsed.report.imports.removed)).toBe(true)
    expect(Array.isArray(parsed.report.exports.added)).toBe(true)
    expect(Array.isArray(parsed.report.exports.removed)).toBe(true)
    expect(parsed.report.strings.added).toContain('extra')
    expect(Array.isArray(parsed.report.sections.changed)).toBe(true)
  })
})
