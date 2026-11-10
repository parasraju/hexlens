import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { scan } from '../scan/index.js'
import { YaraScanner } from '../yara/index.js'
import { toScanJSON, toScanTable } from '../reporters/scan.js'

const RULE = `rule HexLensTest
{
    meta:
        author = "hexlens"
    strings:
        $mz = "MZ"
        $marker = "HEXLENS_YARA_TEST"
    condition:
        $mz at 0 and $marker
}
`

function minimalPE(marker?: string): Uint8Array {
  const buf = new Uint8Array(0x1000)
  buf[0] = 0x4d
  buf[1] = 0x5a
  const peOff = 0x80
  buf[0x3c] = peOff
  buf[peOff] = 0x50
  buf[peOff + 1] = 0x45
  buf[peOff + 2] = 0x00
  buf[peOff + 3] = 0x00
  buf[peOff + 4] = 0x4c
  buf[peOff + 5] = 0x01
  if (marker) buf.set(new TextEncoder().encode(marker), 0x200)
  return buf
}

let root = ''
let rulePath = ''

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'hexlens-yara-'))
  rulePath = join(root, 'rules.yar')
  await writeFile(rulePath, RULE)
  await writeFile(join(root, 'match.exe'), minimalPE('HEXLENS_YARA_TEST'))
  await writeFile(join(root, 'clean.exe'), minimalPE())
})

afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

describe('YARA rule scanning', () => {
  it('loads rules and matches a binary in memory', async () => {
    const scanner = await YaraScanner.load(rulePath)
    const matches = scanner.match(minimalPE('HEXLENS_YARA_TEST'), 'match.exe')

    expect(matches).toHaveLength(1)
    expect(matches[0]!.rule).toBe('HexLensTest')
    expect(matches[0]!.file).toBe('match.exe')
    expect(matches[0]!.meta.author).toBe('hexlens')
    expect(matches[0]!.strings.some(string => string.identifier === '$marker')).toBe(true)
  })

  it('reports nothing for a clean binary', async () => {
    const scanner = await YaraScanner.load(rulePath)
    expect(scanner.match(minimalPE(), 'clean.exe')).toEqual([])
  })

  it('reports matches and clean files in a batch scan', async () => {
    const summary = await scan(root, { yara: rulePath })
    expect(summary.yaraRules).toBe(resolve(rulePath))

    const matching = summary.files.find(file => file.relativePath === 'match.exe')!
    const clean = summary.files.find(file => file.relativePath === 'clean.exe')!

    expect(matching.yaraMatches?.map(match => match.rule)).toEqual(['HexLensTest'])
    expect(clean.yaraMatches).toEqual([])

    const table = toScanTable(summary, { color: false })
    expect(table).toContain('YARA:HexLensTest')
    expect(table).toContain('YARA: 1 rule match')
  })

  it('includes yaraMatches for every file in JSON output', async () => {
    const summary = await scan(root, { yara: rulePath })
    const parsed = JSON.parse(toScanJSON(summary))

    const matching = parsed.files.find((file: { path: string }) => file.path === 'match.exe')
    const clean = parsed.files.find((file: { path: string }) => file.path === 'clean.exe')

    expect(matching.yaraMatches).toHaveLength(1)
    expect(matching.yaraMatches[0].rule).toBe('HexLensTest')
    expect(matching.yaraMatches[0].file).toBe('match.exe')
    expect(clean.yaraMatches).toEqual([])
  })

  it('leaves output unchanged when no rule file is passed', async () => {
    const summary = await scan(root)
    expect(summary.yaraRules).toBeUndefined()
    expect(summary.files.every(file => file.yaraMatches === undefined)).toBe(true)

    const parsed = JSON.parse(toScanJSON(summary))
    expect(parsed.files.every((file: Record<string, unknown>) => !('yaraMatches' in file))).toBe(true)
    expect(toScanTable(summary, { color: false })).not.toContain('YARA')
  })

  it('fails clearly when the rule file is missing', async () => {
    const missing = join(root, 'missing.yar')
    await expect(YaraScanner.load(missing)).rejects.toThrow(/YARA rule file not found/)
    await expect(scan(root, { yara: missing })).rejects.toThrow(/YARA rule file not found/)
  })

  it('fails clearly when the rule file does not compile', async () => {
    const broken = join(root, 'broken.yar')
    await writeFile(broken, 'rule Broken {\n')

    await expect(YaraScanner.load(broken)).rejects.toThrow(/Invalid YARA rule file/)
    await expect(YaraScanner.load(broken)).rejects.toThrow(/broken\.yar: line \d+: syntax error/)
    await expect(scan(root, { yara: broken })).rejects.toThrow(/Invalid YARA rule file/)
  })

  it('rejects an empty rule file instead of scanning without rules', async () => {
    const empty = join(root, 'empty.yar')
    await writeFile(empty, '   \n')
    await expect(YaraScanner.load(empty)).rejects.toThrow(/YARA rule file is empty/)
  })
})
