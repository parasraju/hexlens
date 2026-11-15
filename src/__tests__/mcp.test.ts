import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { analyze } from '../analyze.js'
import { diff } from '../diff/index.js'
import { YaraScanner } from '../yara/index.js'

const RULE = `rule MzHeader {
  strings:
    $mz = "MZ"
  condition:
    $mz at 0
}
`

const repoRoot = fileURLToPath(new URL('../..', import.meta.url))

const base = Uint8Array.from([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
const changed = Uint8Array.from([0x10, 0x20, 0xff, 0x40, 0x50, 0x61, 0x70, 0x80])

function minimalPE(): Uint8Array {
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
  return buf
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function toolText(result: unknown): { text: string; isError: boolean } {
  if (!isRecord(result) || !Array.isArray(result.content)) {
    throw new Error('tool result has no content')
  }
  let text = ''
  for (const block of result.content) {
    if (isRecord(block) && block.type === 'text' && typeof block.text === 'string') {
      text = block.text
      break
    }
  }
  return { text, isError: result.isError === true }
}

function parseObject(text: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text)
  if (!isRecord(value)) throw new Error('expected a JSON object')
  return value
}

function readImphash(report: unknown): string {
  if (!isRecord(report) || !isRecord(report.metadata) || typeof report.metadata.imphash !== 'string') {
    throw new Error('report has no imphash string')
  }
  return report.metadata.imphash
}

let root = ''
let client: Client | undefined

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'hexlens-mcp-'))
  await writeFile(join(root, 'sample.exe'), minimalPE())
  await writeFile(join(root, 'other.exe'), minimalPE())
  await writeFile(join(root, 'same-a.bin'), base)
  await writeFile(join(root, 'changed.bin'), changed)
  await writeFile(join(root, 'notes.txt'), 'not a binary')
  await writeFile(join(root, 'rules.yar'), RULE)

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      join(repoRoot, 'node_modules/vite-node/vite-node.mjs'),
      join(repoRoot, 'src/cli.ts'),
      'mcp',
    ],
    cwd: repoRoot,
    stderr: 'pipe',
  })
  client = new Client({ name: 'hexlens-mcp-test', version: '0.0.0' })
  await client.connect(transport)
}, 20000)

afterAll(async () => {
  await client?.close()
  if (root) await rm(root, { recursive: true, force: true })
})

describe('hexlens mcp', () => {
  it('lists exactly the three tools over stdio', async () => {
    const listed = await client!.listTools()
    expect(listed.tools.map(tool => tool.name).sort()).toEqual([
      'hexlens_analyze',
      'hexlens_diff',
      'hexlens_scan',
    ])
  })

  it('returns the same format and imphash as analyze()', async () => {
    const file = join(root, 'sample.exe')
    const direct = await analyze(file)
    const result = await client!.callTool({ name: 'hexlens_analyze', arguments: { path: file } })
    const { text, isError } = toolText(result)
    expect(isError).toBe(false)

    const report = parseObject(text)
    expect(report.format).toBe(direct.format)
    expect(readImphash(report)).toBe(readImphash(direct))
    expect(text).not.toContain('Analyzing binary')
  })

  it('summarizes both binaries in a directory', async () => {
    const result = await client!.callTool({ name: 'hexlens_scan', arguments: { target: root } })
    const { text, isError } = toolText(result)
    expect(isError).toBe(false)

    const summary = parseObject(text)
    if (!Array.isArray(summary.files)) throw new Error('scan result has no files list')
    const paths = summary.files.map(file => {
      if (!isRecord(file) || typeof file.relativePath !== 'string') {
        throw new Error('scan file is missing relativePath')
      }
      return file.relativePath
    })
    expect(paths.sort()).toEqual(['other.exe', 'sample.exe'])
  })

  it('reports the same byte diff as diff()', async () => {
    const fileA = join(root, 'same-a.bin')
    const fileB = join(root, 'changed.bin')
    const direct = await diff(fileA, fileB)
    const result = await client!.callTool({
      name: 'hexlens_diff',
      arguments: { fileA, fileB },
    })
    const { text, isError } = toolText(result)
    expect(isError).toBe(false)
    expect(parseObject(text)).toEqual(JSON.parse(JSON.stringify(direct)))
  })

  it('names a missing file and keeps the server up', async () => {
    const missing = join(root, 'missing.bin')
    const failed = await client!.callTool({ name: 'hexlens_analyze', arguments: { path: missing } })
    const error = toolText(failed)
    expect(error.isError).toBe(true)
    expect(error.text).toContain('missing.bin')
    expect(error.text.trim().length).toBeGreaterThan(0)

    const listed = await client!.listTools()
    expect(listed.tools).toHaveLength(3)

    const file = join(root, 'sample.exe')
    const again = await client!.callTool({ name: 'hexlens_analyze', arguments: { path: file } })
    const recovered = toolText(again)
    expect(recovered.isError).toBe(false)
    expect(parseObject(recovered.text).format).toBe('PE')
  })

  it('attaches YARA matches when yaraRules is set', async () => {
    const file = join(root, 'sample.exe')
    const rules = join(root, 'rules.yar')
    const direct = (await YaraScanner.load(rules)).match(await readFile(file), file)
    const result = await client!.callTool({
      name: 'hexlens_analyze',
      arguments: { path: file, yaraRules: rules },
    })
    const { text, isError } = toolText(result)
    expect(isError).toBe(false)
    const report = parseObject(text)
    expect(report.yaraMatches).toEqual(direct)
    expect(report.format).toBe('PE')
  })

  it('names a non-binary file instead of returning an empty report', async () => {
    const notes = join(root, 'notes.txt')
    const result = await client!.callTool({ name: 'hexlens_analyze', arguments: { path: notes } })
    const error = toolText(result)
    expect(error.isError).toBe(true)
    expect(error.text).toContain('notes.txt')
    expect(error.text.toLowerCase()).toContain('not a recognized binary')
  })
})
