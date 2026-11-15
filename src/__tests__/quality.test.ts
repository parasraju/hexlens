import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { BufferReader } from '../utils/buffer-reader.js'
import { detectArchitecture, detectFormat, parseDEX, parseDotNet, parseELF, parseMachO, parsePE, parseWASM } from '../parsers/index.js'
import { analyze } from '../analyze.js'
import { detectCompiler, detectLibraries, detectPacker } from '../detectors/index.js'
import { toCSV, toHTML, toMarkdown, toTerminal } from '../reporters/index.js'
import type { PluginContext } from '../types/plugin.js'

function elf64(): Uint8Array {
  const phoff = 64
  const phnum = 2
  const phentsize = 56
  const shoff = phoff + phnum * phentsize
  const shnum = 3
  const shentsize = 64
  const strOff = shoff + shnum * shentsize
  const str = new TextEncoder().encode('\0.text\0.shstrtab\0')
  const buf = new Uint8Array(strOff + str.length)
  const v = new DataView(buf.buffer)
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0)
  v.setUint16(16, 2, true)
  v.setUint16(18, 0x3e, true)
  v.setUint32(20, 1, true)
  v.setBigUint64(24, 0x401000n, true)
  v.setBigUint64(32, BigInt(phoff), true)
  v.setBigUint64(40, BigInt(shoff), true)
  v.setUint16(52, 64, true)
  v.setUint16(54, phentsize, true)
  v.setUint16(56, phnum, true)
  v.setUint16(58, shentsize, true)
  v.setUint16(60, shnum, true)
  v.setUint16(62, 2, true)

  v.setUint32(phoff, 1, true)
  v.setUint32(phoff + 4, 5, true)
  v.setBigUint64(phoff + 8, 0n, true)
  v.setBigUint64(phoff + 16, 0x400000n, true)
  v.setBigUint64(phoff + 32, BigInt(buf.length), true)
  v.setBigUint64(phoff + 40, BigInt(buf.length), true)

  const stack = phoff + phentsize
  v.setUint32(stack, 0x6474e551, true)
  v.setUint32(stack + 4, 6, true)

  const text = shoff + shentsize
  v.setUint32(text, 1, true)
  v.setUint32(text + 4, 1, true)
  v.setBigUint64(text + 8, 6n, true)
  v.setBigUint64(text + 16, 0x401000n, true)
  v.setBigUint64(text + 24, 0n, true)
  v.setBigUint64(text + 32, 32n, true)

  const shstr = shoff + 2 * shentsize
  v.setUint32(shstr, 7, true)
  v.setUint32(shstr + 4, 3, true)
  v.setBigUint64(shstr + 24, BigInt(strOff), true)
  v.setBigUint64(shstr + 32, BigInt(str.length), true)
  buf.set(str, strOff)
  return buf
}

function elf32(): Uint8Array {
  const phoff = 52
  const phnum = 1
  const phentsize = 32
  const shoff = phoff + phnum * phentsize
  const shnum = 3
  const shentsize = 40
  const strOff = shoff + shnum * shentsize
  const str = new TextEncoder().encode('\0.text\0.shstrtab\0')
  const buf = new Uint8Array(strOff + str.length)
  const v = new DataView(buf.buffer)
  buf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1], 0)
  v.setUint16(16, 2, true)
  v.setUint16(18, 3, true)
  v.setUint32(20, 1, true)
  v.setUint32(24, 0x08048054, true)
  v.setUint32(28, phoff, true)
  v.setUint32(32, shoff, true)
  v.setUint32(36, 0, true)
  v.setUint16(40, 52, true)
  v.setUint16(42, phentsize, true)
  v.setUint16(44, phnum, true)
  v.setUint16(46, shentsize, true)
  v.setUint16(48, shnum, true)
  v.setUint16(50, 2, true)

  v.setUint32(phoff, 0x6474e551, true)
  v.setUint32(phoff + 24, 6, true)

  const text = shoff + shentsize
  v.setUint32(text, 1, true)
  v.setUint32(text + 4, 1, true)
  v.setUint32(text + 8, 6, true)
  v.setUint32(text + 12, 0x08048054, true)
  v.setUint32(text + 20, 32, true)

  const shstr = shoff + 2 * shentsize
  v.setUint32(shstr, 7, true)
  v.setUint32(shstr + 4, 3, true)
  v.setUint32(shstr + 16, strOff, true)
  v.setUint32(shstr + 20, str.length, true)
  buf.set(str, strOff)
  return buf
}

function pe32(): Uint8Array {
  const buf = new Uint8Array(0x400)
  const v = new DataView(buf.buffer)
  buf[0] = 0x4d
  buf[1] = 0x5a
  const pe = 0x80
  v.setUint32(0x3c, pe, true)
  buf.set([0x50, 0x45, 0x00, 0x00], pe)
  v.setUint16(pe + 4, 0x14c, true)
  v.setUint16(pe + 6, 1, true)
  v.setUint16(pe + 20, 0xe0, true)
  v.setUint16(pe + 22, 0x0102, true)
  v.setUint16(pe + 24, 0x10b, true)
  v.setUint32(pe + 24 + 16, 0x1234, true)
  v.setUint32(pe + 24 + 28, 0x00400000, true)
  v.setUint32(pe + 24 + 32, 0x1000, true)
  v.setUint32(pe + 24 + 36, 0x200, true)
  v.setUint16(pe + 24 + 68, 3, true)
  v.setUint16(pe + 24 + 70, 0x0140, true)
  v.setUint32(pe + 24 + 92, 16, true)
  const sec = pe + 24 + 0xe0
  buf.set(new TextEncoder().encode('.text'), sec)
  v.setUint32(sec + 8, 0x100, true)
  v.setUint32(sec + 12, 0x1000, true)
  v.setUint32(sec + 16, 0x200, true)
  v.setUint32(sec + 20, 0x200, true)
  v.setUint32(sec + 36, 0x60000020, true)
  return buf
}

function macho64(): Uint8Array {
  const header = 32
  const seg = 152
  const main = 24
  const buf = new Uint8Array(header + seg + main)
  const v = new DataView(buf.buffer)
  v.setUint32(0, 0xfeedfacf, true)
  v.setUint32(4, 0x01000007, true)
  v.setUint32(12, 2, true)
  v.setUint32(16, 2, true)
  v.setUint32(20, seg + main, true)
  v.setUint32(24, 0x200000, true)

  const o = header
  v.setUint32(o, 0x19, true)
  v.setUint32(o + 4, seg, true)
  buf.set(new TextEncoder().encode('__TEXT'), o + 8)
  v.setBigUint64(o + 24, 0x100000000n, true)
  v.setBigUint64(o + 32, 0x1000n, true)
  v.setBigUint64(o + 48, BigInt(buf.length), true)
  v.setUint32(o + 60, 5, true)
  v.setUint32(o + 64, 1, true)
  const s = o + 72
  buf.set(new TextEncoder().encode('__text'), s)
  buf.set(new TextEncoder().encode('__TEXT'), s + 16)
  v.setBigUint64(s + 32, 0x100001000n, true)
  v.setBigUint64(s + 40, 16n, true)
  v.setUint32(s + 48, 32, true)

  const m = header + seg
  v.setUint32(m, 0x80000028, true)
  v.setUint32(m + 4, main, true)
  v.setBigUint64(m + 8, 0x1000n, true)
  return buf
}

function ctx(partial: Partial<PluginContext> & Pick<PluginContext, 'raw'>): PluginContext {
  return {
    format: 'ELF',
    architecture: 'x64',
    sections: [],
    strings: [],
    metadata: {},
    imports: [],
    exports: [],
    ...partial,
  }
}

describe('ELF header layout', () => {
  it('reads ELF64 e_entry and section names from the spec offsets', () => {
    const elf = parseELF(elf64())
    expect(elf).not.toBeNull()
    expect(elf!.entryPoint).toBe(0x401000)
    expect(elf!.sections.some(s => s.name === '.text')).toBe(true)
    expect(elf!.nx).toBe(true)
    expect(elf!.relro).toBe(false)
    expect(elf!.pie).toBe(false)
  })

  it('reads ELF32 e_entry and e_shoff from the spec offsets', () => {
    const elf = parseELF(elf32())
    expect(elf).not.toBeNull()
    expect(elf!.entryPoint).toBe(0x08048054)
    expect(elf!.sections.map(s => s.name)).toContain('.text')
    expect(elf!.nx).toBe(true)
  })

  it('copies the ELF entry point onto the analysis report', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'hexlens-elf-'))
    const path = join(dir, 'sample.elf')
    try {
      await writeFile(path, elf64())
      const report = await analyze(path)
      expect(report.entryPoint).toBe(0x401000)
      expect(report.format).toBe('ELF')
      expect(report.architecture).toBe('x64')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe('PE32 optional header', () => {
  it('reads ImageBase and DllCharacteristics after BaseOfData', () => {
    const pe = parsePE(pe32())
    expect(pe).not.toBeNull()
    expect(pe!.entryPoint).toBe(0x1234)
    expect(pe!.imageBase).toBe(0x400000)
    expect(pe!.dllCharacteristics).toBe(0x0140)
    expect(pe!.sections[0]?.name).toBe('.text')
  })
})

describe('Mach-O load commands', () => {
  it('walks every command and combines LC_MAIN with the __TEXT vmaddr', () => {
    const macho = parseMachO(macho64())
    expect(macho).not.toBeNull()
    expect(macho!.sections.map(s => s.name)).toContain('__text')
    expect(macho!.entryPoint).toBe(0x100000000 + 0x1000)
    expect(macho!.pie).toBe(true)
    expect(detectArchitecture(macho64(), 'Mach-O')).toBe('x64')
  })
})

describe('malformed input', () => {
  const blobs = [
    new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1]),
    new Uint8Array([0x7f, 0x45, 0x4c, 0x46]),
    new Uint8Array([0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00]),
    new Uint8Array([0x4d, 0x5a]),
    new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]),
    new Uint8Array([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 0xff, 0xff]),
    new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]),
    new Uint8Array(0),
    new Uint8Array(300).fill(0xff),
  ]

  it('does not throw from detectors or parsers', () => {
    for (const blob of blobs) {
      const format = detectFormat(blob)
      expect(() => detectArchitecture(blob, format.format)).not.toThrow()
      expect(() => parseELF(blob)).not.toThrow()
      expect(() => parsePE(blob)).not.toThrow()
      expect(() => parseMachO(blob)).not.toThrow()
      expect(() => parseWASM(blob)).not.toThrow()
      expect(() => parseDEX(blob)).not.toThrow()
      expect(() => parseDotNet(blob, [])).not.toThrow()
    }
  })

  it('does not throw when BufferReader is asked to read past the end', () => {
    const reader = BufferReader.from(new Uint8Array([1, 2, 3]))
    expect(reader.peekU32(0, true)).toBe(0)
    expect(reader.peekU64(0, true)).toBe(0n)
    expect(reader.readU32(true)).toBe(0)
    expect(reader.readCStringAt(10, 8)).toBe('')
  })
})

describe('packer false positives', () => {
  it('does not treat COMPRESSION as an MPRESS marker', () => {
    const raw = new TextEncoder().encode('CURLOPT_SSH_COMPRESSION CURLOPT_')
    const packed = detectPacker(ctx({
      raw,
      strings: [{ value: 'CURLOPT_SSH_COMPRESSION', type: 'ASCII', offset: 0 }],
      sections: [{
        name: '.text', rva: 0, fileOffset: 0, size: 20000, entropy: 7.9,
        permissions: 'ALLOC|EXEC|PROGBITS', alignment: 0,
      }],
      imports: [
        { module: 'libc.so.6', name: 'printf' },
        { module: 'libcurl.so.4', name: 'curl_easy_init' },
      ],
    }))
    expect(packed).toBeNull()
  })

  it('still detects a real UPX section', () => {
    const packed = detectPacker(ctx({
      raw: new TextEncoder().encode('UPX!'),
      sections: [{
        name: 'UPX0', rva: 0, fileOffset: 0, size: 100, entropy: 7.9,
        permissions: 'ALLOC|EXEC', alignment: 0,
      }],
    }))
    expect(packed?.name).toBe('UPX')
    expect(packed!.confidence).toBeGreaterThanOrEqual(80)
  })
})

describe('confidence calibration', () => {
  it('scores a GCC version string highly', () => {
    const raw = new TextEncoder().encode('GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\0')
    const compiler = detectCompiler(ctx({
      raw,
      sections: [
        { name: '.text', rva: 0, fileOffset: 0, size: 100, entropy: 5, permissions: 'ALLOC|EXEC', alignment: 0 },
        { name: '.gnu.hash', rva: 0, fileOffset: 0, size: 32, entropy: 4, permissions: 'ALLOC', alignment: 0 },
      ],
    }))
    expect(compiler?.name).toBe('GCC')
    expect(compiler!.confidence).toBeGreaterThanOrEqual(85)
  })

  it('prefers Clang when both a GCC and a Clang version string are present', () => {
    const raw = new TextEncoder().encode('GCC: (Ubuntu 14.2.0) 14.2.0\0Ubuntu clang version 18.1.3\0')
    const compiler = detectCompiler(ctx({ raw }))
    expect(compiler?.name).toBe('Clang')
    expect(compiler!.confidence).toBeGreaterThanOrEqual(85)
  })

  it('scores a linked libcurl highly', () => {
    const libs = detectLibraries(ctx({
      raw: new TextEncoder().encode('curl_easy_init\0curl_easy_perform\0libcurl/8.5.0\0'),
      metadata: { elfData: { needed: ['libcurl.so.4', 'libz.so.1', 'libc.so.6'] } },
      imports: [
        { module: '', name: 'curl_easy_init' },
        { module: '', name: 'curl_easy_perform' },
        { module: '', name: 'curl_easy_setopt' },
      ],
    }))
    const curl = libs.find(lib => lib.name === 'libcurl')
    const zlib = libs.find(lib => lib.name === 'zlib')
    expect(curl).toBeDefined()
    expect(curl!.confidence).toBeGreaterThanOrEqual(80)
    expect(zlib).toBeDefined()
    expect(zlib!.confidence).toBeGreaterThanOrEqual(70)
  })
})

describe('unrecognized files', () => {
  it('says the file is not a recognized binary instead of listing mitigations', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'hexlens-script-'))
    const path = join(dir, 'tool.sh')
    try {
      await writeFile(path, '#!/bin/sh\necho compression helper\n# ' + 'x'.repeat(70) + '\n')
      const report = await analyze(path)
      expect(report.format).toBe('Unknown')
      expect(report.security).toBeNull()
      expect(report.packer).toBeNull()
      expect(report.capabilities).toEqual([])
      const terminal = toTerminal(report)
      expect(terminal).toContain('Not a recognized binary')
      expect(terminal).not.toContain('ASLR')
      expect(toMarkdown(report)).toContain('Not a recognized binary')
      expect(toHTML(report)).toContain('Not a recognized binary')
      expect(toCSV(report)).toContain('Not a recognized binary')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

const live = existsSync('/usr/bin/ls') ? it : it.skip

describe('live system binaries', () => {
  live('parses /usr/bin/ls without throwing and reports a non-zero entry point', async () => {
    const report = await analyze('/usr/bin/ls')
    expect(report.format).toBe('ELF')
    expect(report.architecture).toBe('x64')
    expect(report.entryPoint).not.toBe(0)
    expect(report.sections.map(s => s.name)).toEqual(expect.arrayContaining(['.text', '.dynstr']))
    expect(report.packer).toBeNull()
    expect(report.compiler?.name).toBe('GCC')
    expect(report.compiler!.confidence).toBeGreaterThanOrEqual(80)
    expect(report.language?.name).toBe('C')
    expect(report.language!.confidence).toBeGreaterThanOrEqual(70)
  })

  live('does not flag /usr/bin/curl as MPRESS', async () => {
    if (!existsSync('/usr/bin/curl')) return
    const report = await analyze('/usr/bin/curl')
    expect(report.entryPoint).not.toBe(0)
    expect(report.packer).toBeNull()
    const curl = report.libraries.find(lib => lib.name === 'libcurl')
    expect(curl).toBeDefined()
    expect(curl!.confidence).toBeGreaterThanOrEqual(80)
  })

  live('agrees with the ELF entry point recorded in the file header', async () => {
    const data = await readFile('/usr/bin/ls')
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
    const entry = Number(view.getBigUint64(24, true))
    expect(parseELF(data)!.entryPoint).toBe(entry)
  })
})
