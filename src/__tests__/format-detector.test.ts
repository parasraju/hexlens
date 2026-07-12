import { describe, it, expect } from 'vitest'
import { detectFormat, detectArchitecture, detectOS } from '../parsers/format-detector.js'

function makePE(is64: boolean): Uint8Array {
  const buf = new Uint8Array(0x1000)
  buf[0] = 0x4D; buf[1] = 0x5A
  const peOff = 0x80
  buf[0x3C] = peOff
  buf[peOff] = 0x50; buf[peOff + 1] = 0x45; buf[peOff + 2] = 0x00; buf[peOff + 3] = 0x00
  const machine = is64 ? 0x8664 : 0x14C
  buf[peOff + 4] = machine & 0xFF
  buf[peOff + 5] = (machine >> 8) & 0xFF
  return buf
}

function makeELF(is64: boolean): Uint8Array {
  const buf = new Uint8Array(0x100)
  buf[0] = 0x7F; buf[1] = 0x45; buf[2] = 0x4C; buf[3] = 0x46
  buf[4] = is64 ? 2 : 1
  buf[5] = 1
  return buf
}

function makeMachO(): Uint8Array {
  const buf = new Uint8Array(0x100)
  const magic = 0xFEEDFACE
  buf[0] = magic & 0xFF
  buf[1] = (magic >> 8) & 0xFF
  buf[2] = (magic >> 16) & 0xFF
  buf[3] = (magic >> 24) & 0xFF
  return buf
}

function makeWASM(): Uint8Array {
  const buf = new Uint8Array(0x100)
  buf[0] = 0x00; buf[1] = 0x61; buf[2] = 0x73; buf[3] = 0x6D
  buf[4] = 0x01; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00
  return buf
}

describe('detectFormat', () => {
  it('detects PE32', () => {
    const result = detectFormat(makePE(false))
    expect(result.format).toBe('PE')
    expect(result.endianness).toBe('little')
  })

  it('detects PE32+', () => {
    const result = detectFormat(makePE(true))
    expect(result.format).toBe('PE')
  })

  it('detects ELF32', () => {
    const result = detectFormat(makeELF(false))
    expect(result.format).toBe('ELF')
  })

  it('detects ELF64', () => {
    const result = detectFormat(makeELF(true))
    expect(result.format).toBe('ELF')
  })

  it('detects Mach-O', () => {
    const result = detectFormat(makeMachO())
    expect(result.format).toBe('Mach-O')
  })

  it('detects WASM', () => {
    const result = detectFormat(makeWASM())
    expect(result.format).toBe('WASM')
  })

  it('returns Unknown for empty buffer', () => {
    const result = detectFormat(new Uint8Array(0))
    expect(result.format).toBe('Unknown')
  })

  it('returns Unknown for garbage data', () => {
    const result = detectFormat(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF]))
    expect(result.format).toBe('Unknown')
  })
})

describe('detectArchitecture', () => {
  it('detects x86 from PE', () => {
    const pe = makePE(false)
    expect(detectArchitecture(pe, 'PE')).toBe('x86')
  })

  it('detects x64 from PE', () => {
    const pe = makePE(true)
    expect(detectArchitecture(pe, 'PE')).toBe('x64')
  })
})

describe('detectOS', () => {
  it('returns Windows for PE', () => {
    expect(detectOS('PE')).toBe('Windows')
  })

  it('returns Linux for ELF', () => {
    expect(detectOS('ELF')).toBe('Linux')
  })

  it('returns macOS for Mach-O', () => {
    expect(detectOS('Mach-O')).toBe('macOS')
  })

  it('returns Unknown for WASM', () => {
    expect(detectOS('WASM')).toBe('Unknown')
  })
})
