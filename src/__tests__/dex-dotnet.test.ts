import { describe, it, expect } from 'vitest'
import { detectFormat, detectOS } from '../parsers/format-detector.js'
import { parseDEX } from '../parsers/dex.js'
import { parseDotNet } from '../parsers/dotnet.js'
import { parsePE } from '../parsers/pe.js'
import { computeImphash } from '../utils/hash.js'
import { buildDEX, buildDotNet } from './fixtures.js'



describe('DEX parser', () => {
  it('detects DEX format', () => {
    expect(detectFormat(buildDEX()).format).toBe('DEX')
    expect(detectOS('DEX')).toBe('Android')
  })

  it('parses strings, classes and imports', () => {
    const dex = parseDEX(buildDEX())
    expect(dex).not.toBeNull()
    expect(dex!.version).toBe('035')
    expect(dex!.strings).toContain('Lcom/example/Foo;')
    expect(dex!.strings).toContain('Ljava/lang/Object;')
    expect(dex!.classes).toEqual(['Lcom/example/Foo;'])
    expect(dex!.imports.some(i => i.name === 'bar' && i.module === 'Ljava/lang/Object;')).toBe(true)
    expect(dex!.exports.some(e => e.name === 'Lcom/example/Foo;')).toBe(true)
    expect(dex!.sections.length).toBeGreaterThan(0)
  })

  it('rejects non-DEX data', () => {
    expect(parseDEX(new Uint8Array(16))).toBeNull()
  })
})

describe('.NET parser', () => {
  it('detects .NET format from PE with COM descriptor', () => {
    expect(detectFormat(buildDotNet()).format).toBe('.NET')
    expect(detectOS('.NET')).toBe('Windows')
  })

  it('parses assembly metadata, type refs and method defs', () => {
    const dotnet = buildDotNet()
    const pe = parsePE(dotnet)
    expect(pe).not.toBeNull()

    const dn = parseDotNet(dotnet, pe!.sections)
    expect(dn).not.toBeNull()
    expect(dn!.runtimeVersion).toBe('v4.0.30319')
    expect(dn!.moduleName).toBe('MyApp')
    expect(dn!.assemblyName).toBe('MyApp')
    expect(dn!.typeRefs).toContain('System.Object')
    expect(dn!.typeRefs).toContain('Foo.Bar')
    expect(dn!.methodDefs).toContain('Program')
    expect(dn!.methodDefs).toContain('Foo')
    expect(dn!.assemblyVersion).toBe('4.0.0.0')
    expect(dn!.imports.length).toBe(2)
    expect(dn!.exports.length).toBe(2)
  })
})

describe('imphash', () => {
  it('computes a deterministic import hash', () => {
    const a = [{ module: 'kernel32.dll', name: 'CreateFileW' }, { module: 'user32.dll', name: 'MessageBoxA' }]
    const b = [{ module: 'user32.dll', name: 'MessageBoxA' }, { module: 'kernel32.dll', name: 'CreateFileW' }]
    expect(computeImphash(a)).toBe(computeImphash(b))
    expect(computeImphash(a)).toMatch(/^[a-f0-9]{32}$/)
  })

  it('returns empty for no imports', () => {
    expect(computeImphash([])).toBe('')
  })
})