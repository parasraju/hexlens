import { describe, it, expect } from 'vitest'
import { detectFormat, detectArchitecture, detectOS } from '../parsers/format-detector.js'
import type { SecurityInfo, BinaryMetrics } from '../types/index.js'
import { parsePE } from '../parsers/pe.js'
import { toJSON } from '../reporters/json.js'

describe('integration', () => {
  it('analyzes a minimal PE and produces JSON output', () => {
    const buf = new Uint8Array(0x1000)
    buf[0] = 0x4D; buf[1] = 0x5A
    const peOff = 0x80
    buf[0x3C] = peOff
    buf[peOff] = 0x50; buf[peOff + 1] = 0x45; buf[peOff + 2] = 0x00; buf[peOff + 3] = 0x00
    buf[peOff + 4] = 0x4C; buf[peOff + 5] = 0x01
    buf[peOff + 6] = 0x03; buf[peOff + 7] = 0x00

    const fmt = detectFormat(buf)
    expect(fmt.format).toBe('PE')

    const arch = detectArchitecture(buf, 'PE')
    expect(arch).toBe('x86')

    const os = detectOS('PE')
    expect(os).toBe('Windows')

    const pe = parsePE(buf)
    expect(pe).not.toBeNull()
    expect(pe!.sections).toBeDefined()
    expect(pe!.imports).toEqual([])
    expect(pe!.exports).toEqual([])
  })

  it('handles empty data gracefully', () => {
    const empty = new Uint8Array(0)
    expect(parsePE(empty)).toBeNull()
  })

  it('handles non-PE data gracefully', () => {
    const garbage = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF])
    expect(parsePE(garbage)).toBeNull()
  })

  it('JSON reporter handles full report without crashing', () => {
    const json = toJSON({
      file: { name: 'test.bin', size: 0, sha256: '', sha1: '', md5: '' },
      format: 'Unknown',
      architecture: 'Unknown',
      operatingSystem: 'Unknown',
      endianness: 'little',
      compiler: null,
      language: null,
      optimization: null,
      stripped: false,
      packer: null,
      obfuscation: null,
      domains: [],
      libraries: [],
      imports: [],
      exports: [],
      strings: [],
      resources: [],
      capabilities: [],
      security: {
        aslr: false, dep: false, cfg: false, nx: false, pie: false,
        relro: false, stackCanaries: false, safeSEH: false,
        signed: false, certificateValid: false, timestampAnomaly: false, overlay: false,
      } as SecurityInfo,
      sections: [],
      graphs: {
        callGraph: { nodes: [], edges: [] },
        importGraph: { nodes: [], edges: [] },
        dependencyGraph: { nodes: [], edges: [] },
        sectionGraph: { nodes: [], edges: [] },
      },
      metrics: {
        functionCount: 0, averageFunctionSize: 0, complexityScore: 0,
        sectionEntropy: 0, symbolDensity: 0, instructionDensity: 0,
        optimizationEstimate: 'Unknown',
      } as BinaryMetrics,
      similarBinaries: [],
      entryPoint: 0,
      timestamp: 0,
      metadata: {},
    })
    const parsed = JSON.parse(json)
    expect(parsed.format).toBe('Unknown')
  })
})
