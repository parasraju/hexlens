import { describe, it, expect } from 'vitest'
import type { BinaryReport, BinaryMetrics } from '../types/index.js'
import { toJSON } from '../reporters/json.js'
import { toMarkdown } from '../reporters/markdown.js'
import { toYAML } from '../reporters/yaml.js'
import { toCSV } from '../reporters/csv.js'
import { toSARIF } from '../reporters/sarif.js'

const minReport: BinaryReport = {
  file: { name: 'test.exe', size: 1024, sha256: 'abc', sha1: 'def', md5: 'ghi' },
  format: 'PE',
  architecture: 'x64',
  operatingSystem: 'Windows',
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
    aslr: true, dep: true, cfg: false, nx: true, pie: false,
    relro: false, stackCanaries: true, safeSEH: false,
    signed: false, certificateValid: null, timestampAnomaly: false, overlay: false,
  },
  sections: [],
  graphs: { callGraph: { nodes: [], edges: [] }, importGraph: { nodes: [], edges: [] }, dependencyGraph: { nodes: [], edges: [] }, sectionGraph: { nodes: [], edges: [] } },
  metrics: { functionCount: 0, averageFunctionSize: 0, complexityScore: 0, sectionEntropy: 0, symbolDensity: 0, instructionDensity: 0, optimizationEstimate: 'Unknown' } as BinaryMetrics,
  similarBinaries: [],
  entryPoint: 0,
  timestamp: 0,
  metadata: {},
}

describe('reporters', () => {
  it('toJSON produces valid JSON', () => {
    const json = toJSON(minReport)
    const parsed = JSON.parse(json)
    expect(parsed.format).toBe('PE')
    expect(parsed.file.name).toBe('test.exe')
  })

  it('toJSON pretty prints', () => {
    const json = toJSON(minReport, true)
    const lines = json.split('\n')
    expect(lines.length).toBeGreaterThan(1)
  })

  it('toMarkdown produces expected sections', () => {
    const md = toMarkdown(minReport)
    expect(md).toContain('# HexLens Report:')
    expect(md).toContain('test.exe')
    expect(md).toContain('PE')
    expect(md).toContain('x64')
    expect(md).toContain('Windows')
  })

  it('toYAML produces valid YAML', () => {
    const yaml = toYAML(minReport)
    expect(yaml).toContain('format: "PE"')
    expect(yaml).toContain('architecture: "x64"')
    expect(yaml).toContain('endianness: "little"')
  })

  it('toCSV produces CSV with header', () => {
    const csv = toCSV(minReport)
    expect(csv).toContain('Section')
    expect(csv).toContain('Property')
    expect(csv).toContain('Value')
    expect(csv).toContain('test.exe')
  })

  it('toSARIF produces valid SARIF JSON', () => {
    const sarif = toSARIF(minReport)
    const parsed = JSON.parse(sarif)
    expect(parsed.$schema).toBeDefined()
    expect(parsed.version).toBe('2.1.0')
    expect(parsed.runs).toHaveLength(1)
    expect(parsed.runs[0].tool.driver.name).toBe('HexLens')
  })

  it('toSARIF includes artifacts', () => {
    const sarif = toSARIF(minReport)
    const parsed = JSON.parse(sarif)
    expect(parsed.runs[0].artifacts).toBeDefined()
    expect(parsed.runs[0].artifacts[0].location.uri).toBe('test.exe')
  })

  it('toSARIF reports packer findings', () => {
    const report = { ...minReport, packer: { name: 'UPX', confidence: 90, evidence: ['UPX signature'] } }
    const sarif = toSARIF(report)
    const parsed = JSON.parse(sarif)
    expect(parsed.runs[0].results).toHaveLength(1)
    expect(parsed.runs[0].results[0].ruleId).toBe('HL0001')
  })
})
