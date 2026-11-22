import { describe, it, expect } from 'vitest'
import type { BinaryReport, BinaryMetrics } from '../types/index.js'
import { toJSON } from '../reporters/json.js'
import { toMarkdown } from '../reporters/markdown.js'
import { toYAML } from '../reporters/yaml.js'
import { toCSV } from '../reporters/csv.js'
import { toSARIF } from '../reporters/sarif.js'
import { toIOC, toSTIX } from '../reporters/ioc.js'
import type { YaraMatch } from '../types/index.js'

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

const yara: YaraMatch[] = [
  { file: 'test.exe', rule: 'RuleA', meta: { author: 'hexlens' }, strings: [] },
  { file: 'test.exe', rule: 'RuleA', meta: {}, strings: [] },
  { file: 'test.exe', rule: 'RuleB', meta: {}, strings: [] },
]

describe('ioc export', () => {
  const report: typeof minReport = {
    ...minReport,
    metadata: { imphash: 'deadbeef' },
    imports: [
      { module: 'KERNEL32.dll', name: 'CreateFileW', address: 0x1000 },
      { module: 'USER32.dll', name: 'CreateFileW' },
      { module: 'KERNEL32.dll', name: '' },
    ],
    domains: ['example.com'],
    strings: [
      { value: 'https://example.com/a', type: 'URL', offset: 0 },
      { value: 'prefix https://example.com/a suffix', type: 'URL', offset: 10 },
      { value: '203.0.113.10', type: 'IPv4', offset: 20 },
      { value: 'addr 203.0.113.10 tail', type: 'IPv4', offset: 30 },
      { value: '999.999.999.999', type: 'IPv4', offset: 40 },
      { value: 'example.com', type: 'Domain', offset: 50 },
      { value: 'HKLM\\SOFTWARE\\HexLens', type: 'RegistryPath', offset: 60 },
    ],
  }

  it('lists each real indicator once and leaves other string types out', () => {
    const parsed = JSON.parse(toIOC(report, yara))
    expect(Object.keys(parsed)).toEqual([
      'sha256', 'md5', 'sha1', 'imphash', 'urls', 'ips', 'imports', 'yara_matches',
    ])
    expect(parsed).toEqual({
      sha256: 'abc',
      md5: 'ghi',
      sha1: 'def',
      imphash: 'deadbeef',
      urls: ['https://example.com/a'],
      ips: ['203.0.113.10'],
      imports: ['CreateFileW'],
      yara_matches: ['RuleA', 'RuleB'],
    })
  })

  it('uses null and empty arrays when those indicators are absent', () => {
    const parsed = JSON.parse(toIOC({ ...minReport, metadata: { imphash: '' } }))
    expect(parsed.imphash).toBeNull()
    expect(parsed.urls).toEqual([])
    expect(parsed.ips).toEqual([])
    expect(parsed.imports).toEqual([])
    expect(parsed.yara_matches).toEqual([])
  })

  it('emits one STIX 2.1 bundle whose objects come from those fields', () => {
    const created = new Date('2026-11-22T15:30:00.000Z')
    const text = toSTIX(report, yara, true, created)
    expect(toSTIX(report, yara, true, created)).toBe(text)
    const parsed = JSON.parse(text)
    expect(parsed.type).toBe('bundle')
    expect(parsed.spec_version).toBe('2.1')
    expect(parsed.id).toMatch(/^bundle--[0-9a-f-]{36}$/)

    const files = parsed.objects.filter((object: { type: string }) => object.type === 'file')
    const urls = parsed.objects.filter((object: { type: string }) => object.type === 'url')
    const ips = parsed.objects.filter((object: { type: string }) => object.type === 'ipv4-addr')
    const indicators = parsed.objects.filter((object: { type: string }) => object.type === 'indicator')

    expect(files).toHaveLength(1)
    expect(files[0].spec_version).toBe('2.1')
    expect(files[0].name).toBe('test.exe')
    expect(files[0].size).toBe(1024)
    expect(files[0].hashes).toEqual({ 'SHA-256': 'abc', MD5: 'ghi', 'SHA-1': 'def' })
    expect(files[0].extensions).toBeUndefined()

    expect(urls.map((object: { value: string }) => object.value)).toEqual(['https://example.com/a'])
    expect(ips.map((object: { value: string }) => object.value)).toEqual(['203.0.113.10'])

    expect(indicators.map((object: { name: string }) => object.name)).toEqual([
      'test.exe',
      '203.0.113.10',
      'https://example.com/a',
      'CreateFileW',
      'RuleA',
      'RuleB',
    ])
    for (const object of indicators) {
      expect(object.spec_version).toBe('2.1')
      expect(object.pattern_type).toBe('stix')
      expect(object.pattern_version).toBe('2.1')
      expect(object.created).toBe('2026-11-22T15:30:00.000Z')
      expect(object.modified).toBe('2026-11-22T15:30:00.000Z')
      expect(object.valid_from).toBe('2026-11-22T15:30:00.000Z')
      expect(object.pattern).toContain("file:hashes.'SHA-256' = 'abc'")
      expect(object.id).toMatch(/^indicator--[0-9a-f-]{36}$/)
    }
    const urlIndicator = indicators.find((object: { name: string }) => object.name === 'https://example.com/a')
    expect(urlIndicator.pattern).toContain("[url:value = 'https://example.com/a']")
    const ipIndicator = indicators.find((object: { name: string }) => object.name === '203.0.113.10')
    expect(ipIndicator.pattern).toContain("[ipv4-addr:value = '203.0.113.10']")
    const fileIndicator = indicators.find((object: { name: string }) => object.name === 'test.exe')
    expect(fileIndicator.description).toBe('imphash deadbeef')
    expect(fileIndicator.pattern).toContain("file:hashes.MD5 = 'ghi'")
    expect(fileIndicator.pattern).toContain("file:hashes.'SHA-1' = 'def'")
    const blob = JSON.stringify(parsed)
    expect(blob).not.toContain('example.com"')
    expect(blob).not.toContain('HKLM')
    expect(blob).not.toContain('999.999.999.999')
    expect(blob).not.toContain('hexlens')
    expect(blob).not.toContain('KERNEL32')
  })
})
