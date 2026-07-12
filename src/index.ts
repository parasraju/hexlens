import { readFile } from 'node:fs/promises'
import { type BinaryReport, type BinaryFormat, type Architecture, type OperatingSystem, type Endianness, type SectionInfo, type ImportInfo, type ExportInfo, type StringInfo, type DetectedItem, type CapabilityInfo, type SecurityInfo, type BinaryMetrics, type AnalysisGraphs, type SimilarityResult } from './types/index.js'
import type { PluginContext } from './types/plugin.js'
import { detectFormat, detectArchitecture, detectOS, parsePE, parseELF, parseMachO, parseWASM } from './parsers/index.js'
import { detectCompiler, detectLanguage, detectLibraries, detectCapabilities, detectSecurity, detectPacker, detectObfuscation, extractStrings } from './detectors/index.js'
import { calculateMetrics, analyzeSymbols, discoverFunctions } from './analysis/index.js'
import { buildAllGraphs, graphToGraphviz, graphToMermaid, compareBinaries } from './engine/index.js'
import { createPluginManager } from './engine/plugin.js'
import { hashes } from './utils/hash.js'

export type { BinaryReport, BinaryFormat, Architecture, OperatingSystem, Endianness, SectionInfo, ImportInfo, ExportInfo, StringInfo, DetectedItem, CapabilityInfo, SecurityInfo, BinaryMetrics, AnalysisGraphs, SimilarityResult }
export type { Plugin, PluginContext, PluginManager } from './types/plugin.js'

export { detectFormat, detectArchitecture, detectOS, parsePE, parseELF, parseMachO, parseWASM }
export { detectCompiler, detectLanguage, detectLibraries, detectCapabilities, detectSecurity, detectPacker, detectObfuscation, extractStrings }
export { calculateMetrics, analyzeSymbols, discoverFunctions }
export { buildAllGraphs, graphToGraphviz, graphToMermaid, compareBinaries, createPluginManager }
export { toJSON, toMarkdown, toTerminal, toHTML, toSARIF, toYAML, toCSV } from './reporters/index.js'

export async function analyze(path: string): Promise<BinaryReport> {
  const raw = await readFile(path)
  const data = raw

  const { format, endianness } = detectFormat(data)
  const architecture = detectArchitecture(data, format)
  const operatingSystem = detectOS(format)

  const fileInfo = {
    name: path.split(/[/\\]/).pop() || path,
    size: raw.length,
    ...hashes(data),
  }

  let sections: SectionInfo[] = []
  let imports: ImportInfo[] = []
  let exports: ExportInfo[] = []
  let entryPoint = 0
  let timestamp = 0
  let metadata: Record<string, unknown> = {}

  if (format === 'PE') {
    const pe = parsePE(data)
    if (pe) {
      sections = pe.sections
      imports = pe.imports
      exports = pe.exports as ExportInfo[]
      entryPoint = pe.entryPoint
      timestamp = pe.timestamp
      metadata.peData = pe
    }
  } else if (format === 'ELF') {
    const elf = parseELF(data)
    if (elf) {
      sections = elf.sections
      imports = elf.imports
      exports = elf.exports.map(e => ({ name: e.name, address: e.address }))
      metadata.elfData = elf
    }
  } else if (format === 'Mach-O') {
    const macho = parseMachO(data)
    if (macho) {
      sections = macho.sections
      imports = macho.imports
      exports = macho.exports
      entryPoint = macho.entryPoint
      metadata.machoData = macho
    }
  } else if (format === 'WASM') {
    const wasm = parseWASM(data)
    if (wasm) {
      sections = wasm.sections
      imports = wasm.imports
      exports = wasm.exports
      metadata.wasmData = wasm
    }
  }

  const strings = extractStrings(data)

  const pluginCtx: PluginContext = {
    raw: data,
    format,
    architecture,
    sections,
    strings,
    metadata,
    imports,
    exports,
    domains: strings.filter(s => s.type === 'Domain').map(s => s.value),
    urls: strings.filter(s => s.type === 'URL').map(s => s.value),
  }

  const compiler = detectCompiler(pluginCtx)
  const language = detectLanguage(pluginCtx)
  const libraries = detectLibraries({ ...pluginCtx, libraries: [] })

  const packer = detectPacker(pluginCtx)
  const obfuscation = detectObfuscation(pluginCtx)
  const security = detectSecurity(pluginCtx)
  const capabilities = detectCapabilities({ ...pluginCtx, libraries })

  const metrics = calculateMetrics(sections, data, strings.length, imports.length)

  const optimization = metrics.optimizationEstimate

  const stripped = sections.some(s => s.name === '.debug' || s.name === '__debug_info')
    ? false
    : (imports.length > 0 || exports.length > 0 ? false : true)

  const graphs = buildAllGraphs(imports, sections, libraries)

  const functions = discoverFunctions(entryPoint, imports, exports, strings)
  const domains = strings.filter(s => s.type === 'Domain').map(s => s.value)

  const report: BinaryReport = {
    file: fileInfo,
    format,
    architecture,
    operatingSystem,
    endianness,
    compiler,
    language,
    optimization,
    stripped,
    packer: packer || null,
    obfuscation: obfuscation && obfuscation.confidence > 30 ? obfuscation : null,
    domains,
    libraries,
    imports,
    exports,
    strings: strings.slice(0, 5000),
    resources: [],
    capabilities,
    graphs,
    security,
    metadata: {
      functions: functions.slice(0, 100),
      ...metadata,
    },
    sections,
    metrics,
    similarBinaries: [],
    entryPoint,
    timestamp,
  }

  return report
}


