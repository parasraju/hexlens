import { readFile } from 'node:fs/promises'
import { type BinaryReport, type SectionInfo, type ImportInfo, type ExportInfo } from './types/index.js'
import type { PluginContext } from './types/plugin.js'
import { detectFormat, detectArchitecture, detectOS, parsePE, parseELF, parseMachO, parseWASM, parseDEX, parseDotNet } from './parsers/index.js'
import { detectCompiler, detectLanguage, detectLibraries, detectCapabilities, detectSecurity, detectPacker, detectObfuscation, extractStrings } from './detectors/index.js'
import { calculateMetrics, discoverFunctions } from './analysis/index.js'
import { buildAllGraphs } from './engine/index.js'
import { hashes, computeImphash } from './utils/hash.js'

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
  let resources: { name: string; type: string; size: number; offset: number }[] = []
  let entryPoint = 0
  let timestamp = 0
  let metadata: Record<string, unknown> = {}
  let headerParsed = false

  if (format === 'PE') {
    const pe = parsePE(data)
    if (pe) {
      headerParsed = true
      sections = pe.sections
      imports = pe.imports
      exports = pe.exports as ExportInfo[]
      resources = pe.resources
      entryPoint = pe.entryPoint
      timestamp = pe.timestamp
      metadata.peData = pe
    }
  } else if (format === '.NET') {
    const pe = parsePE(data)
    const dotnet = pe ? parseDotNet(data, pe.sections) : null
    if (pe) {
      headerParsed = true
      sections = pe.sections
      entryPoint = pe.entryPoint
      timestamp = pe.timestamp
      resources = pe.resources
      metadata.peData = pe
      imports = pe.imports
    }
    if (dotnet) {
      imports = [...imports, ...dotnet.imports]
      exports = dotnet.exports
      metadata.dotNetData = dotnet
      metadata.assembly = {
        name: dotnet.assemblyName,
        version: dotnet.assemblyVersion,
        module: dotnet.moduleName,
        runtime: dotnet.runtimeVersion,
      }
    }
  } else if (format === 'ELF') {
    const elf = parseELF(data)
    if (elf) {
      headerParsed = true
      sections = elf.sections
      imports = elf.imports
      exports = elf.exports.map(e => ({ name: e.name, address: e.address }))
      entryPoint = elf.entryPoint
      metadata.elfData = elf
    }
  } else if (format === 'Mach-O') {
    const macho = parseMachO(data)
    if (macho) {
      headerParsed = true
      sections = macho.sections
      imports = macho.imports
      exports = macho.exports
      entryPoint = macho.entryPoint
      metadata.machoData = macho
    }
  } else if (format === 'WASM') {
    const wasm = parseWASM(data)
    if (wasm) {
      headerParsed = true
      sections = wasm.sections
      imports = wasm.imports
      exports = wasm.exports
      metadata.wasmData = wasm
    }
  } else if (format === 'DEX') {
    const dex = parseDEX(data)
    if (dex) {
      headerParsed = true
      sections = dex.sections
      imports = dex.imports
      exports = dex.exports
      metadata.dexData = dex
      metadata.dex = {
        version: dex.version,
        classes: dex.classCount,
        methods: dex.methodCount,
        strings: dex.stringCount,
      }
    }
  }

  if (format === 'Unknown') {
    return unrecognizedReport(fileInfo, endianness)
  }

  if (!headerParsed) metadata.truncated = true

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
  if (compiler) pluginCtx.metadata.detectedCompiler = compiler.name
  const language = detectLanguage(pluginCtx)
  const libraries = detectLibraries({ ...pluginCtx, libraries: [] })

  const packer = detectPacker(pluginCtx)
  const obfuscation = detectObfuscation(pluginCtx)
  const security = headerParsed ? detectSecurity(pluginCtx) : null
  const capabilities = detectCapabilities({ ...pluginCtx, libraries })

  const functionSizes = functionSizesFrom(metadata)
  const metrics = calculateMetrics(sections, data, strings.length, imports.length, functionSizes)

  const optimization = metrics.optimizationEstimate

  const stripped = inferStripped(format, metadata)

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
    resources,
    capabilities,
    graphs,
    security,
    metadata: {
      functions: functions.slice(0, 100),
      imphash: computeImphash(imports),
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

const UNRECOGNIZED = 'Not a recognized binary. This file does not match PE, ELF, Mach-O, WASM, DEX, or .NET.'

function unrecognizedReport(file: BinaryReport['file'], endianness: BinaryReport['endianness']): BinaryReport {
  return {
    file,
    format: 'Unknown',
    architecture: 'Unknown',
    operatingSystem: 'Unknown',
    endianness,
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
    graphs: {},
    security: null,
    metadata: { recognized: false, note: UNRECOGNIZED },
    sections: [],
    metrics: null,
    similarBinaries: [],
    entryPoint: 0,
    timestamp: 0,
  }
}

function inferStripped(format: BinaryReport['format'], metadata: Record<string, unknown>): boolean {
  if (format === 'ELF') {
    const elf = metadata.elfData as { hasSymtab?: boolean } | undefined
    return elf?.hasSymtab === false
  }
  if (format === 'PE' || format === '.NET') {
    const pe = metadata.peData as { numberOfSymbols?: number } | undefined
    return (pe?.numberOfSymbols ?? 0) === 0
  }
  if (format === 'Mach-O') {
    const macho = metadata.machoData as { symbolCount?: number } | undefined
    return (macho?.symbolCount ?? 0) === 0
  }
  return false
}

function functionSizesFrom(metadata: Record<string, unknown>): number[] {
  const elf = metadata.elfData as { symbols?: { type: string; size: number }[] } | undefined
  if (!elf?.symbols) return []
  return elf.symbols.filter(s => s.type === 'FUNC' && s.size > 0).map(s => s.size)
}
