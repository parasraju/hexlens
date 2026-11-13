export type { BinaryReport, BinaryFormat, Architecture, OperatingSystem, Endianness, SectionInfo, ImportInfo, ExportInfo, StringInfo, DetectedItem, CapabilityInfo, SecurityInfo, BinaryMetrics, AnalysisGraphs, SimilarityResult, YaraMatch, YaraStringMatch, BinaryDiff, DiffBytes, DiffReportComparison, DiffFileSide, DiffByteChange } from './types/index.js'
export type { Plugin, PluginContext, PluginManager } from './types/plugin.js'

export { analyze } from './analyze.js'
export { detectFormat, detectArchitecture, detectOS, parsePE, parseELF, parseMachO, parseWASM, parseDEX, parseDotNet } from './parsers/index.js'
export { detectCompiler, detectLanguage, detectLibraries, detectCapabilities, detectSecurity, detectPacker, detectObfuscation, extractStrings } from './detectors/index.js'
export { calculateMetrics, analyzeSymbols, discoverFunctions } from './analysis/index.js'
export { buildAllGraphs, graphToGraphviz, graphToMermaid, compareBinaries, createPluginManager } from './engine/index.js'
export { computeImphash } from './utils/hash.js'

export { toJSON, toMarkdown, toTerminal, toHTML, toSARIF, toYAML, toCSV, toDiffJSON, toDiffTerminal } from './reporters/index.js'
export { diff, diffExitCode, diffOrExit } from './diff/index.js'
export { toScanTable, toScanJSON, toScanCSV, toScanMarkdown, toScanHTML, toScanSARIF, toScanYAML, formatScan } from './reporters/scan.js'

export { scan } from './scan/index.js'
export type { ScanOptions, ScanSummary, ScanFile, ScanFlag, ScanError, ScanRisk, ScanFlagSeverity } from './scan/index.js'

export { YaraScanner } from './yara/index.js'
