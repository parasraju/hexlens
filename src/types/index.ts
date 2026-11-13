export type BinaryFormat = 'PE' | 'ELF' | 'Mach-O' | 'WASM' | 'DEX' | '.NET' | 'Unknown'
export type Architecture = 'x86' | 'x64' | 'ARM' | 'ARM64' | 'MIPS' | 'RISC-V' | 'PowerPC' | 'SPARC' | 'm68k' | 'Unknown'
export type OperatingSystem = 'Windows' | 'Linux' | 'macOS' | 'Android' | 'iOS' | 'Unknown'
export type Endianness = 'little' | 'big'

export interface FileInfo {
  name: string
  size: number
  sha256: string
  md5: string
  sha1: string
}

export interface SectionInfo {
  name: string
  rva: number
  fileOffset: number
  size: number
  entropy: number
  permissions: string
  alignment: number
}

export interface ImportInfo {
  module: string
  name: string
  address?: number
}

export interface ExportInfo {
  name: string
  address: number
  ordinal?: number
}

export interface DetectedItem {
  name: string
  confidence: number
  evidence: string[]
}

export interface StringInfo {
  value: string
  type: 'ASCII' | 'UTF-8' | 'UTF-16' | 'URL' | 'Domain' | 'IPv4' | 'FilePath' | 'RegistryPath' | 'UserAgent' | 'Base64'
  offset: number
}

export interface ResourceInfo {
  name: string
  type: string
  size: number
  offset: number
}

export interface CapabilityInfo {
  name: string
  category: string
  confidence: number
  evidence: string[]
}

export interface SecurityInfo {
  aslr: boolean
  dep: boolean
  cfg: boolean
  nx: boolean
  pie: boolean
  relro: boolean
  stackCanaries: boolean
  safeSEH: boolean
  signed: boolean
  certificateValid: boolean | null
  timestampAnomaly: boolean
  overlay: boolean
}

export interface BinaryMetrics {
  functionCount: number
  averageFunctionSize: number
  sectionEntropy: number
  symbolDensity: number
  instructionDensity: number
  complexityScore: number
  optimizationEstimate: string
}

export interface GraphData {
  nodes: { id: string; label: string; group: string }[]
  edges: { source: string; target: string; type: string }[]
}

export interface AnalysisGraphs {
  callGraph?: GraphData
  importGraph?: GraphData
  dependencyGraph?: GraphData
  sectionGraph?: GraphData
}

export interface SimilarityResult {
  algorithm: string
  score: number
  matchedBinary?: string
}

export interface YaraStringMatch {
  identifier: string
  offset: number
  length: number
}

export interface YaraMatch {
  /** File the rule matched, as it appears in the report (relative path in batch scans). */
  file: string
  /** YARA rule name. */
  rule: string
  /** Rule metadata, stringified by the libyara wrapper. */
  meta: Record<string, string>
  /** String identifiers and offsets that caused the rule to match. */
  strings: YaraStringMatch[]
}

export interface BinaryReport {
  file: FileInfo
  format: BinaryFormat
  architecture: Architecture
  operatingSystem: OperatingSystem
  endianness: Endianness
  compiler: DetectedItem | null
  language: DetectedItem | null
  optimization: string | null
  stripped: boolean
  packer: DetectedItem | null
  obfuscation: DetectedItem | null
  domains: string[]
  libraries: DetectedItem[]
  imports: ImportInfo[]
  exports: ExportInfo[]
  strings: StringInfo[]
  resources: ResourceInfo[]
  capabilities: CapabilityInfo[]
  graphs: AnalysisGraphs
  security: SecurityInfo | null
  metadata: Record<string, unknown>
  sections: SectionInfo[]
  metrics: BinaryMetrics | null
  similarBinaries: SimilarityResult[]
  entryPoint: number
  timestamp: number
}

export interface DiffFileSide {
  path: string
  name: string
  size: number
  sha256: string
  sha1: string
  md5: string
}

export interface DiffByteChange {
  offset: number
  /** Hex byte in file A, or null when the file ends before this offset. */
  a: string | null
  /** Hex byte in file B, or null when the file ends before this offset. */
  b: string | null
  /** Hex bytes around the offset. The byte at the offset is wrapped in brackets. */
  contextA: string
  contextB: string
}

export interface DiffBytes {
  sizeA: number
  sizeB: number
  identical: boolean
  differingBytes: number
  /** Share of matching bytes across the longer file, 0–100, two decimal places. */
  similarity: number
  /** The first differing offsets, at most 10. */
  differences: DiffByteChange[]
}

export interface DiffNameSize {
  name: string
  size: number
}

export interface DiffSectionChange {
  name: string
  sizeA: number
  sizeB: number
}

export interface DiffDetectionSide {
  name: string
  confidence: number
}

export interface DiffDetection {
  changed: boolean
  /** Null when this file's report has no detection. */
  a: DiffDetectionSide | null
  b: DiffDetectionSide | null
}

export interface DiffImphash {
  /** True only when both reports include an imphash and the values are equal. */
  same: boolean
  /** Null when file A has no imphash. */
  a: string | null
  /** Null when file B has no imphash. */
  b: string | null
  missingA: boolean
  missingB: boolean
}

export interface DiffValueChange<T> {
  changed: boolean
  a: T
  b: T
}

export interface DiffReportComparison {
  imphash: DiffImphash
  imports: { added: string[]; removed: string[] }
  exports: { added: string[]; removed: string[] }
  sections: { added: DiffNameSize[]; removed: DiffNameSize[]; changed: DiffSectionChange[] }
  strings: { added: string[]; removed: string[]; addedTotal: number; removedTotal: number }
  compiler: DiffDetection
  packer: DiffDetection
  language: DiffDetection
  entryPoint: DiffValueChange<number>
  format: DiffValueChange<BinaryFormat>
  architecture: DiffValueChange<Architecture>
}

export interface BinaryDiff {
  /** True when the file bytes are identical. */
  identical: boolean
  fileA: DiffFileSide
  fileB: DiffFileSide
  bytes: DiffBytes
  report: DiffReportComparison
}
