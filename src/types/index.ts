export type BinaryFormat = 'PE' | 'ELF' | 'Mach-O' | 'WASM' | 'Unknown'
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
