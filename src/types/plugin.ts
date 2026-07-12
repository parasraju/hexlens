import type { SectionInfo, CapabilityInfo, DetectedItem, StringInfo, SecurityInfo, BinaryMetrics, ImportInfo } from './index.js'

export interface PluginContext {
  raw: Buffer | Uint8Array
  format: string
  architecture: string
  sections: SectionInfo[]
  strings: StringInfo[]
  metadata: Record<string, unknown>
  domains?: string[]
  urls?: string[]
  libraries?: DetectedItem[]
  imports?: ImportInfo[]
  exports?: { name: string; address: number }[]
  timestamp?: number
  security?: SecurityInfo | null
  metrics?: BinaryMetrics | null
}

export interface Plugin {
  name: string
  version: string
  description: string
  analyze(ctx: PluginContext): Promise<void> | void
}

export interface PluginManager {
  register(plugin: Plugin): void
  unregister(name: string): void
  getPlugins(): Plugin[]
  runAll(ctx: PluginContext): Promise<void>
}

export interface Detector<T> {
  name: string
  detect(ctx: PluginContext): Promise<T | null>
}

export type CompilerDetector = Detector<DetectedItem>
export type LanguageDetector = Detector<DetectedItem>
export type PackerDetector = Detector<DetectedItem>
export type LibraryDetector = Detector<DetectedItem[]>
export type CapabilityDetector = Detector<CapabilityInfo[]>
export type SecurityDetector = Detector<SecurityInfo>
export type StringDetector = Detector<StringInfo[]>
export type MetricsCalculator = Detector<BinaryMetrics>
