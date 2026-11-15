import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { hasSection, hasText } from './evidence.js'

interface PackerSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const MIN_CONFIDENCE = 60

/**
 * Named packers report only on a signature that does not occur in ordinary
 * compiler output. Entropy and import counts never identify a packer on their own:
 * "MPRESS" is a substring of "COMPRESSION", and high-entropy .rodata is normal.
 */
const signatures: PackerSignature[] = [
  {
    name: 'UPX',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasSection(ctx, n => n === 'UPX0' || n === 'UPX1' || n === 'UPX2')) {
        score += 80; evidence.push('UPX section names')
      }
      if (hasText(ctx, 'UPX!') || hasText(ctx, '$Id: UPX')) {
        score += 55; evidence.push('UPX magic')
      }
      return { confidence: Math.min(score, 99), evidence }
    },
  },
  {
    name: 'Themida',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'Themida') || hasText(ctx, '.themida')) {
        score += 70; evidence.push('Themida marker')
      }
      if (hasSection(ctx, n => n === '.themida' || n === '.scylla')) {
        score += 40; evidence.push('Themida section')
      }
      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'VMProtect',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'VMProtect')) {
        score += 70; evidence.push('VMProtect marker')
      }
      if (hasSection(ctx, n => n === '.vmp0' || n === '.vmp1' || n === '.vmp')) {
        score += 45; evidence.push('VMProtect section')
      }
      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'MPRESS',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      // "MPRESS1"/"MPRESS2" are the on-disk markers. Bare "MPRESS" matches COMPRESSION.
      if (hasText(ctx, 'MPRESS1') || hasText(ctx, 'MPRESS2')) {
        score += 75; evidence.push('MPRESS marker')
      }
      if (hasSection(ctx, n => /^\.mpress/i.test(n) || n === '.mprs')) {
        score += 40; evidence.push('MPRESS section')
      }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'ASPack',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'ASPack')) {
        score += 70; evidence.push('ASPack marker')
      }
      if (hasSection(ctx, n => n.toLowerCase() === '.aspack')) {
        score += 40; evidence.push('ASPack section')
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Custom Packer',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasSection(ctx, n => /^\.(packed|enigma1|petite|nsp[01]|upack)$/i.test(n))) {
        score += 70; evidence.push('Packer section name')
      }
      const modules = new Set((ctx.imports ?? []).map(i => i.module).filter(Boolean))
      const exec = (ctx.sections ?? []).filter(s =>
        /EXEC|EXECUTE/.test(s.permissions) && !/NOBITS/.test(s.permissions) && s.size > 8192 && s.entropy > 7.2,
      )
      // Packed PE stubs typically import only LoadLibrary/GetProcAddress. Static ELF does not.
      if (ctx.format === 'PE' && modules.size > 0 && modules.size <= 2 && exec.length > 0) {
        score += 25; evidence.push('PE with a tiny import set and high-entropy code')
      }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
]

export function detectPacker(ctx: PluginContext): DetectedItem | null {
  let best: DetectedItem | null = null
  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence < MIN_CONFIDENCE || result.evidence.length === 0) continue
    if (!best || result.confidence > best.confidence) {
      best = { name: sig.name, confidence: result.confidence, evidence: result.evidence }
    }
  }
  return best
}

export function detectObfuscation(ctx: PluginContext): DetectedItem | null {
  const packed = detectPacker(ctx)
  if (!packed) return null
  return { name: `${packed.name} (packed/obfuscated)`, confidence: packed.confidence, evidence: packed.evidence }
}
