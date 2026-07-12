import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

interface PackerSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[]; obfuscated: boolean }
}

const signatures: PackerSignature[] = [
  {
    name: 'UPX',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /UPX[!\d]/.test(s.value) || s.value === 'UPX!' || s.value.startsWith('UPX '))) {
        score += 40; evidence.push('UPX signature found')
      }
      if (ctx.sections?.some(s => s.name === 'UPX0' || s.name === 'UPX1' || s.name === 'UPX2')) {
        score += 35; evidence.push('UPX section names')
      }
      if (ctx.sections?.some(s => s.name === '.packed' || s.name === '.rsrc' && s.entropy > 7)) score += 10
      if (ctx.format === 'PE' && ctx.sections?.some(s => s.name === 'UPX0')) score += 5
      return { confidence: Math.min(score, 99), evidence, obfuscated: score > 20 }
    },
  },
  {
    name: 'Themida',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Themida') || s.value.includes('Oreans'))) {
        score += 35; evidence.push('Themida/Oreans strings')
      }
      if (ctx.sections?.some(s => s.name === '.themida' || s.name === '.scylla')) {
        score += 25; evidence.push('Themida sections')
      }
      if (ctx.sections?.some(s => s.entropy > 7.8)) score += 15
      return { confidence: Math.min(score, 95), evidence, obfuscated: true }
    },
  },
  {
    name: 'VMProtect',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('VMProtect') || s.value.includes('VMP'))) {
        score += 35; evidence.push('VMProtect strings')
      }
      if (ctx.sections?.some(s => s.name === '.vmp0' || s.name === '.vmp1' || s.name === '.vmp')) {
        score += 30; evidence.push('VMProtect sections')
      }
      return { confidence: Math.min(score, 95), evidence, obfuscated: true }
    },
  },
  {
    name: 'MPRESS',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('MPRESS') || s.value.includes('MPRESS1'))) {
        score += 35; evidence.push('MPRESS signature')
      }
      if (ctx.sections?.some(s => s.name === '.MPRESS' || s.name === '.mprs')) {
        score += 25; evidence.push('MPRESS sections')
      }
      if (ctx.sections?.some(s => s.entropy > 7.5)) score += 10
      return { confidence: Math.min(score, 92), evidence, obfuscated: true }
    },
  },
  {
    name: 'ASPack',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('ASPack') || s.value.includes('ASPack '))) {
        score += 35; evidence.push('ASPack signature')
      }
      if (ctx.sections?.some(s => s.name === '.aspack' || s.name === '.adata')) {
        score += 25; evidence.push('ASPack sections')
      }
      return { confidence: Math.min(score, 90), evidence, obfuscated: true }
    },
  },
  {
    name: 'Custom Packer',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      const highEntropySections = ctx.sections?.filter(s => s.entropy > 7.5) || []
      if (highEntropySections.length > 0) {
        score += 15; evidence.push(`${highEntropySections.length} high-entropy sections (>7.5)`)
      }

      if (ctx.sections?.some(s => s.entropy > 7.8 && s.size > 10000)) {
        score += 10; evidence.push('Very high entropy in large section')
      }

      const importCount = ctx.imports?.length || 0
      if (importCount < 5 && (ctx.format === 'PE' || ctx.format === 'ELF')) {
        score += 10; evidence.push('Suspiciously few imports')
      }

      if (ctx.security?.overlay) {
        score += 5; evidence.push('Executable overlay present')
      }

      return { confidence: Math.min(score, 60), evidence, obfuscated: score > 20 }
    },
  },
]

export function detectPacker(ctx: PluginContext): DetectedItem | null {
  let best: DetectedItem | null = null

  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence > 15 && (!best || result.confidence > best.confidence)) {
      const item: DetectedItem = { name: sig.name, confidence: result.confidence, evidence: result.evidence }
      if (!best || result.confidence > best.confidence) best = item
    }
  }

  return best
}

export function detectObfuscation(ctx: PluginContext): DetectedItem | null {
  const best = detectPacker(ctx)
  if (best && best.confidence > 30) {
    return { name: `${best.name} (packed/obfuscated)`, confidence: best.confidence, evidence: best.evidence }
  }

  const highEntropySections = ctx.sections?.filter(s => s.entropy > 7.5) || []
  if (highEntropySections.length > 1) {
    return {
      name: 'Obfuscated',
      confidence: Math.min(40 + highEntropySections.length * 10, 80),
      evidence: [`${highEntropySections.length} high-entropy sections`],
    }
  }

  return null
}
