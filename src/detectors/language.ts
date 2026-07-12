import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

interface LanguageSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const signatures: LanguageSignature[] = [
  {
    name: 'C',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 5

      if (ctx.strings?.some(s => s.value.includes('main') || s.value.includes('argc') || s.value.includes('argv'))) {
        score += 10; evidence.push('C entry point pattern')
      }
      if (ctx.sections.some(s => s.name === '.text' || s.name === '.data' || s.name === '.bss')) {
        score += 10; evidence.push('Standard C sections')
      }
      if (ctx.strings?.some(s => /^(printf|scanf|malloc|free|strlen|memcpy)\b/.test(s.value))) {
        score += 15; evidence.push('C standard library functions')
      }

      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'C++',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.strings?.some(s => s.value.includes('__cxa_') || s.value.includes('__gxx_'))) {
        score += 20; evidence.push('C++ ABI symbols')
      }
      if (ctx.strings?.some(s => s.value.includes('vtable') || s.value.includes('VTT'))) {
        score += 15; evidence.push('C++ vtable references')
      }
      if (ctx.strings?.some(s => /std::/.test(s.value))) {
        score += 15; evidence.push('C++ standard library')
      }
      if (ctx.strings?.some(s => /::\w+\(/.test(s.value) && s.value.includes('('))) {
        score += 10; evidence.push('C++ mangled names')
      }
      if (ctx.raw) {
        const str = new TextDecoder().decode(ctx.raw.slice(0, Math.min(ctx.raw.length, 100000)))
        if (str.includes('__cxa_throw') || str.includes('__cxa_begin_catch')) {
          score += 15; evidence.push('C++ exception handling')
        }
      }

      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Rust',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.strings?.some(s => s.value.includes('rust_begin_unwind') || s.value.includes('core::panic'))) {
        score += 20; evidence.push('Rust panic mechanism')
      }
      if (ctx.strings?.some(s => /::[a-z_][a-z0-9_]*::h[0-9a-f]{16}/.test(s.value))) {
        score += 25; evidence.push('Rust hash-mangled symbols')
      }
      if (ctx.strings?.some(s => s.value.endsWith('::') && s.value.length > 10)) {
        score += 10; evidence.push('Rust module paths')
      }
      if (ctx.sections.some(s => s.name.includes('.rust'))) {
        score += 15; evidence.push('Rust-specific sections')
      }

      return { confidence: Math.min(score, 93), evidence }
    },
  },
  {
    name: 'Go',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.strings?.some(s => s.value.startsWith('go1.') || s.value.startsWith('go2.'))) {
        score += 25; evidence.push(`Go version: ${ctx.strings!.find(s => s.value.startsWith('go'))!.value}`)
      }
      if (ctx.strings?.some(s => /^runtime\./.test(s.value))) {
        score += 15; evidence.push('Go runtime references')
      }
      if (ctx.strings?.some(s => s.value === 'main.main' || s.value === 'main.init')) {
        score += 15; evidence.push('Go entry points')
      }
      if (ctx.sections.some(s => s.name === '.go' || s.name === '.noptrdata' || s.name === '.noptrbss')) {
        score += 15; evidence.push('Go sections')
      }

      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'Swift',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.strings?.some(s => /^\$s\d+/.test(s.value) || /^_T0/.test(s.value))) {
        score += 25; evidence.push('Swift mangled symbols')
      }
      if (ctx.strings?.some(s => s.value.includes('swift_') || s.value.includes('Swift.'))) {
        score += 15; evidence.push('Swift runtime')
      }
      if (ctx.sections.some(s => s.name.startsWith('__swift'))) {
        score += 20; evidence.push('Swift sections')
      }
      if (ctx.format === 'Mach-O' && ctx.architecture === 'ARM64') score += 10

      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Zig',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Zig ') || s.value === 'zig')) score += 20
      if (ctx.strings?.some(s => s.value.includes('std.') && (s.value.includes('mem') || s.value.includes('os')))) score += 10
      return { confidence: Math.min(score, 75), evidence }
    },
  },
  {
    name: 'Nim',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /Nim\s+(?:CR|lib|rod)/.test(s.value))) score += 20
      if (ctx.strings?.some(s => s.value.includes('nimGC') || s.value.includes('nimRaw'))) score += 15
      return { confidence: Math.min(score, 75), evidence }
    },
  },
  {
    name: 'D',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('object.d') || s.value.includes('std.'))) score += 15
      if (ctx.strings?.some(s => /_D\w+\d+/.test(s.value))) { score += 20; evidence.push('D mangled names') }
      return { confidence: Math.min(score, 70), evidence }
    },
  },
  {
    name: 'Delphi',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Borland') || s.value.includes('Delphi'))) score += 20
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.imports?.some((i: any) => i.module?.startsWith('borlndmm') || i.module === 'System')) {
          score += 20; evidence.push('Borland/Delphi runtime')
        }
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Crystal',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Crystal') || s.value.includes('crystal:'))) score += 20
      if (ctx.strings?.some(s => s.value.includes('__crystal_'))) { score += 15; evidence.push('Crystal runtime') }
      return { confidence: Math.min(score, 70), evidence }
    },
  },
  {
    name: 'Odin',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Odin ') || s.value.includes('odin_'))) score += 15
      if (ctx.raw) {
        const str = new TextDecoder().decode(ctx.raw.slice(0, Math.min(ctx.raw.length, 50000)))
        if (str.includes('Odin ') || str.includes('runtime.default_context')) score += 10
      }
      return { confidence: Math.min(score, 60), evidence }
    },
  },
  {
    name: 'Assembly',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /\bNASM\b|\bFASM\b|\bMASM\b|\bGAS\b/.test(s.value))) score += 20
      if (ctx.metrics) {
        const m = ctx.metrics
        if (m.functionCount < 50 && m.averageFunctionSize < 50) { score += 10; evidence.push('Small functions typical of asm') }
      }
      return { confidence: Math.min(score, 60), evidence }
    },
  },
]

export function detectLanguage(ctx: PluginContext): DetectedItem | null {
  let best: DetectedItem | null = null

  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence > 10 && (!best || result.confidence > best.confidence)) {
      best = { name: sig.name, confidence: result.confidence, evidence: result.evidence }
    }
  }

  return best
}
