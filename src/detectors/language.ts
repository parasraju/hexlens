import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { countNames, hasSection, hasText, symbolSet, textMarker } from './evidence.js'

interface LanguageSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const MIN_CONFIDENCE = 55

const C_COMPILERS = new Set(['GCC', 'Clang', 'MinGW', 'MSVC', 'TinyCC'])

function compilerName(ctx: PluginContext): string | null {
  const value = ctx.metadata.detectedCompiler
  return typeof value === 'string' && value.length > 0 ? value : null
}

function cxxMangled(ctx: PluginContext): number {
  let count = 0
  for (const name of symbolSet(ctx)) {
    if (name.startsWith('_Z') && name.length > 4) count++
  }
  return count
}

function cxxAbi(ctx: PluginContext): boolean {
  return hasText(ctx, '__gxx_personality_v0')
    || hasText(ctx, '__cxa_throw')
    || hasText(ctx, '__cxa_allocate_exception')
    || hasText(ctx, '__cxa_begin_catch')
    || cxxMangled(ctx) > 0
    || hasText(ctx, '_ZSt')
    || hasText(ctx, '_ZNSt')
    || hasText(ctx, '_ZTVN')
}

const signatures: LanguageSignature[] = [
  {
    name: 'Rust',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (compilerName(ctx) === 'Rustc' || hasText(ctx, 'rustc version')) {
        score += 80; evidence.push('rustc toolchain')
      }
      if (hasText(ctx, 'rust_begin_unwind') || hasText(ctx, 'core::panic')) {
        score += 18; evidence.push('Rust panic runtime')
      }
      if (hasSection(ctx, n => n.includes('.rust'))) {
        score += 12; evidence.push('Rust sections')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'Go',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'go1.')
      if ((version && /^go1\.\d+/.test(version)) || compilerName(ctx) === 'Go') {
        score += 82; evidence.push(version && /^go1\.\d+/.test(version) ? version.split(' ')[0] : 'Go toolchain')
      }
      if (hasSection(ctx, n => n === '.gopclntab' || n === '.go.buildinfo' || n === '.noptrdata')) {
        score += 12; evidence.push('Go sections')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'C++',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const mangled = cxxMangled(ctx)
      if (cxxAbi(ctx)) { score += 80; evidence.push(mangled > 0 ? `${mangled} Itanium C++ symbols` : 'Itanium C++ ABI') }
      if (compilerName(ctx) === 'MSVC' && (hasText(ctx, '??_7') || hasText(ctx, '_CxxThrowException'))) {
        score += 70; evidence.push('MSVC C++ RTTI')
      }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'Swift',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasSection(ctx, n => n.startsWith('__swift')) || compilerName(ctx) === 'Swift') {
        score += 75; evidence.push('Swift metadata')
      }
      if (hasText(ctx, 'swift_retain')) { score += 15; evidence.push('Swift runtime') }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Zig',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (compilerName(ctx) === 'Zig' || hasText(ctx, 'zig_panic')) {
        score += 75; evidence.push('Zig runtime')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Nim',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (compilerName(ctx) === 'Nim' || hasText(ctx, 'NimMain') || hasText(ctx, 'nimGC_')) {
        score += 78; evidence.push('Nim runtime')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Delphi',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (compilerName(ctx) === 'Delphi' || hasText(ctx, 'Embarcadero') || hasText(ctx, 'Software\\Borland')) {
        score += 75; evidence.push('Delphi/Borland runtime')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'C',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const compiler = compilerName(ctx)
      const other = compiler === 'Rustc' || compiler === 'Go' || compiler === 'Zig' || compiler === 'Swift' || compiler === 'Nim' || compiler === 'Delphi'
      if (!other && !cxxAbi(ctx) && compiler && C_COMPILERS.has(compiler)) {
        score += 74
        evidence.push(`${compiler} C toolchain`)
      }
      const symbols = symbolSet(ctx)
      const libc = countNames(symbols, ['printf', 'puts', 'fprintf', 'malloc', 'free', 'memcpy', 'strlen', 'fopen', 'scanf', 'sprintf'])
      if (!cxxAbi(ctx) && libc > 0) {
        score += Math.min(18, libc * 6)
        evidence.push(`${libc} C standard library symbols`)
      }
      if (hasText(ctx, 'GNU C') && !hasText(ctx, 'GNU C++') && !cxxAbi(ctx)) {
        score += 8
        evidence.push('GNU C language tag')
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'D',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, '_Dmain') || hasText(ctx, '_d_assert')) {
        score += 75; evidence.push('D runtime')
      }
      return { confidence: Math.min(score, 86), evidence }
    },
  },
  {
    name: 'Crystal',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, '__crystal_main') || hasText(ctx, 'Crystal::')) {
        score += 75; evidence.push('Crystal runtime')
      }
      return { confidence: Math.min(score, 86), evidence }
    },
  },
  {
    name: 'Odin',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'runtime.default_context') || hasText(ctx, 'odin_rt')) {
        score += 70; evidence.push('Odin runtime')
      }
      return { confidence: Math.min(score, 82), evidence }
    },
  },
  {
    name: 'Assembly',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const banner = textMarker(ctx, 'NASM') ?? textMarker(ctx, 'The Netwide Assembler')
      if (banner) { score += 70; evidence.push(banner) }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
]

export function detectLanguage(ctx: PluginContext): DetectedItem | null {
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
