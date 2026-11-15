import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { hasSection, hasText, textMarker } from './evidence.js'

interface CompilerSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const MIN_CONFIDENCE = 55

const signatures: CompilerSignature[] = [
  {
    name: 'Rustc',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'rustc version') ?? textMarker(ctx, 'rustc 1.')
      if (version) { score += 97; evidence.push(version) }
      if (hasText(ctx, 'rust_metadata') || hasSection(ctx, n => n.includes('.rust'))) {
        score += 20; evidence.push('Rust metadata section')
      }
      if (hasText(ctx, 'rust_begin_unwind') || hasText(ctx, 'rust_panic')) {
        score += 15; evidence.push('Rust panic runtime')
      }
      return { confidence: Math.min(score, 97), evidence }
    },
  },
  {
    name: 'Go',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'go1.')
      if (version && /^go1\.\d+/.test(version)) { score += 96; evidence.push(version.split(' ')[0]) }
      if (hasSection(ctx, n => n === '.gopclntab' || n === '.go.buildinfo' || n === '.noptrdata')) {
        score += 18; evidence.push('Go runtime sections')
      }
      if (hasText(ctx, 'runtime.gopanic') || hasText(ctx, 'go.buildid')) {
        score += 12; evidence.push('Go runtime')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'Clang',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'clang version')
      if (version) { score += 95; evidence.push(version) }
      if (hasSection(ctx, n => n.startsWith('__clang') || n.startsWith('.llvm'))) {
        score += 12; evidence.push('LLVM/Clang sections')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'MinGW',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.format !== 'PE' && ctx.format !== '.NET') return { confidence: 0, evidence }
      const gcc = textMarker(ctx, 'GCC: (')
      const mingw = textMarker(ctx, 'MinGW') ?? textMarker(ctx, 'mingw-w64')
      const mods = (ctx.imports ?? []).map(i => i.module.toLowerCase())
      const runtime = mods.some(m => m.includes('msvcrt') || m.includes('libgcc') || m.includes('libstdc++') || m.includes('libwinpthread'))
      if (gcc && (mingw || runtime)) {
        score += 94
        evidence.push(mingw ? 'MinGW runtime' : 'GCC toolchain linked against the MinGW CRT')
        evidence.push(gcc)
      } else if (mingw) {
        score += 70
        evidence.push(mingw)
      }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'GCC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'GCC: (')
      if (version) {
        score += 90
        evidence.push(version)
      } else if (hasText(ctx, 'GNU C++') || hasText(ctx, 'GNU C')) {
        score += 78
        evidence.push('GNU C compiler identification')
      } else if (
        hasSection(ctx, n => n.startsWith('.gnu.'))
        && hasText(ctx, 'GLIBC_')
        && !hasText(ctx, 'clang version')
        && !hasText(ctx, 'rustc version')
      ) {
        // Stripped distribution binaries often keep GNU hash sections and glibc
        // versions after .comment has been removed.
        score += 84
        evidence.push('GNU binutils sections and glibc symbol versions')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'MSVC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.format !== 'PE' && ctx.format !== '.NET') return { confidence: 0, evidence }
      const banner = textMarker(ctx, 'Microsoft Visual C++') ?? textMarker(ctx, 'Microsoft (R) C/C++')
      if (banner) { score += 85; evidence.push(banner) }
      const pe = ctx.metadata.peData as { linkerVersion?: string; imports?: { module?: string }[] } | undefined
      const mods = (pe?.imports ?? ctx.imports ?? []).map(i => (i.module ?? '').toLowerCase())
      if (mods.some(m => m.includes('vcruntime') || m.startsWith('msvcp'))) {
        score += 25; evidence.push('MSVC C/C++ runtime')
      }
      if (mods.some(m => m.startsWith('api-ms-win-'))) {
        score += 15; evidence.push('Universal CRT')
      }
      if (!banner && pe?.linkerVersion && score >= 25) {
        score += 15; evidence.push(`Linker version ${pe.linkerVersion}`)
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'Zig',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const version = textMarker(ctx, 'zig version') ?? textMarker(ctx, 'Zig ')
      if (version && /zig/i.test(version)) { score += 75; evidence.push(version) }
      if (hasText(ctx, 'zig_panic') || hasSection(ctx, n => n.includes('zig'))) {
        score += 20; evidence.push('Zig runtime')
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Swift',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasSection(ctx, n => n.startsWith('__swift'))) { score += 70; evidence.push('Swift metadata sections') }
      if (hasText(ctx, 'swift_retain') || hasText(ctx, 'swift_release')) {
        score += 25; evidence.push('Swift runtime')
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'TinyCC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const banner = textMarker(ctx, 'TinyCC') ?? textMarker(ctx, 'tcc version')
      if (banner) { score += 80; evidence.push(banner) }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Intel Compiler',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const banner = textMarker(ctx, 'Intel(R) C++') ?? textMarker(ctx, 'Intel(R) oneAPI') ?? textMarker(ctx, 'Intel Fortran')
      if (banner) { score += 85; evidence.push(banner) }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Delphi',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const banner = textMarker(ctx, 'Embarcadero') ?? textMarker(ctx, 'Borland')
      if (banner) { score += 75; evidence.push(banner) }
      if (hasModuleName(ctx, /^borlndmm/i)) { score += 25; evidence.push('Borland memory manager') }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Nim',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'NimMain') || hasText(ctx, 'nimGC_') || hasText(ctx, 'nimToCStringConv')) {
        score += 80; evidence.push('Nim runtime')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
]

function hasModuleName(ctx: PluginContext, pattern: RegExp): boolean {
  return (ctx.imports ?? []).some(i => pattern.test(i.module))
}

export function detectCompiler(ctx: PluginContext): DetectedItem | null {
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
