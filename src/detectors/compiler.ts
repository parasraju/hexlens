import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

interface CompilerSignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const signatures: CompilerSignature[] = [
  {
    name: 'MSVC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => /\.text\b/.test(s.name))) score += 5
      if (ctx.sections.some(s => s.name.includes('debug') || s.name.includes('rdata'))) score += 3
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.linkerVersion) { score += 10; evidence.push(`MSVC linker version ${pe.linkerVersion}`) }
        if (pe?.imports?.some((i: any) => i.module === 'msvcrt' || i.module === 'VCRUNTIME140')) {
          score += 20; evidence.push('MSVC runtime imports detected')
        }
        if (pe?.imports?.some((i: any) => i.module?.startsWith('api-ms-win-'))) {
          score += 15; evidence.push('Universal CRT imports')
        }
      }
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('Microsoft Visual C++')) { score += 25; evidence.push('MSVC compiler string found') }
        if (str.includes('LINK') && str.includes('VERSION')) { score += 10; evidence.push('MSVC linker metadata') }
      }
      if (ctx.strings?.some(s => s.value.includes('/GS ') || s.value.includes('/GL '))) {
        score += 10; evidence.push('MSVC compiler flags')
      }

      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'GCC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name === '.text' || s.name === '.bss')) score += 5
      if (ctx.sections.some(s => s.name.startsWith('.gnu'))) { score += 10; evidence.push('GNU section detected') }
      if (ctx.sections.some(s => s.name === '.init_array' || s.name === '.fini_array')) score += 5

      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('GCC: (')) { score += 25; evidence.push('GCC version string') }
        if (str.includes('GNU C')) { score += 20; evidence.push('GNU C string') }
        if (str.includes('GLIBC')) { score += 15; evidence.push('GLIBC references') }
      }

      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'Clang',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name === '__TEXT' || s.name === '__DATA')) score += 5
      if (ctx.sections.some(s => s.name.startsWith('__clang'))) { score += 15; evidence.push('Clang-specific sections') }

      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('clang version')) { score += 25; evidence.push('Clang version string') }
        if (str.includes('LLVM')) { score += 15; evidence.push('LLVM references') }
      }
      if (ctx.format === 'Mach-O' && ctx.architecture === 'ARM64') score += 10

      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'MinGW',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name === '.text' || s.name === '.data')) score += 5
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.imports?.some((i: any) => i.module === 'msys-2.0' || i.module?.startsWith('msys-'))) {
          score += 25; evidence.push('MSYS imports (MinGW)')
        }
        if (pe?.imports?.some((i: any) => i.module === 'libwinpthread-1')) {
          score += 20; evidence.push('MinGW pthread')
        }
        if (pe?.imports?.some((i: any) => i.module === 'libgcc_s_' || i.module === 'libstdc++-6')) {
          score += 15; evidence.push('MinGW GCC runtime')
        }
      }
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('MinGW')) { score += 20; evidence.push('MinGW string') }
      }

      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Rustc',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name.startsWith('.rust'))) { score += 15; evidence.push('Rust sections') }
      if (ctx.strings?.some(s => s.value.includes('rust_begin_unwind') || s.value.includes('core::panic'))) {
        score += 20; evidence.push('Rust panic/unwind strings')
      }
      if (ctx.strings?.some(s => s.value.includes('::') && s.value.endsWith('>') && s.value.includes('<'))) {
        score += 10; evidence.push('Rust mangled names')
      }

      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 100000)))
        if (str.includes('rust_metadata')) { score += 20; evidence.push('Rust metadata') }
        if (/::[a-z_][a-z0-9_]*::h[0-9a-f]{16}/.test(str)) { score += 25; evidence.push('Rust hash-mangled symbols') }
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
        score += 25; evidence.push('Go version string')
      }
      if (ctx.strings?.some(s => s.value === 'main.main' || s.value === 'main.init')) {
        score += 15; evidence.push('Go entry points')
      }
      if (ctx.sections.some(s => s.name === '.go' || s.name === '.noptrdata')) {
        score += 10; evidence.push('Go sections')
      }
      if (ctx.strings?.some(s => s.value.startsWith('runtime.') || s.value.startsWith('sync.'))) {
        score += 15; evidence.push('Go runtime strings')
      }

      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 100000)))
        if (str.includes('runtime_main') || str.includes('runtime.goexit')) {
          score += 15; evidence.push('Go runtime symbols')
        }
      }

      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'Zig',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.strings?.some(s => s.value.includes('zig_') || s.value.includes('Zig'))) {
        score += 15; evidence.push('Zig strings')
      }
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('Zig ') || str.includes('zig ')) score += 15
        if (str.includes('std.debug') || str.includes('std.os')) score += 10
      }

      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Delphi',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name === '.idata' || s.name === '.itext')) score += 5
      if (ctx.strings?.some(s => s.value.includes('Borland') || s.value.includes('Delphi'))) {
        score += 20; evidence.push('Delphi/Borland strings')
      }
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.imports?.some((i: any) => i.module?.startsWith('borlndmm'))) {
          score += 20; evidence.push('Borland memory manager')
        }
      }

      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Swift',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0

      if (ctx.sections.some(s => s.name.startsWith('__swift'))) { score += 20; evidence.push('Swift sections') }
      if (ctx.strings?.some(s => s.value.includes('swift_') || s.value.includes('Swift'))) {
        score += 15; evidence.push('Swift runtime strings')
      }
      if (ctx.strings?.some(s => s.value.startsWith('_T0') || s.value.startsWith('$s'))) {
        score += 20; evidence.push('Swift mangled symbols')
      }

      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Nim',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => s.value.includes('Nim') || s.value.includes('nim'))) score += 15
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('Nim ') || str.includes('nim ')) score += 15
      }
      return { confidence: Math.min(score, 70), evidence }
    },
  },
  {
    name: 'TinyCC',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('TinyCC') || str.includes('tcc ')) { score += 25; evidence.push('TinyCC string') }
      }
      if (ctx.strings?.some(s => s.value.includes('TinyCC'))) { score += 15; evidence.push('TinyCC references') }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Intel Compiler',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.raw) {
        const bytes = ctx.raw
        const str = new TextDecoder().decode(bytes.slice(0, Math.min(bytes.length, 50000)))
        if (str.includes('Intel(R) C++')) { score += 25; evidence.push('Intel C++ compiler string') }
        if (str.includes('Intel Fortran')) { score += 20; evidence.push('Intel Fortran') }
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
]

export function detectCompiler(ctx: PluginContext): DetectedItem | null {
  let best: DetectedItem | null = null

  for (const sig of signatures) {
    if (sig.name === 'TinyCC' && ctx.format !== 'PE') continue
    const result = sig.score(ctx)
    if (result.confidence > 0 && (!best || result.confidence > best.confidence)) {
      best = { name: sig.name, confidence: result.confidence, evidence: result.evidence }
    }
  }

  return best
}
