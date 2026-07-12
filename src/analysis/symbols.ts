import type { ImportInfo, ExportInfo } from '../types/index.js'

export function analyzeSymbols(
  imports: ImportInfo[],
  exports: ExportInfo[],
  strings: { value: string; offset: number }[],
): { imports: ImportInfo[]; exports: ExportInfo[]; rtti: string[]; vtableCount: number; mangledNames: string[] } {
  const rtti: string[] = []
  const mangledNames: string[] = []

  for (const s of strings) {
    if (s.value.includes('vtable') || s.value.includes('__vtbl')) {
      rtti.push(s.value)
    }
    if (s.value.includes('@@') || s.value.startsWith('_Z') || s.value.startsWith('?') && s.value.includes('@@')) {
      mangledNames.push(s.value)
    }
  }

  const vtableCount = rtti.length

  return {
    imports,
    exports,
    rtti,
    vtableCount,
    mangledNames,
  }
}

export function demangleName(name: string): string {
  if (name.startsWith('_Z')) return demangleItanium(name)
  if (name.startsWith('?') && name.includes('@@')) return demangleMSVC(name)
  if (name.startsWith('_T0')) return demangleSwift(name)
  if (/::h[0-9a-f]{16}$/.test(name)) return name.replace(/::h[0-9a-f]{16}$/, '')
  return name
}

function demangleItanium(name: string): string {
  return name
}

function demangleMSVC(name: string): string {
  return name
}

function demangleSwift(name: string): string {
  return name
}
