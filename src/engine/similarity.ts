import type { SimilarityResult, SectionInfo, ImportInfo } from '../types/index.js'

export function compareByHash(data: Uint8Array): SimilarityResult[] {
  return []
}

export function compareBySectionSimilarity(aSections: SectionInfo[], bSections: SectionInfo[]): number {
  const aEntropies = aSections.map(s => s.entropy).sort()
  const bEntropies = bSections.map(s => s.entropy).sort()
  const maxLen = Math.max(aEntropies.length, bEntropies.length)
  if (maxLen === 0) return 0

  let diff = 0
  for (let i = 0; i < Math.min(aEntropies.length, bEntropies.length); i++) {
    diff += Math.abs(aEntropies[i] - bEntropies[i])
  }

  return Math.max(0, Math.round((1 - diff / (maxLen * 8)) * 100))
}

export function compareByImportSimilarity(aImports: ImportInfo[], bImports: ImportInfo[]): number {
  const aSet = new Set(aImports.map(i => `${i.module}:${i.name}`))
  const bSet = new Set(bImports.map(i => `${i.module}:${i.name}`))

  if (aSet.size === 0 && bSet.size === 0) return 0

  let intersection = 0
  for (const item of aSet) {
    if (bSet.has(item)) intersection++
  }

  const union = new Set([...aSet, ...bSet])
  return Math.round((intersection / union.size) * 100)
}

export function compareBinaries(
  a: { sections: SectionInfo[]; imports: ImportInfo[]; hash: string },
  b: { sections: SectionInfo[]; imports: ImportInfo[]; hash: string },
): SimilarityResult[] {
  return [
    {
      algorithm: 'Import Similarity',
      score: compareByImportSimilarity(a.imports, b.imports),
    },
    {
      algorithm: 'Section Similarity',
      score: compareBySectionSimilarity(a.sections, b.sections),
    },
  ]
}

export function computeTLSH(data: Uint8Array): string {
  return ''
}

export function computeSsdeep(data: Uint8Array): string {
  return ''
}
