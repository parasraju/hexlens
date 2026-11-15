import type { BinaryMetrics, SectionInfo } from '../types/index.js'

export function calculateMetrics(
  sections: SectionInfo[],
  raw: Uint8Array,
  stringCount: number,
  importCount: number,
  functionSizes: number[] = [],
): BinaryMetrics {
  const codeSections = sections.filter(s =>
    s.permissions.includes('EXEC') && s.size > 0 && !s.permissions.includes('NOBITS')
  )
  const totalCodeSize = codeSections.reduce((sum, s) => sum + s.size, 0)
  const sized = functionSizes.filter(n => n > 0 && n < 1_000_000)
  const functionCount = sized.length >= 3
    ? sized.length
    : (codeSections.length > 0 ? Math.max(1, Math.round(totalCodeSize / 80)) : 0)

  const averageFunctionSize = sized.length >= 3
    ? Math.round(sized.reduce((sum, n) => sum + n, 0) / sized.length)
    : 0

  const sectionEntropy = sections.length > 0
    ? sections.reduce((sum, s) => sum + s.entropy, 0) / sections.length
    : 0

  const symbolDensity = sections.length > 0
    ? Math.min(importCount / sections.length * 10, 100)
    : 0

  const codePercent = raw.length > 0 ? (totalCodeSize / raw.length) * 100 : 0
  const instructionDensity = Math.min(codePercent, 100)

  const complexityFactors = [
    sections.length > 10 ? 10 : sections.length,
    sectionEntropy > 6 ? 15 : sectionEntropy > 4 ? 8 : 2,
    functionCount > 500 ? 15 : functionCount > 100 ? 10 : 5,
    stringCount > 1000 ? 10 : stringCount > 100 ? 5 : 1,
    importCount > 100 ? 10 : importCount > 20 ? 5 : 1,
  ]
  const complexityScore = Math.min(
    Math.round(complexityFactors.reduce((a, b) => a + b, 0) * 1.5),
    100
  )

  const hasDebug = sections.some(s => s.name.startsWith('.debug') || s.name.startsWith('__debug'))
  let optimizationEstimate = 'Unknown'
  if (hasDebug) optimizationEstimate = 'Debug'
  else if (averageFunctionSize > 0 && averageFunctionSize < 48) optimizationEstimate = 'Optimized'
  else if (sections.length > 0) optimizationEstimate = 'Release'

  return {
    functionCount,
    averageFunctionSize,
    sectionEntropy,
    symbolDensity,
    instructionDensity,
    complexityScore,
    optimizationEstimate,
  }
}
