import type { BinaryMetrics, SectionInfo } from '../types/index.js'

export function calculateMetrics(
  sections: SectionInfo[],
  raw: Uint8Array,
  stringCount: number,
  importCount: number,
): BinaryMetrics {
  const codeSections = sections.filter(s =>
    s.permissions.includes('EXEC') && s.size > 0
  )
  const totalCodeSize = codeSections.reduce((sum, s) => sum + s.size, 0)
  const estimatedFunctionSize = 40
  const functionCount = codeSections.length > 0
    ? Math.round(totalCodeSize / estimatedFunctionSize)
    : 0

  const averageFunctionSize = functionCount > 0
    ? Math.round(totalCodeSize / functionCount)
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

  let optimizationEstimate = 'Unknown'
  if (functionCount > 0) {
    const avgFnSize = totalCodeSize / functionCount
    if (avgFnSize > 200) optimizationEstimate = 'Debug'
    else if (avgFnSize > 80) optimizationEstimate = 'Release'
    else optimizationEstimate = 'Optimized'
  }

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
