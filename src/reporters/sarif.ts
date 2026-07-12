import type { BinaryReport } from '../types/index.js'

interface SarifResult {
  ruleId: string
  level: string
  message: { text: string }
  locations: { physicalLocation: { artifactLocation: { uri: string } } }[]
  properties?: Record<string, unknown>
}

export function toSARIF(report: BinaryReport): string {
  const results: SarifResult[] = []

  if (report.packer) {
    results.push({
      ruleId: 'HL0001',
      level: 'warning',
      message: { text: `Binary is packed with ${report.packer.name}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: report.file.name },
        },
      }],
      properties: { confidence: report.packer.confidence },
    })
  }

  if (report.security) {
    const sec = report.security
    if (!sec.aslr) results.push(sarifResult('HL0002', 'error', 'ASLR is disabled'))
    if (!sec.dep) results.push(sarifResult('HL0003', 'error', 'DEP is disabled'))
    if (!sec.nx) results.push(sarifResult('HL0004', 'warning', 'NX is not enabled'))
    if (sec.timestampAnomaly) results.push(sarifResult('HL0005', 'warning', 'Timestamp anomaly detected'))
    if (sec.overlay) results.push(sarifResult('HL0006', 'note', 'Executable overlay present'))
  }

  for (const cap of report.capabilities) {
    if (['Code Injection', 'Keylogging', 'Anti-Debug'].includes(cap.name)) {
      results.push({
        ruleId: 'HL0010',
        level: 'error',
        message: { text: `${cap.name} capability detected (confidence: ${cap.confidence}%)` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: report.file.name },
          },
        }],
      })
    }
  }

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'HexLens', version: '0.1.0' } },
      artifacts: [{
        location: { uri: report.file.name },
        description: { text: `Binary analysis: ${report.format} ${report.architecture}` },
      }],
      results,
    }],
  }, null, 2)
}

function sarifResult(ruleId: string, level: string, text: string): SarifResult {
  return {
    ruleId,
    level,
    message: { text },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: '' },
      },
    }],
  }
}
