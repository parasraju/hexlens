import type { BinaryReport } from '../types/index.js'

export function toJSON(report: BinaryReport, pretty = true): string {
  return JSON.stringify(report, null, pretty ? 2 : undefined)
}
