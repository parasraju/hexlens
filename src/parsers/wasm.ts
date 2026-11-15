import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

export interface WASMData {
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: ExportInfo[]
  types: string[]
  functions: number
  memories: number
  tables: number
  globals: number
  version: number
}

export function parseWASM(data: Uint8Array): WASMData | null {
  try {
    return parseWASMInner(data)
  } catch {
    return null
  }
}

function parseWASMInner(data: Uint8Array): WASMData | null {
  if (data.length < 8) return null

  if (data[0] !== 0x00 || data[1] !== 0x61 || data[2] !== 0x73 || data[3] !== 0x6D) return null

  if (data.byteOffset + 8 > data.buffer.byteLength) return null
  const version = new DataView(data.buffer, data.byteOffset + 4, 4).getUint32(0, true)
  if (version !== 1) return null

  const reader = BufferReader.from(data)
  reader.seek(8)

  const sections: SectionInfo[] = []
  const imports: ImportInfo[] = []
  const exports: ExportInfo[] = []
  const types: string[] = []
  let functionCount = 0
  let memories = 0
  let tables = 0
  let globals = 0

  const sectionNames: Record<number, string> = {
    0: 'custom', 1: 'type', 2: 'import', 3: 'function',
    4: 'table', 5: 'memory', 6: 'global', 7: 'export',
    8: 'start', 9: 'element', 10: 'code', 11: 'data',
    12: 'data_count',
  }

  let guard = 0
  while (reader.remaining > 0 && guard++ < 10000) {
    const here = reader.offset
    const sectionId = reader.readU8()
    const sectionSize = readLEB128(reader)
    const sectionStart = reader.offset
    if (sectionSize < 0 || sectionStart < here || sectionStart > data.length) break
    const sectionName = sectionNames[sectionId] || `section_${sectionId}`

    sections.push({
      name: sectionName,
      rva: sectionStart,
      fileOffset: sectionStart,
      size: sectionSize,
      entropy: sectionEntropy(data, sectionStart, Math.min(sectionSize, data.length - sectionStart)),
      permissions: sectionId === 10 ? 'RX' : 'R',
      alignment: 0,
    })

    if (sectionId === 1) {
      const count = readLEB128(reader)
      for (let i = 0; i < count; i++) {
        const form = reader.readU8()
        if (form === 0x60) {
          const paramCount = readLEB128(reader)
          reader.skip(paramCount)
          const resultCount = readLEB128(reader)
          reader.skip(resultCount)
          types.push(`func_${i}`)
        }
      }
    } else if (sectionId === 2) {
      const count = readLEB128(reader)
      for (let i = 0; i < count; i++) {
        const modLen = readLEB128(reader)
        const module = reader.readString(modLen)
        const nameLen = readLEB128(reader)
        const name = reader.readString(nameLen)
        const kind = reader.readU8()
        imports.push({ module, name })
        if (kind === 1) reader.skip(readLEB128(reader))
        else if (kind === 2) reader.skip(1)
        else if (kind === 3) { reader.skip(1); functionCount++ }
      }
    } else if (sectionId === 3) {
      functionCount = readLEB128(reader)
    } else if (sectionId === 4) {
      tables = readLEB128(reader)
      reader.skip(1)
      const limits = reader.readU8()
      reader.skip(limits & 0x01 ? 8 : 4)
    } else if (sectionId === 5) {
      memories = readLEB128(reader)
      const limits = reader.readU8()
      reader.skip(limits & 0x01 ? 8 : 4)
    } else if (sectionId === 6) {
      globals = readLEB128(reader)
    } else if (sectionId === 7) {
      const count = readLEB128(reader)
      for (let i = 0; i < count; i++) {
        const nameLen = readLEB128(reader)
        const name = reader.readString(nameLen)
        const kind = reader.readU8()
        const idx = readLEB128(reader)
        exports.push({ name, address: idx })
      }
    }

    const next = sectionStart + sectionSize
    if (!Number.isFinite(next) || next <= here || next > data.length) break
    reader.seek(next)
  }

  return {
    sections,
    imports,
    exports,
    types,
    functions: functionCount,
    memories,
    tables,
    globals,
    version,
  }
}

function readLEB128(reader: BufferReader): number {
  let result = 0
  let shift = 0
  for (let count = 0; count < 5; count++) {
    if (reader.remaining <= 0) return result
    const byte = reader.readU8()
    result |= (byte & 0x7F) << shift
    if ((byte & 0x80) === 0) break
    shift += 7
  }
  return result >>> 0
}
