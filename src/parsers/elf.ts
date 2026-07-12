import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

export interface ELFData {
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: { name: string; address: number }[]
  entryPoint: number
  type: number
  timestamp: number
  isShared: boolean
  isExecutable: boolean
  symbols: { name: string; address: number; size: number; type: string }[]
  dynamic: Map<string, bigint>
}

export function parseELF(data: Uint8Array): ELFData | null {
  if (data.length < 64) return null
  if (data[0] !== 0x7F || data[1] !== 0x45 || data[2] !== 0x4C || data[3] !== 0x46) return null

  const reader = BufferReader.from(data)
  const is64 = data[4] === 2
  const littleEndian = data[5] === 1

  const eType = new DataView(data.buffer, data.byteOffset + 16, 2).getUint16(0, littleEndian)
  const eMachine = new DataView(data.buffer, data.byteOffset + 18, 2).getUint16(0, littleEndian)

  const sections: SectionInfo[] = []
  const dynamicMap = new Map<string, bigint>()
  let entryPointVal = 0

  if (is64) {
    reader.seek(0)
    reader.skip(16)
    const eType64 = reader.readU16(littleEndian)
    reader.skip(2 + 4 + 8)
    entryPointVal = Number(reader.readU64(littleEndian))

    reader.skip(8 + 8)
    const eShOff = Number(reader.readU64(littleEndian))
    reader.skip(4 + 2)
    const eShentsize = reader.readU16(littleEndian)
    const eShnum = reader.readU16(littleEndian)
    const eShstrndx = reader.readU16(littleEndian)

    const shstrtabOff = eShOff + eShstrndx * eShentsize
    const shstrtabSecOff = reader.peekU32(shstrtabOff + 24, littleEndian)

    for (let i = 0; i < eShnum && i < 100; i++) {
      const secOff = eShOff + i * eShentsize
      if (secOff + eShentsize > data.length) break

      reader.seek(secOff)
      const shName = reader.readU32(littleEndian)
      const shType = reader.readU32(littleEndian)
      const shFlags = Number(reader.readU64(littleEndian))
      const shAddr = Number(reader.readU64(littleEndian))
      const shOffset = Number(reader.readU64(littleEndian))
      const shSize = Number(reader.readU64(littleEndian))

      if (shSize === 0) continue

      const name = shstrtabOff > 0 && shstrtabSecOff > 0
        ? reader.readCStringAt(shstrtabSecOff + shName, 64)
        : `.section_${i}`

      const perms: string[] = []
      if (shFlags & 0x1) perms.push('WRITE')
      if (shFlags & 0x2) perms.push('ALLOC')
      if (shFlags & 0x4) perms.push('EXEC')
      if (shType === 0x1) perms.push('PROGBITS')
      if (shType === 0x8) perms.push('NOBITS')

      const rawDataSize = Math.min(shSize, Math.max(0, data.length - shOffset))
      const entropy = rawDataSize > 0 ? sectionEntropy(data, shOffset, rawDataSize) : 0

      sections.push({
        name,
        rva: shAddr,
        fileOffset: shOffset,
        size: shSize,
        entropy,
        permissions: perms.join('|') || 'UNKNOWN',
        alignment: 0,
      })
    }

    const dynamicSection = sections.find(s => s.name === '.dynamic')
    if (dynamicSection) {
      parseDynamicSegment(data, dynamicSection.fileOffset, dynamicSection.size, littleEndian, true, dynamicMap)
    }
  } else {
    reader.seek(0)
    reader.skip(16)
    reader.skip(2 + 2 + 4)
    entryPointVal = reader.readU32(littleEndian)

    reader.skip(4 + 4)
    const eShOff = reader.readU32(littleEndian)
    reader.skip(4 + 2)
    const eShentsize = reader.readU16(littleEndian)
    const eShnum = reader.readU16(littleEndian)
    const eShstrndx = reader.readU16(littleEndian)

    const shstrtabOff = eShOff + eShstrndx * eShentsize
    const shstrtabSecOff = reader.peekU32(shstrtabOff + 16, littleEndian)

    for (let i = 0; i < eShnum && i < 100; i++) {
      const secOff = eShOff + i * eShentsize
      if (secOff + eShentsize > data.length) break

      reader.seek(secOff)
      const shName = reader.readU32(littleEndian)
      const shType = reader.readU32(littleEndian)
      const shFlags = reader.readU32(littleEndian)
      const shAddr = reader.readU32(littleEndian)
      const shOffset = reader.readU32(littleEndian)
      const shSize = reader.readU32(littleEndian)

      if (shSize === 0) continue

      const name = shstrtabOff > 0 && shstrtabSecOff > 0
        ? reader.readCStringAt(shstrtabSecOff + shName, 64)
        : `.section_${i}`

      const perms: string[] = []
      if (shFlags & 0x1) perms.push('WRITE')
      if (shFlags & 0x2) perms.push('ALLOC')
      if (shFlags & 0x4) perms.push('EXEC')

      const rawDataSize = Math.min(shSize, Math.max(0, data.length - shOffset))
      const entropy = rawDataSize > 0 ? sectionEntropy(data, shOffset, rawDataSize) : 0

      sections.push({
        name,
        rva: shAddr,
        fileOffset: shOffset,
        size: shSize,
        entropy,
        permissions: perms.join('|') || 'UNKNOWN',
        alignment: 0,
      })
    }

    const dynamicSection = sections.find(s => s.name === '.dynamic')
    if (dynamicSection) {
      parseDynamicSegment(data, dynamicSection.fileOffset, dynamicSection.size, littleEndian, false, dynamicMap)
    }
  }

  const isShared = eType === 3
  const isExecutable = eType === 2

  return {
    sections,
    imports: [] as ImportInfo[],
    exports: extractELFSymbols(data, sections, 'export').map(s => ({ name: s.name, address: s.address })),
    entryPoint: entryPointVal,
    type: eType,
    timestamp: 0,
    isShared,
    isExecutable,
    symbols: [],
    dynamic: dynamicMap,
  }
}

function parseDynamicSegment(data: Uint8Array, offset: number, size: number, le: boolean, is64: boolean, map: Map<string, bigint>): void {
  const reader = BufferReader.from(data)
  let pos = offset
  const entrySize = is64 ? 16 : 8
  const tagNames: Record<number, string> = {
    1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH',
    5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ',
    9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 12: 'INIT',
    13: 'FINI', 14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC',
    17: 'REL', 18: 'RELSZ', 19: 'RELENT', 21: 'PLTREL',
    23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY',
    26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ',
    30: 'FLAGS', 0x6FFFFFFE: 'VERNEED', 0x6FFFFFFF: 'VERNEEDNUM',
    0x6FFFFFF0: 'VERSYM', 0x6FFFFFFA: 'RELACOUNT',
  }

  while (pos < offset + size && pos < data.length - entrySize) {
    if (is64) {
      const d_tag = Number(reader.peekU32(pos, le))
      const d_val = reader.peekU32(pos + 8, le) | (reader.peekU32(pos + 12, le) << 32)
      if (d_tag === 0) break
      const name = tagNames[d_tag]
      if (name) map.set(name, BigInt(d_val))
    } else {
      const d_tag = reader.peekU32(pos, le)
      const d_val = reader.peekU32(pos + 4, le)
      if (d_tag === 0) break
      const name = tagNames[d_tag]
      if (name) map.set(name, BigInt(d_val))
    }
    pos += entrySize
  }
}

function extractELFSymbols(data: Uint8Array, sections: SectionInfo[], type: 'import' | 'export'): { name: string; address: number; size: number; type: string }[] {
  return []
}
