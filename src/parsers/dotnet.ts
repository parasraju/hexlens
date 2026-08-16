import { BufferReader } from '../utils/buffer-reader.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

export interface DotNetData {
  runtimeVersion: string
  assemblyName: string
  assemblyVersion: string
  moduleName: string
  flags: number
  entryPointToken: number
  clrMajor: number
  clrMinor: number
  streams: { name: string; size: number; offset: number }[]
  methodDefs: string[]
  typeRefs: string[]
  userStrings: string[]
  imports: ImportInfo[]
  exports: ExportInfo[]
}

const MAX_ITEMS = 50000

export function parseDotNet(data: Uint8Array, sections: SectionInfo[]): DotNetData | null {
  if (data.length < 0x40) return null
  if (data[0] !== 0x4D || data[1] !== 0x5A) return null

  const reader = BufferReader.from(data)
  const peOffset = reader.peekU32(0x3C, true)
  if (peOffset + 4 > data.length) return null
  if (reader.peekU32(peOffset, true) !== 0x00004550) return null

  const magic = reader.peekU16(peOffset + 24, true)
  const dataDirStart = peOffset + 24 + (magic === 0x20B ? 112 : 96)
  if (dataDirStart + 14 * 8 + 8 > data.length) return null

  const comRva = reader.peekU32(dataDirStart + 14 * 8, true)
  if (comRva === 0) return null

  const comOff = resolveRVA(data, comRva, sections)
  if (comOff === null || comOff + 72 > data.length) return null

  reader.seek(comOff)
  const cb = reader.readU32(true)
  const clrMajor = reader.readU16(true)
  const clrMinor = reader.readU16(true)
  const metaRva = reader.readU32(true)
  const metaSize = reader.readU32(true)
  const flags = reader.readU32(true)
  const entryPointToken = reader.readU32(true)

  const metaOff = resolveRVA(data, metaRva, sections)
  if (metaOff === null || metaOff + 24 > data.length) return null

  reader.seek(metaOff)
  const sig = reader.readU32(true)
  if (sig !== 0x424A5342) return null
  reader.readU16(true)
  reader.readU16(true)
  reader.readU32(true)
  const versionLength = reader.readU32(true)
  const versionEnd = metaOff + 16 + versionLength
  if (versionEnd > data.length) return null

  const versionBytes = reader.readBytes(versionLength)
  const runtimeVersion = decodeCString(versionBytes)

  reader.seek(versionEnd)
  const streamFlags = reader.readU16(true)
  const streamCount = reader.readU16(true)

  const streams: { name: string; size: number; offset: number; absOff: number }[] = []
  for (let i = 0; i < streamCount && i < 64; i++) {
    const headerStart = reader.offset
    const sOff = reader.readU32(true)
    const sSize = reader.readU32(true)
    const nameStart = reader.offset
    let name = ''
    while (reader.remaining > 0) {
      const c = reader.readU8()
      if (c === 0) break
      name += String.fromCharCode(c)
    }
    const nameLen = reader.offset - nameStart
    reader.seek(headerStart + Math.ceil((8 + nameLen) / 4) * 4)
    const absOff = metaOff + sOff
    streams.push({
      name,
      size: sSize,
      offset: sOff,
      absOff: absOff < data.length ? absOff : data.length,
    })
  }

  const stringsHeap = streams.find(s => s.name === '#Strings')
  const blobHeap = streams.find(s => s.name === '#Blob')
  const guidHeap = streams.find(s => s.name === '#GUID')
  const tablesStream = streams.find(s => s.name === '#~' || s.name === '#-')
  const usStream = streams.find(s => s.name === '#US')

  const readString = (idx: number): string => {
    if (!stringsHeap || idx <= 0) return ''
    const abs = stringsHeap.absOff + idx
    if (abs >= data.length) return ''
    return readCStringAt(data, abs)
  }

  const rowCounts = new Array<number>(0x40).fill(0)
  let heapSizes = 0
  let validMask = 0n
  let tablesOff = 0

  if (tablesStream && tablesStream.absOff + 24 <= data.length) {
    const tOff = tablesStream.absOff
    reader.seek(tOff)
    reader.skip(4)
    reader.readU8()
    reader.readU8()
    heapSizes = reader.readU8()
    reader.skip(1)
    validMask = reader.readU64(true)
    reader.skip(8)
    for (let t = 0; t < 0x40; t++) {
      if ((validMask & (1n << BigInt(t))) !== 0n) {
        rowCounts[t] = reader.readU32(true)
      }
    }
    tablesOff = reader.offset
  }

  const stringsIdx = () => (heapSizes & 0x01) !== 0 ? 4 : 2
  const guidIdx = () => (heapSizes & 0x02) !== 0 ? 4 : 2
  const blobIdx = () => (heapSizes & 0x04) !== 0 ? 4 : 2
  const tableIdx = (t: number) => rowCounts[t] > 0xFFFF ? 4 : 2
  const codedIdx = (tables: number[], tagBits: number) => {
    let max = 0
    for (const t of tables) max = Math.max(max, rowCounts[t])
    const indexBits = 16 - tagBits
    return max < (1 << indexBits) ? 2 : 4
  }

  const s = () => stringsIdx()
  const g = () => guidIdx()
  const b = () => blobIdx()
  const ti = (t: number) => tableIdx(t)
  const c = (tables: number[], tagBits: number) => codedIdx(tables, tagBits)

  const resolutionScope = () => c([0, 0x1A, 0x23, 1], 2)
  const typeDefOrRef = () => c([2, 1, 0x1B], 2)
  const memberRefParent = () => c([2, 1, 0x1A, 6, 0x1B], 3)
  const methodDefOrRef = () => c([6, 0x0A], 1)
  const hasSemantics = () => c([0x14, 0x17], 2)
  const memberForwarded = () => c([0x04, 6], 1)
  const hasCustomAttribute = () => c([6, 0x04, 1, 2, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B], 2)
  const customAttributeType = () => c([6, 0x0A, 0x2B], 5)
  const hasConstant = () => c([0x04, 0x08, 0x17], 2)
  const hasFieldMarshal = () => c([0x04, 0x08, 0x17, 0x14, 0x06], 2)
  const hasDeclSecurity = () => c([6, 0x04, 0x08, 0x17, 0x14, 0x02, 0x01, 0x0A, 0x20, 0x23, 0x26, 0x27, 0x28], 2)
  const implementation = () => c([0x26, 0x23, 0x02], 2)
  const typeOrMethodDef = () => c([6, 0x04], 2)

  const rowSize = (t: number): number => {
    switch (t) {
      case 0x00: return 2 + s() + 3 * g()
      case 0x01: return resolutionScope() + s() + s()
      case 0x02: return 4 + s() + s() + typeDefOrRef() + ti(0x04) + ti(0x06)
      case 0x03: return ti(0x04)
      case 0x04: return 2 + s() + b()
      case 0x05: return ti(0x06)
      case 0x06: return 4 + 2 + 2 + s() + b() + ti(0x08)
      case 0x07: return ti(0x08)
      case 0x08: return 2 + 2 + s()
      case 0x09: return ti(0x02) + typeDefOrRef()
      case 0x0A: return memberRefParent() + s() + b()
      case 0x0B: return 2 + hasConstant() + ti(0x0B)
      case 0x0C: return hasCustomAttribute() + customAttributeType() + b()
      case 0x0D: return hasFieldMarshal() + b()
      case 0x0E: return 2 + hasDeclSecurity() + b()
      case 0x0F: return 2 + 4 + ti(0x02)
      case 0x10: return 4 + ti(0x04)
      case 0x11: return b()
      case 0x12: return ti(0x02) + ti(0x14)
      case 0x13: return ti(0x14)
      case 0x14: return 2 + s() + typeDefOrRef()
      case 0x15: return ti(0x02) + ti(0x17)
      case 0x16: return ti(0x17)
      case 0x17: return 2 + s() + b()
      case 0x18: return 2 + ti(0x06) + hasSemantics()
      case 0x19: return ti(0x02) + methodDefOrRef() + methodDefOrRef()
      case 0x1A: return s()
      case 0x1B: return b()
      case 0x1C: return 2 + memberForwarded() + s() + ti(0x1A)
      case 0x1D: return 4 + ti(0x04)
      case 0x1E: return 4 + 4
      case 0x1F: return 4
      case 0x20: return 4 + 2 + 2 + 2 + 2 + 4 + b() + s() + s()
      case 0x21: return 4
      case 0x22: return 4 + 4 + 4
      case 0x23: return 2 + 2 + 2 + 2 + 4 + b() + s() + s() + b()
      case 0x24: return 4 + ti(0x23)
      case 0x25: return 4 + 4 + 4 + ti(0x23)
      case 0x26: return 4 + s() + b()
      case 0x27: return 4 + 4 + s() + s() + implementation()
      case 0x28: return 4 + 4 + s() + implementation()
      case 0x29: return ti(0x02) + ti(0x02)
      case 0x2A: return 2 + 2 + typeOrMethodDef() + s()
      case 0x2B: return methodDefOrRef() + b()
      case 0x2C: return ti(0x2A) + typeDefOrRef()
      default: return 0
    }
  }

  const readUInt = (offset: number, size: number): number => {
    if (offset + size > data.length) return 0
    if (size === 4) return reader.peekU32(offset, true)
    if (size === 2) return reader.peekU16(offset, true)
    return data[offset]
  }

  let moduleName = ''
  let assemblyName = ''
  let assemblyVersion = ''
  const typeRefs: string[] = []
  const methodDefs: string[] = []

  if (tablesStream) {
    let off = tablesOff
    for (let t = 0; t < 0x40; t++) {
      if ((validMask & (1n << BigInt(t))) === 0n) continue
      const count = rowCounts[t]
      const size = rowSize(t)
      if (off + count * size > data.length) break

      if (t === 0x00 && count > 0) {
        const nameIdx = readUInt(off + 2, stringsIdx())
        moduleName = readString(nameIdx)
      } else if (t === 0x01) {
        const rowStart = off
        for (let i = 0; i < count && typeRefs.length < MAX_ITEMS; i++) {
          const row = rowStart + i * size
          const nameIdx = readUInt(row + resolutionScope(), stringsIdx())
          const nsIdx = readUInt(row + resolutionScope() + stringsIdx(), stringsIdx())
          const name = readString(nameIdx)
          const ns = readString(nsIdx)
          if (name) typeRefs.push(ns ? `${ns}.${name}` : name)
        }
      } else if (t === 0x06) {
        const rowStart = off
        for (let i = 0; i < count && methodDefs.length < MAX_ITEMS; i++) {
          const row = rowStart + i * size
          const nameIdx = readUInt(row + 8, stringsIdx())
          const name = readString(nameIdx)
          if (name) methodDefs.push(name)
        }
      } else if (t === 0x20 && count > 0) {
        const row = off
        const major = readUInt(row + 4, 2)
        const minor = readUInt(row + 6, 2)
        const build = readUInt(row + 8, 2)
        const rev = readUInt(row + 10, 2)
        assemblyVersion = `${major}.${minor}.${build}.${rev}`
        const nameIdx = readUInt(row + 16 + blobIdx(), stringsIdx())
        assemblyName = readString(nameIdx)
      }

      off += count * size
    }
  }

  const userStrings: string[] = []
  if (usStream && usStream.absOff + 4 <= data.length) {
    const start = usStream.absOff + 4
    let p = start
    let scanned = 0
    while (p + 1 < data.length && scanned < MAX_ITEMS) {
      const len = readCompressed(data, p)
      p += len.size
      const blobLen = len.value
      if (blobLen === 0 || p + blobLen > data.length) break
      const raw = data.slice(p, p + blobLen)
      if (blobLen >= 2) {
        userStrings.push(decodeUTF16(raw))
      }
      p += blobLen + 1
      scanned++
      if (userStrings.length >= 5000) break
    }
  }

  const imports: ImportInfo[] = Array.from(new Set(typeRefs)).slice(0, MAX_ITEMS)
    .map(name => ({ module: '.NET', name }))
  const exports: ExportInfo[] = methodDefs.slice(0, MAX_ITEMS)
    .map((name, i) => ({ name, address: i, ordinal: i }))

  return {
    runtimeVersion,
    assemblyName,
    assemblyVersion,
    moduleName,
    flags,
    entryPointToken,
    clrMajor,
    clrMinor,
    streams: streams.map(s => ({ name: s.name, size: s.size, offset: s.offset })),
    methodDefs: methodDefs.slice(0, MAX_ITEMS),
    typeRefs: typeRefs.slice(0, MAX_ITEMS),
    userStrings,
    imports,
    exports,
  }
}

function readCompressed(data: Uint8Array, offset: number): { value: number; size: number } {
  const b0 = data[offset]
  if (b0 < 0x80) return { value: b0, size: 1 }
  if (b0 < 0xC0 && offset + 1 < data.length) {
    return { value: ((b0 & 0x3F) << 8) | data[offset + 1], size: 2 }
  }
  if (b0 < 0xE0 && offset + 3 < data.length) {
    const b1 = data[offset + 1]
    const b2 = data[offset + 2]
    const b3 = data[offset + 3]
    return { value: ((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3, size: 4 }
  }
  return { value: 0, size: 1 }
}

function decodeUTF16(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8))
  }
  return s
}

function decodeCString(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) break
    s += String.fromCharCode(bytes[i])
  }
  return s
}

function readCStringAt(data: Uint8Array, offset: number): string {
  let s = ''
  for (let i = offset; i < data.length && i < offset + 256; i++) {
    if (data[i] === 0) break
    s += String.fromCharCode(data[i])
  }
  return s
}

function findSectionByRVA(rva: number, sections: SectionInfo[]): SectionInfo | null {
  for (const s of sections) {
    if (rva >= s.rva && rva < s.rva + (s.size || 0)) return s
  }
  return null
}

function resolveRVA(data: Uint8Array, rva: number, sections: SectionInfo[]): number | null {
  const section = findSectionByRVA(rva, sections)
  if (!section || section.fileOffset === 0) return null
  const offset = rva - section.rva + section.fileOffset
  if (offset < 0 || offset >= data.length) return null
  return offset
}