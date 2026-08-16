import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

interface PEOptionalHeader {
  magic: number
  addressOfEntryPoint: number
  imageBase: number
  sectionAlignment: number
  fileAlignment: number
  sizeOfImage: number
  sizeOfHeaders: number
  subsystem: number
  dllCharacteristics: number
  numberOfRvaAndSizes: number
}

export interface PEData {
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: ExportInfo[]
  entryPoint: number
  imageBase: number
  subsystem: number
  dllCharacteristics: number
  timestamp: number
  isDLL: boolean
  isDriver: boolean
  resources: { name: string; type: string; size: number; offset: number }[]
}

export function parsePE(data: Uint8Array): PEData | null {
  if (data.length < 0x40) return null

  const reader = BufferReader.from(data)

  const peOffset = reader.peekU32(0x3C, true)
  if (peOffset + 4 > data.length) return null

  const peSig = reader.peekU32(peOffset, true)
  if (peSig !== 0x00004550) return null

  reader.seek(peOffset + 4)
  const machine = reader.readU16(true)
  const numberOfSections = reader.readU16(true)
  const timestamp = reader.readU32(true)
  reader.skip(8)
  const sizeOfOptionalHeader = reader.readU16(true)
  const characteristics = reader.readU16(true)

  const isDLL = (characteristics & 0x2000) !== 0
  const isDriver = machine === 0x01C4 || machine === 0xAA64

  const optHeader: PEOptionalHeader = {
    magic: 0,
    addressOfEntryPoint: 0,
    imageBase: 0,
    sectionAlignment: 0,
    fileAlignment: 0,
    sizeOfImage: 0,
    sizeOfHeaders: 0,
    subsystem: 0,
    dllCharacteristics: 0,
    numberOfRvaAndSizes: 0,
  }

  reader.seek(peOffset + 24)
  optHeader.magic = reader.readU16(true)
  const isPE32Plus = optHeader.magic === 0x20B

  if (isPE32Plus) {
    reader.seek(peOffset + 24 + 16)
    optHeader.addressOfEntryPoint = reader.readU32(true)
    reader.skip(4)
    optHeader.imageBase = Number(reader.readU64(true))
    optHeader.sectionAlignment = reader.readU32(true)
    optHeader.fileAlignment = reader.readU32(true)
    reader.skip(2 + 2 + 2 + 2 + 2 + 2 + 4)
    optHeader.sizeOfImage = reader.readU32(true)
    optHeader.sizeOfHeaders = reader.readU32(true)
    reader.skip(4)
    optHeader.subsystem = reader.readU16(true)
    optHeader.dllCharacteristics = reader.readU16(true)
    reader.skip(8 + 8 + 8 + 8 + 4)
    optHeader.numberOfRvaAndSizes = reader.readU32(true)
  } else {
    reader.seek(peOffset + 24 + 16)
    optHeader.addressOfEntryPoint = reader.readU32(true)
    optHeader.imageBase = reader.readU32(true)
    optHeader.sectionAlignment = reader.readU32(true)
    optHeader.fileAlignment = reader.readU32(true)
    reader.skip(2 + 2 + 2 + 2 + 2 + 2 + 4)
    optHeader.sizeOfImage = reader.readU32(true)
    optHeader.sizeOfHeaders = reader.readU32(true)
    reader.skip(4)
    optHeader.subsystem = reader.readU16(true)
    optHeader.dllCharacteristics = reader.readU16(true)
    reader.skip(4 + 4 + 4 + 4 + 4)
    optHeader.numberOfRvaAndSizes = reader.readU32(true)
  }

  const sections: SectionInfo[] = []
  reader.seek(peOffset + 24 + sizeOfOptionalHeader)

  for (let i = 0; i < numberOfSections; i++) {
    const name = reader.readString(8)
    const virtualSize = reader.readU32(true)
    const virtualAddress = reader.readU32(true)
    const rawSize = reader.readU32(true)
    const rawOffset = reader.readU32(true)
    reader.skip(12)
    const characteristicsFlags = reader.readU32(true)

    const perms: string[] = []
    if (characteristicsFlags & 0x20) perms.push('CODE')
    if (characteristicsFlags & 0x40) perms.push('INIT_DATA')
    if (characteristicsFlags & 0x80) perms.push('UNINIT_DATA')
    if (characteristicsFlags & 0x20000000) perms.push('EXECUTE')
    if (characteristicsFlags & 0x40000000) perms.push('READ')
    if (characteristicsFlags & 0x80000000) perms.push('WRITE')

    const rawDataSize = rawSize > 0 && rawOffset > 0 ? Math.min(rawSize, data.length - rawOffset) : 0
    const entropy = rawDataSize > 0 ? sectionEntropy(data, rawOffset, rawDataSize) : 0

    sections.push({
      name: name || `.section_${i}`,
      rva: virtualAddress,
      fileOffset: rawOffset,
      size: rawSize || virtualSize,
      entropy,
      permissions: perms.join('|') || 'UNKNOWN',
      alignment: optHeader.sectionAlignment,
    })
  }

  const dataDirStart = peOffset + 24 + (isPE32Plus ? 112 : 96)

  const imports = extractImports(data, dataDirStart, isPE32Plus, optHeader.imageBase, sections)
  const exports_ = extractExports(data, dataDirStart, isPE32Plus, sections)
  const resources = extractResources(data, sections)

  return {
    sections,
    imports,
    exports: exports_,
    entryPoint: optHeader.addressOfEntryPoint,
    imageBase: optHeader.imageBase,
    subsystem: optHeader.subsystem,
    dllCharacteristics: optHeader.dllCharacteristics,
    timestamp,
    isDLL,
    isDriver,
    resources,
  }
}

function extractImports(data: Uint8Array, dataDirStart: number, isPE32Plus: boolean, imageBase: number, sections: SectionInfo[]): ImportInfo[] {
  const reader = BufferReader.from(data)
  const importDirOffset = dataDirStart + 8
  const importRVA = reader.peekU32(importDirOffset, true)
  const importSize = reader.peekU32(importDirOffset + 4, true)

  if (importRVA === 0 || importSize === 0) return []

  if (!findSectionByRVA(importRVA, sections)) return []

  const fileOffset = resolveRVA(data, importRVA, sections)
  if (fileOffset === null) return []

  const result: ImportInfo[] = []
  let offset = fileOffset

  let maxIter = 500
  while (maxIter-- > 0) {
    if (offset + 20 > data.length) break
    const lookupTableRVA = reader.peekU32(offset, true)
    const nameRVA = reader.peekU32(offset + 12, true)
    if (lookupTableRVA === 0 && nameRVA === 0) break

    const nameOffset = resolveRVA(data, nameRVA, sections)
    let moduleName = ''
    if (nameOffset !== null && nameOffset < data.length) {
      moduleName = reader.readCStringAt(nameOffset, 128)
    }

    const thunkOffset = resolveRVA(data, lookupTableRVA, sections)
    if (thunkOffset !== null) {
      let i = 0
      while (i < 500) {
        const entryOffset = isPE32Plus ? thunkOffset + i * 8 : thunkOffset + i * 4
        if (entryOffset + 4 > data.length) break
        const entry = reader.peekU32(entryOffset, true)
        if (entry === 0) break
        const isOrdinal = (entry & 0x80000000) !== 0
        if (!isOrdinal && moduleName) {
          const importNameOffset = resolveRVA(data, entry & 0x7FFFFFFF, sections)
          if (importNameOffset !== null && importNameOffset + 2 < data.length) {
            const name = reader.readCStringAt(importNameOffset + 2, 128)
            if (name) {
              result.push({ module: moduleName, name })
            }
          }
        }
        i++
      }
    }
    offset += 20
  }

  return result
}

function extractExports(data: Uint8Array, dataDirStart: number, isPE32Plus: boolean, sections: SectionInfo[]): ExportInfo[] {
  const reader = BufferReader.from(data)
  const exportDirOffset = dataDirStart + 0
  const exportRVA = reader.peekU32(exportDirOffset, true)
  const exportSize = reader.peekU32(exportDirOffset + 4, true)

  if (exportRVA === 0 || exportSize === 0) return []

  const fileOffset = resolveRVA(data, exportRVA, sections)
  if (fileOffset === null) return []

  reader.seek(fileOffset)
  reader.skip(4)
  const numberOfFunctions = reader.readU32(true)
  const numberOfNames = reader.readU32(true)
  const addressTableRVA = reader.readU32(true)
  const namePointerRVA = reader.readU32(true)
  const ordinalTableRVA = reader.readU32(true)

  const result: ExportInfo[] = []
  const addressTableOffset = resolveRVA(data, addressTableRVA, sections)
  const namePointerOffset = resolveRVA(data, namePointerRVA, sections)
  const ordinalTableOffset = resolveRVA(data, ordinalTableRVA, sections)

  if (addressTableOffset === null) return result

  const maxFunc = Math.min(numberOfFunctions, 500)
  for (let i = 0; i < maxFunc; i++) {
    const addrOffset = addressTableOffset + i * 4
    if (addrOffset + 4 > data.length) break
    const address = reader.peekU32(addrOffset, true)
    if (address === 0) continue

    let name = ''
    if (namePointerOffset !== null && ordinalTableOffset !== null) {
      const ordOffset = ordinalTableOffset + i * 2
      if (ordOffset + 2 > data.length) break
      const ordinal = reader.peekU16(ordOffset, true) as number
      if (ordinal < numberOfNames) {
        const namePtrOffset = namePointerOffset + ordinal * 4
        if (namePtrOffset + 4 > data.length) break
        const namePtr = reader.peekU32(namePtrOffset, true)
        const nameOff = resolveRVA(data, namePtr, sections)
        if (nameOff !== null && nameOff < data.length) {
          name = reader.readCStringAt(nameOff, 128)
        }
      }
    }

    result.push({ name: name || `fn_${i}`, address, ordinal: i })
  }

  return result
}

function extractResources(data: Uint8Array, sections: SectionInfo[]): { name: string; type: string; size: number; offset: number }[] {
  const reader = BufferReader.from(data)
  const dataDirStart = sections.length > 0 ? findDataDirStart(data) : 0
  if (dataDirStart === 0) return []

  const resourceRVA = reader.peekU32(dataDirStart + 2 * 8, true)
  const resourceSize = reader.peekU32(dataDirStart + 2 * 8 + 4, true)
  if (resourceRVA === 0 || resourceSize === 0) return []

  const rootOffset = resolveRVA(data, resourceRVA, sections)
  if (rootOffset === null) return []

  const typeNames: Record<number, string> = {
    1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING',
    7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE',
    12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE',
    19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST',
  }

  const result: { name: string; type: string; size: number; offset: number }[] = []

  const readDirectory = (dirOffset: number): void => {
    if (dirOffset + 16 > data.length) return
    const named = reader.peekU16(dirOffset + 12, true)
    const idCount = reader.peekU16(dirOffset + 14, true)
    const entries = dirOffset + 16
    for (let i = 0; i < named + idCount; i++) {
      const entryOff = entries + i * 8
      if (entryOff + 8 > data.length) return
      const nameOrId = reader.peekU32(entryOff, true)
      const dataOrDir = reader.peekU32(entryOff + 4, true)
      if ((dataOrDir & 0x80000000) !== 0) {
        const subDir = rootOffset + (dataOrDir & 0x7FFFFFFF)
        readDirectory(subDir)
      } else {
        const dataEntry = resolveRVA(data, dataOrDir, sections)
        if (dataEntry === null || dataEntry + 16 > data.length) continue
        const payloadRva = reader.peekU32(dataEntry, true)
        const size = reader.peekU32(dataEntry + 4, true)
        const payloadOff = resolveRVA(data, payloadRva, sections)
        if (payloadOff === null) continue
        const isNamed = (nameOrId & 0x80000000) !== 0
        let name = ''
        let type = ''
        if (isNamed) {
          const nameOff = rootOffset + (nameOrId & 0x7FFFFFFF)
          const len = reader.peekU16(nameOff, true)
          name = reader.readString(Math.min(len, 256), 'utf16')
        }
        if (typeNames[nameOrId & 0x7FFFFFFF]) {
          type = typeNames[nameOrId & 0x7FFFFFFF]
        }
        result.push({
          name: name || `${nameOrId & 0x7FFFFFFF}`,
          type: type || `TYPE_${nameOrId & 0x7FFFFFFF}`,
          size,
          offset: payloadOff,
        })
      }
    }
  }

  readDirectory(rootOffset)
  return result
}

function findDataDirStart(data: Uint8Array): number {
  const reader = BufferReader.from(data)
  const peOffset = reader.peekU32(0x3C, true)
  if (peOffset + 24 + 4 > data.length) return 0
  const magic = reader.peekU16(peOffset + 24, true)
  return peOffset + 24 + (magic === 0x20B ? 112 : 96)
}

function findSectionByRVA(rva: number, sections: SectionInfo[]): SectionInfo | null {
  for (const s of sections) {
    if (rva >= s.rva && rva < s.rva + s.size) {
      return s
    }
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
