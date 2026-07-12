import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import type { SectionInfo } from '../types/index.js'

export interface MachOData {
  sections: SectionInfo[]
  entryPoint: number
  cputype: number
  cpusubtype: number
  filetype: number
  flags: number
  imports: { module: string; name: string }[]
  exports: { name: string; address: number }[]
  isDylib: boolean
  isExecutable: boolean
}

export function parseMachO(data: Uint8Array): MachOData | null {
  if (data.length < 4) return null

  const magic = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true)

  const is64 = magic === 0xFEEDFACF || magic === 0xCFFAEDFE
  const littleEndian = magic === 0xFEEDFACE || magic === 0xFEEDFACF || magic === 0xCEFAEDFE
  const isFat = magic === 0xCAFEBABE || magic === 0xBEBAFECA

  if (isFat) {
    return parseFatBinary(data)
  }

  const reader = BufferReader.from(data)
  reader.seek(4)

  const cputype = reader.readI32(littleEndian)
  const cpusubtype = reader.readI32(littleEndian)
  const filetype = reader.readU32(littleEndian)
  const ncmds = reader.readU32(littleEndian)
  const sizeofcmds = reader.readU32(littleEndian)
  const flags = reader.readU32(littleEndian)

  const sections: SectionInfo[] = []
  let entryPoint = 0

  for (let cmd = 0; cmd < ncmds; cmd++) {
    if (reader.offset + 8 > reader.length) break
    const cmdType = reader.peekU32(reader.offset, littleEndian)
    const cmdSize = reader.peekU32(reader.offset + 4, littleEndian)

    if (cmdType === 0x01 || cmdType === 0x19) {
      const isSeg64 = cmdType === 0x19
      reader.seek(reader.offset + 8)

      if (isSeg64) {
        const segName = reader.readString(16)
        reader.skip(8)
        const vmAddr = Number(reader.readU64(littleEndian))
        const vmSize = Number(reader.readU64(littleEndian))
        const fileOff = Number(reader.readU64(littleEndian))
        const fileSize = Number(reader.readU64(littleEndian))
        reader.skip(4 + 4 + 4)
        const nsects = reader.readU32(littleEndian)
        reader.skip(4)

        for (let s = 0; s < nsects; s++) {
          const sectName = reader.readString(16)
          const segName2 = reader.readString(16)
          const addr = Number(reader.readU64(littleEndian))
          const size = Number(reader.readU64(littleEndian))
          const off = Number(reader.readU32(littleEndian))
          reader.skip(4 + 4 + 4 + 4 + 4 + 4)

          const rawSize = off > 0 ? Math.min(size, Math.max(0, data.length - off)) : 0
          const entropy = rawSize > 0 ? sectionEntropy(data, off, rawSize) : 0

          sections.push({
            name: sectName,
            rva: addr,
            fileOffset: off,
            size,
            entropy,
            permissions: 'R',
            alignment: 0,
          })
        }
      } else {
        const segName = reader.readString(16)
        const vmAddr = reader.readU32(littleEndian)
        const vmSize = reader.readU32(littleEndian)
        const fileOff = reader.readU32(littleEndian)
        const fileSize = reader.readU32(littleEndian)
        reader.skip(4 + 4)
        const nsects = reader.readU32(littleEndian)
        reader.skip(4)

        for (let s = 0; s < nsects; s++) {
          const sectName = reader.readString(16)
          const segName2 = reader.readString(16)
          const addr = reader.readU32(littleEndian)
          const size = reader.readU32(littleEndian)
          const off = reader.readU32(littleEndian)
          reader.skip(4 + 4 + 4 + 4 + 4 + 4)

          const rawSize = off > 0 ? Math.min(size, Math.max(0, data.length - off)) : 0
          const entropy = rawSize > 0 ? sectionEntropy(data, off, rawSize) : 0

          sections.push({
            name: sectName,
            rva: addr,
            fileOffset: off,
            size,
            entropy,
            permissions: 'R',
            alignment: 0,
          })
        }
      }
    } else if (cmdType === 0x28 || cmdType === 0x80000028) {
      reader.seek(reader.offset + 8)
      entryPoint = Number(cmdType === 0x80000028 ? reader.readU64(littleEndian) : reader.readU32(littleEndian))
    }

    reader.seek(reader.offset + cmdSize)
  }

  const isDylib = filetype === 6
  const isExecutable = filetype === 2

  return {
    sections,
    entryPoint,
    cputype,
    cpusubtype,
    filetype,
    flags,
    imports: [],
    exports: [],
    isDylib,
    isExecutable,
  }
}

function parseFatBinary(data: Uint8Array): MachOData | null {
  return null
}

export function parseUniversalBinary(data: Uint8Array): MachOData[] {
  return []
}
