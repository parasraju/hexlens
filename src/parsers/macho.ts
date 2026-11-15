import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import { readCString } from '../utils/bytes.js'
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
  /** LC_LOAD_DYLIB names. */
  needed: string[]
  /** MH_PIE */
  pie: boolean
  /** Stack is not executable (MH_ALLOW_STACK_EXECUTION is clear). */
  nx: boolean
  symbolCount: number
}

const MH_MAGIC = 0xFEEDFACE
const MH_CIGAM = 0xCEFAEDFE
const MH_MAGIC_64 = 0xFEEDFACF
const MH_CIGAM_64 = 0xCFFAEDFE
const FAT_MAGIC_LE = 0xBEBAFECA
const FAT_CIGAM_LE = 0xCAFEBABE
const LC_SEGMENT = 0x1
const LC_SYMTAB = 0x2
const LC_LOAD_DYLIB = 0xc
const LC_LOAD_WEAK_DYLIB = 0x18
const LC_SEGMENT_64 = 0x19
const LC_MAIN = 0x80000028
const MH_PIE = 0x200000
const MH_ALLOW_STACK_EXECUTION = 0x20000
const MH_EXECUTE = 2
const MH_DYLIB = 6
const MAX_CMDS = 4096
const MAX_SECTS = 256
const MAX_SYMS = 8000

export function parseMachO(data: Uint8Array): MachOData | null {
  try {
    if (data.length < 8) return null
    const magic = new BufferReader(data.buffer, data.byteOffset, data.byteLength).peekU32(0, true)
    if (magic === FAT_MAGIC_LE || magic === FAT_CIGAM_LE) return parseFat(data, magic === FAT_MAGIC_LE)
    return parseThin(data)
  } catch {
    return null
  }
}

function parseFat(data: Uint8Array, bigEndian: boolean): MachOData | null {
  const reader = BufferReader.from(data)
  const nfat = reader.peekU32(4, !bigEndian)
  const count = Math.min(nfat, 16)
  for (let i = 0; i < count; i++) {
    const arch = 8 + i * 20
    if (!reader.inBounds(arch, 20)) break
    const offset = reader.peekU32(arch + 8, !bigEndian)
    const size = reader.peekU32(arch + 12, !bigEndian)
    if (offset < 8 || size < 28 || offset + size > data.length) continue
    const slice = data.subarray(offset, offset + size)
    const parsed = parseThin(slice)
    if (parsed) return parsed
  }
  return null
}

function parseThin(data: Uint8Array): MachOData | null {
  if (data.length < 28) return null
  const reader = BufferReader.from(data)
  const magic = reader.peekU32(0, true)
  const is64 = magic === MH_MAGIC_64 || magic === MH_CIGAM_64
  const is32 = magic === MH_MAGIC || magic === MH_CIGAM
  if (!is64 && !is32) return null
  const le = magic === MH_MAGIC || magic === MH_MAGIC_64
  const headerSize = is64 ? 32 : 28
  if (data.length < headerSize) return null

  const cputype = reader.peekU32(4, le)
  const cpusubtype = reader.peekU32(8, le)
  const filetype = reader.peekU32(12, le)
  const ncmds = Math.min(reader.peekU32(16, le), MAX_CMDS)
  const flags = reader.peekU32(24, le)

  const sections: SectionInfo[] = []
  const imports: { module: string; name: string }[] = []
  const exports: { name: string; address: number }[] = []
  const needed: string[] = []
  let entryOff: number | null = null
  let textVmAddr = 0
  let symbolCount = 0
  let symoff = 0
  let nsyms = 0
  let stroff = 0
  let strsize = 0

  let offset = headerSize
  for (let cmd = 0; cmd < ncmds; cmd++) {
    if (!reader.inBounds(offset, 8)) break
    const cmdType = reader.peekU32(offset, le)
    const cmdSize = reader.peekU32(offset + 4, le)
    if (cmdSize < 8 || offset + cmdSize > data.length) break
    const cmdEnd = offset + cmdSize

    if ((cmdType === LC_SEGMENT || cmdType === LC_SEGMENT_64) && reader.inBounds(offset, is64 && cmdType === LC_SEGMENT_64 ? 72 : 56)) {
      const seg64 = cmdType === LC_SEGMENT_64
      const nameOff = offset + 8
      const segName = readCString(data, nameOff, 16)
      if (seg64) {
        const vmaddr = Number(reader.peekU64(offset + 24, le))
        const fileoff = Number(reader.peekU64(offset + 40, le))
        const initprot = reader.peekU32(offset + 60, le)
        const nsects = reader.peekU32(offset + 64, le)
        if (segName === '__TEXT') textVmAddr = vmaddr
        let sect = offset + 72
        const sectCount = Math.min(nsects, MAX_SECTS)
        for (let s = 0; s < sectCount && sect + 80 <= cmdEnd; s++) {
          sections.push(readSection(data, reader, sect, true, le, initprot))
          sect += 80
        }
        if (fileoff === 0 && segName === '__TEXT') textVmAddr = vmaddr
      } else {
        const vmaddr = reader.peekU32(offset + 24, le)
        const initprot = reader.peekU32(offset + 44, le)
        const nsects = reader.peekU32(offset + 48, le)
        if (segName === '__TEXT') textVmAddr = vmaddr
        let sect = offset + 56
        const sectCount = Math.min(nsects, MAX_SECTS)
        for (let s = 0; s < sectCount && sect + 68 <= cmdEnd; s++) {
          sections.push(readSection(data, reader, sect, false, le, initprot))
          sect += 68
        }
      }
    } else if (cmdType === LC_MAIN && reader.inBounds(offset, 16)) {
      entryOff = Number(reader.peekU64(offset + 8, le))
    } else if ((cmdType === LC_LOAD_DYLIB || cmdType === LC_LOAD_WEAK_DYLIB) && reader.inBounds(offset, 12)) {
      const nameOffset = reader.peekU32(offset + 8, le)
      const abs = offset + nameOffset
      const lib = readCString(data, abs, 256)
      if (lib) needed.push(lib)
    } else if (cmdType === LC_SYMTAB && reader.inBounds(offset, 24)) {
      symoff = reader.peekU32(offset + 8, le)
      nsyms = reader.peekU32(offset + 12, le)
      stroff = reader.peekU32(offset + 16, le)
      strsize = reader.peekU32(offset + 20, le)
      symbolCount = nsyms
    }

    offset = cmdEnd
  }

  const entryPoint = entryOff === null ? 0 : textVmAddr + entryOff

  if (nsyms > 0 && symoff > 0 && stroff > 0 && strsize > 0) {
    readSymbols(data, reader, is64, le, symoff, nsyms, stroff, strsize, imports, exports)
  }

  return {
    sections,
    entryPoint,
    cputype,
    cpusubtype,
    filetype,
    flags,
    imports,
    exports,
    isDylib: filetype === MH_DYLIB,
    isExecutable: filetype === MH_EXECUTE,
    needed,
    pie: (flags & MH_PIE) !== 0,
    nx: (flags & MH_ALLOW_STACK_EXECUTION) === 0,
    symbolCount,
  }
}

function readSection(data: Uint8Array, reader: BufferReader, off: number, is64: boolean, le: boolean, prot: number): SectionInfo {
  const name = readCString(data, off, 16) || readCString(data, off + 16, 16)
  let addr = 0
  let size = 0
  let fileOff = 0
  if (is64) {
    addr = Number(reader.peekU64(off + 32, le))
    size = Number(reader.peekU64(off + 40, le))
    fileOff = reader.peekU32(off + 48, le)
  } else {
    addr = reader.peekU32(off + 32, le)
    size = reader.peekU32(off + 36, le)
    fileOff = reader.peekU32(off + 40, le)
  }
  const perms: string[] = []
  if (prot & 1) perms.push('READ')
  if (prot & 2) perms.push('WRITE')
  if (prot & 4) perms.push('EXEC')
  const raw = fileOff > 0 && fileOff < data.length ? Math.min(size, data.length - fileOff) : 0
  return {
    name: name || '__section',
    rva: addr,
    fileOffset: fileOff,
    size,
    entropy: raw > 0 ? sectionEntropy(data, fileOff, raw) : 0,
    permissions: perms.join('|') || 'UNKNOWN',
    alignment: 0,
  }
}

function readSymbols(
  data: Uint8Array,
  reader: BufferReader,
  is64: boolean,
  le: boolean,
  symoff: number,
  nsyms: number,
  stroff: number,
  strsize: number,
  imports: { module: string; name: string }[],
  exports: { name: string; address: number }[],
): void {
  const ent = is64 ? 16 : 12
  const count = Math.min(nsyms, MAX_SYMS)
  const seen = new Set<string>()
  for (let i = 0; i < count; i++) {
    const off = symoff + i * ent
    if (!reader.inBounds(off, ent)) break
    const strx = reader.peekU32(off, le)
    if (strx <= 0 || strx >= strsize) continue
    const name = readCString(data, stroff + strx, 512)
    if (!name || seen.has(name)) continue
    const ntype = reader.peekU8(off + 4)
    const nsect = reader.peekU8(off + 5)
    const value = is64 ? Number(reader.peekU64(off + 8, le)) : reader.peekU32(off + 8, le)
    const external = (ntype & 0x01) !== 0
    if (!external) continue
    seen.add(name)
    if (nsect === 0) {
      if (imports.length < MAX_SYMS) imports.push({ module: '', name })
    } else if ((ntype & 0x0e) === 0) {
      // N_UNDF already handled. Other defined externals are exports.
    }
    if (nsect !== 0 && exports.length < MAX_SYMS) exports.push({ name, address: value })
  }
}
