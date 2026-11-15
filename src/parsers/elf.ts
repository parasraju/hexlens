import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import { readCString } from '../utils/bytes.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

export interface ELFSymbol {
  name: string
  address: number
  size: number
  type: string
}

export interface ELFData {
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: { name: string; address: number }[]
  entryPoint: number
  type: number
  machine: number
  timestamp: number
  isShared: boolean
  isExecutable: boolean
  symbols: ELFSymbol[]
  dynamic: Map<string, bigint>
  /** DT_NEEDED sonames. */
  needed: string[]
  /** PT_GNU_STACK is present and not executable. Null when the header is absent. */
  nx: boolean | null
  /** PT_GNU_RELRO is present. */
  relro: boolean
  /** DF_BIND_NOW / DF_1_NOW — full RELRO when relro is also set. */
  bindNow: boolean
  /** DF_1_PIE or ET_DYN. */
  pie: boolean
  hasSymtab: boolean
  /** Highest file offset covered by a segment, section, or the header tables. */
  fileCoverageEnd: number
}

const PT_LOAD = 1
const PT_DYNAMIC = 2
const PT_GNU_STACK = 0x6474e551
const PT_GNU_RELRO = 0x6474e552
const PF_X = 0x1
const SHT_PROGBITS = 1
const SHT_SYMTAB = 2
const SHT_STRTAB = 3
const SHT_DYNAMIC = 6
const SHT_NOBITS = 8
const SHT_DYNSYM = 11
const SHN_UNDEF = 0
const SHN_LORESERVE = 0xff00
const SHN_XINDEX = 0xffff
const STB_GLOBAL = 1
const STB_WEAK = 2
const STT_FUNC = 2
const DT_NULL = 0
const DT_NEEDED = 1
const DT_STRTAB = 5
const DT_SYMTAB = 6
const DT_STRSZ = 10
const DT_BIND_NOW = 24
const DT_FLAGS = 30
const DT_FLAGS_1 = 0x6ffffffb
const DF_BIND_NOW = 0x8
const DF_1_NOW = 0x1
const DF_1_PIE = 0x08000000
const ET_EXEC = 2
const ET_DYN = 3
const MAX_SECTIONS = 4096
const MAX_PHDRS = 256
const MAX_SYMBOLS = 8000
const MAX_IMPORTS = 8000

interface Shdr {
  nameOff: number
  type: number
  flags: number
  addr: number
  offset: number
  size: number
  link: number
  entsize: number
}

interface Phdr {
  type: number
  flags: number
  offset: number
  vaddr: number
  filesz: number
  memsz: number
}

const TAG_NAMES: Record<number, string> = {
  1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH',
  5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ',
  9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT', 12: 'INIT',
  13: 'FINI', 14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC',
  17: 'REL', 18: 'RELSZ', 19: 'RELENT', 21: 'PLTREL',
  23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY',
  26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ',
  30: 'FLAGS', 0x6ffffffb: 'FLAGS_1', 0x6ffffffe: 'VERNEED',
  0x6fffffff: 'VERNEEDNUM', 0x6ffffff0: 'VERSYM', 0x6ffffffa: 'RELACOUNT',
}

export function parseELF(data: Uint8Array): ELFData | null {
  try {
    return parseELFInner(data)
  } catch {
    return null
  }
}

function parseELFInner(data: Uint8Array): ELFData | null {
  if (data.length < 16) return null
  if (data[0] !== 0x7f || data[1] !== 0x45 || data[2] !== 0x4c || data[3] !== 0x46) return null

  const eiClass = data[4]
  const eiData = data[5]
  if ((eiClass !== 1 && eiClass !== 2) || (eiData !== 1 && eiData !== 2)) return null

  const is64 = eiClass === 2
  const le = eiData === 1
  const headerSize = is64 ? 64 : 52
  const reader = BufferReader.from(data)

  if (data.length < headerSize) return null

  // e_ident[16] | e_type u16 | e_machine u16 | e_version u32 | e_entry | e_phoff | e_shoff | ...
  const eType = reader.peekU16(16, le)
  const eMachine = reader.peekU16(18, le)

  let entry = 0
  let phoff = 0
  let shoff = 0
  let phentsize = 0
  let phnum = 0
  let shentsize = 0
  let shnum = 0
  let shstrndx = 0

  if (is64) {
    entry = Number(reader.peekU64(24, le))
    phoff = Number(reader.peekU64(32, le))
    shoff = Number(reader.peekU64(40, le))
    phentsize = reader.peekU16(54, le)
    phnum = reader.peekU16(56, le)
    shentsize = reader.peekU16(58, le)
    shnum = reader.peekU16(60, le)
    shstrndx = reader.peekU16(62, le)
  } else {
    entry = reader.peekU32(24, le)
    phoff = reader.peekU32(28, le)
    shoff = reader.peekU32(32, le)
    phentsize = reader.peekU16(42, le)
    phnum = reader.peekU16(44, le)
    shentsize = reader.peekU16(46, le)
    shnum = reader.peekU16(48, le)
    shstrndx = reader.peekU16(50, le)
  }

  const shdrSize = is64 ? 64 : 40
  if (shentsize !== 0 && shentsize < shdrSize) {
    shnum = 0
  }
  if (shnum > MAX_SECTIONS) shnum = MAX_SECTIONS
  if (phnum > MAX_PHDRS) phnum = MAX_PHDRS
  if (phentsize !== 0 && phentsize < (is64 ? 56 : 32)) phnum = 0

  // SHN_XINDEX / zero shnum live in the first section header.
  if (shoff > 0 && shentsize >= shdrSize && data.length >= shoff + shdrSize) {
    const first = readShdr(reader, shoff, is64, le)
    if (first) {
      if (shnum === 0 && first.size > 0 && first.size <= MAX_SECTIONS) shnum = first.size
      if (shstrndx === SHN_XINDEX && first.link < MAX_SECTIONS) shstrndx = first.link
    }
  }

  const shdrs: Shdr[] = []
  for (let i = 0; i < shnum; i++) {
    const off = shoff + i * shentsize
    const sh = readShdr(reader, off, is64, le)
    if (!sh) break
    shdrs.push(sh)
  }

  let strtabOff = 0
  if (shstrndx > 0 && shstrndx < shdrs.length) {
    const shstr = shdrs[shstrndx]
    if (shstr.type === SHT_STRTAB || shstr.offset > 0) strtabOff = shstr.offset
  }

  const sections: SectionInfo[] = []
  for (let i = 0; i < shdrs.length; i++) {
    const sh = shdrs[i]
    if (sh.size === 0 && sh.type !== SHT_NOBITS) continue
    const rawName = strtabOff > 0 ? readCString(data, strtabOff + sh.nameOff, 64) : ''
    const name = printable(rawName) || `.section_${i}`
    const perms: string[] = []
    if (sh.flags & 0x1) perms.push('WRITE')
    if (sh.flags & 0x2) perms.push('ALLOC')
    if (sh.flags & 0x4) perms.push('EXEC')
    if (sh.type === SHT_PROGBITS) perms.push('PROGBITS')
    if (sh.type === SHT_NOBITS) perms.push('NOBITS')

    const fileSize = sh.type === SHT_NOBITS ? 0 : sh.size
    const rawSpan = fileSize > 0 && sh.offset >= 0 && sh.offset < data.length
      ? Math.min(fileSize, data.length - sh.offset)
      : 0
    sections.push({
      name,
      rva: sh.addr,
      fileOffset: sh.offset,
      size: sh.size,
      entropy: rawSpan > 0 ? sectionEntropy(data, sh.offset, rawSpan) : 0,
      permissions: perms.join('|') || 'UNKNOWN',
      alignment: sh.entsize,
    })
  }

  const phdrs: Phdr[] = []
  const phSize = is64 ? 56 : 32
  for (let i = 0; i < phnum; i++) {
    const off = phoff + i * (phentsize || phSize)
    const ph = readPhdr(reader, off, is64, le)
    if (!ph) break
    phdrs.push(ph)
  }

  let nx: boolean | null = null
  let relro = false
  for (const ph of phdrs) {
    if (ph.type === PT_GNU_STACK) nx = (ph.flags & PF_X) === 0
    if (ph.type === PT_GNU_RELRO) relro = true
  }

  const dynamic = new Map<string, bigint>()
  const needed: string[] = []
  let bindNow = false
  let flags1 = 0n

  const dynPh = phdrs.find(p => p.type === PT_DYNAMIC && p.filesz > 0)
  const dynSh = shdrs.find(s => s.type === SHT_DYNAMIC && s.size > 0)
  const dynOff = dynPh?.offset ?? dynSh?.offset ?? -1
  const dynSize = dynPh?.filesz ?? dynSh?.size ?? 0
  if (dynOff >= 0 && dynSize > 0) {
    parseDynamic(data, reader, dynOff, dynSize, is64, le, dynamic)
    const flags = dynamic.get('FLAGS') ?? 0n
    flags1 = dynamic.get('FLAGS_1') ?? 0n
    bindNow = dynamic.has('BIND_NOW') || (flags & BigInt(DF_BIND_NOW)) !== 0n || (flags1 & BigInt(DF_1_NOW)) !== 0n
  }

  const strtabVa = dynamic.get('STRTAB')
  const strsz = Number(dynamic.get('STRSZ') ?? 0n)
  let dynStrOff: number | null = null
  if (dynSh && dynSh.link < shdrs.length) dynStrOff = shdrs[dynSh.link].offset
  if (dynStrOff === null && strtabVa !== undefined) dynStrOff = vaToOffset(phdrs, shdrs, Number(strtabVa))
  if (dynStrOff !== null && dynStrOff >= 0) {
    for (const [tag, val] of dynamic) {
      if (!tag.startsWith('NEEDED#')) continue
      if (strsz > 0 && Number(val) >= strsz) continue
      const name = printable(readCString(data, dynStrOff + Number(val), 256))
      if (name) needed.push(name)
    }
  }

  const imports: ImportInfo[] = []
  const exports: ExportInfo[] = []
  const symbols: ELFSymbol[] = []
  const seenImport = new Set<string>()

  const dynsym = shdrs.find(s => s.type === SHT_DYNSYM)
  const symtab = shdrs.find(s => s.type === SHT_SYMTAB)
  if (dynsym) collectSymbols(data, reader, is64, le, dynsym, shdrs, symbols, imports, exports, seenImport, true, !symtab)
  if (symtab) collectSymbols(data, reader, is64, le, symtab, shdrs, symbols, imports, exports, seenImport, false, true)

  let coverage = headerSize
  coverage = Math.max(coverage, phoff + phnum * (phentsize || 0))
  coverage = Math.max(coverage, shoff + shdrs.length * (shentsize || 0))
  for (const ph of phdrs) {
    if (ph.type === PT_LOAD || ph.filesz > 0) coverage = Math.max(coverage, ph.offset + ph.filesz)
  }
  for (const sh of shdrs) {
    if (sh.type === SHT_NOBITS || sh.size === 0) continue
    coverage = Math.max(coverage, sh.offset + sh.size)
  }
  if (coverage > data.length) coverage = data.length

  const pie = eType === ET_DYN || (flags1 & BigInt(DF_1_PIE)) !== 0n

  return {
    sections,
    imports,
    exports,
    entryPoint: entry,
    type: eType,
    machine: eMachine,
    timestamp: 0,
    isShared: eType === ET_DYN,
    isExecutable: eType === ET_EXEC || eType === ET_DYN,
    symbols,
    dynamic,
    needed,
    nx,
    relro,
    bindNow,
    pie,
    hasSymtab: Boolean(symtab),
    fileCoverageEnd: coverage,
  }
}

function readShdr(reader: BufferReader, off: number, is64: boolean, le: boolean): Shdr | null {
  const need = is64 ? 64 : 40
  if (!reader.inBounds(off, need)) return null
  if (is64) {
    return {
      nameOff: reader.peekU32(off, le),
      type: reader.peekU32(off + 4, le),
      flags: Number(reader.peekU64(off + 8, le)),
      addr: Number(reader.peekU64(off + 16, le)),
      offset: Number(reader.peekU64(off + 24, le)),
      size: Number(reader.peekU64(off + 32, le)),
      link: reader.peekU32(off + 40, le),
      entsize: Number(reader.peekU64(off + 56, le)),
    }
  }
  return {
    nameOff: reader.peekU32(off, le),
    type: reader.peekU32(off + 4, le),
    flags: reader.peekU32(off + 8, le),
    addr: reader.peekU32(off + 12, le),
    offset: reader.peekU32(off + 16, le),
    size: reader.peekU32(off + 20, le),
    link: reader.peekU32(off + 24, le),
    entsize: reader.peekU32(off + 36, le),
  }
}

function readPhdr(reader: BufferReader, off: number, is64: boolean, le: boolean): Phdr | null {
  if (is64) {
    if (!reader.inBounds(off, 56)) return null
    return {
      type: reader.peekU32(off, le),
      flags: reader.peekU32(off + 4, le),
      offset: Number(reader.peekU64(off + 8, le)),
      vaddr: Number(reader.peekU64(off + 16, le)),
      filesz: Number(reader.peekU64(off + 32, le)),
      memsz: Number(reader.peekU64(off + 40, le)),
    }
  }
  if (!reader.inBounds(off, 32)) return null
  return {
    type: reader.peekU32(off, le),
    offset: reader.peekU32(off + 4, le),
    vaddr: reader.peekU32(off + 8, le),
    filesz: reader.peekU32(off + 16, le),
    memsz: reader.peekU32(off + 20, le),
    flags: reader.peekU32(off + 24, le),
  }
}

function parseDynamic(
  data: Uint8Array,
  reader: BufferReader,
  offset: number,
  size: number,
  is64: boolean,
  le: boolean,
  map: Map<string, bigint>,
): void {
  const entrySize = is64 ? 16 : 8
  const end = Math.min(data.length, offset + size)
  let pos = offset
  let guard = 0
  while (pos + entrySize <= end && guard++ < 4096) {
    let tag: bigint
    let val: bigint
    if (is64) {
      tag = reader.peekU64(pos, le)
      val = reader.peekU64(pos + 8, le)
    } else {
      tag = BigInt(reader.peekU32(pos, le))
      val = BigInt(reader.peekU32(pos + 4, le))
    }
    if (tag === BigInt(DT_NULL)) break
    const tagNum = Number(tag)
    const name = TAG_NAMES[tagNum]
    if (name === 'NEEDED') {
      // Several DT_NEEDED entries share one tag name. Keep each value under a unique key
      // and also the canonical name pointing at the last one (callers use the NEEDED walk below).
      map.set(`NEEDED#${pos}`, val)
      map.set('NEEDED', val)
    } else if (name) {
      map.set(name, val)
    }
    if (tagNum === DT_BIND_NOW) map.set('BIND_NOW', 1n)
    if (tagNum === DT_STRTAB) map.set('STRTAB', val)
    if (tagNum === DT_SYMTAB) map.set('SYMTAB', val)
    if (tagNum === DT_STRSZ) map.set('STRSZ', val)
    if (tagNum === DT_FLAGS) map.set('FLAGS', val)
    if (tagNum === DT_FLAGS_1) map.set('FLAGS_1', val)
    pos += entrySize
  }
}

function vaToOffset(phdrs: Phdr[], shdrs: Shdr[], va: number): number | null {
  for (const ph of phdrs) {
    if (ph.type !== PT_LOAD || ph.filesz <= 0) continue
    if (va >= ph.vaddr && va < ph.vaddr + ph.filesz) return ph.offset + (va - ph.vaddr)
  }
  for (const sh of shdrs) {
    if (sh.size <= 0 || sh.type === SHT_NOBITS) continue
    if (va >= sh.addr && va < sh.addr + sh.size) return sh.offset + (va - sh.addr)
  }
  return null
}

function collectSymbols(
  data: Uint8Array,
  reader: BufferReader,
  is64: boolean,
  le: boolean,
  sym: Shdr,
  shdrs: Shdr[],
  symbols: ELFSymbol[],
  imports: ImportInfo[],
  exports: ExportInfo[],
  seenImport: Set<string>,
  fromDynsym: boolean,
  recordSymbols: boolean,
): void {
  const str = shdrs[sym.link]
  if (!str || str.offset < 0) return
  const entsize = sym.entsize > 0 ? sym.entsize : (is64 ? 24 : 16)
  const minEnt = is64 ? 24 : 16
  if (entsize < minEnt || sym.offset < 0 || sym.size <= 0) return
  const count = Math.min(Math.floor(sym.size / entsize), MAX_SYMBOLS)
  for (let i = 0; i < count; i++) {
    const off = sym.offset + i * entsize
    if (!reader.inBounds(off, minEnt)) break
    let nameOff = 0
    let info = 0
    let shndx = 0
    let value = 0
    let size = 0
    if (is64) {
      nameOff = reader.peekU32(off, le)
      info = reader.peekU8(off + 4)
      shndx = reader.peekU16(off + 6, le)
      value = Number(reader.peekU64(off + 8, le))
      size = Number(reader.peekU64(off + 16, le))
    } else {
      nameOff = reader.peekU32(off, le)
      value = reader.peekU32(off + 4, le)
      size = reader.peekU32(off + 8, le)
      info = reader.peekU8(off + 12)
      shndx = reader.peekU16(off + 14, le)
    }
    const name = readCString(data, str.offset + nameOff, 512)
    if (!name) continue
    const bind = info >> 4
    const typ = info & 0xf
    const typeName = typ === STT_FUNC ? 'FUNC' : typ === 1 ? 'OBJECT' : typ === 0 ? 'NOTYPE' : 'OTHER'
    if (recordSymbols && symbols.length < MAX_SYMBOLS && (typ === STT_FUNC || typ === 1 || fromDynsym)) {
      symbols.push({ name, address: value, size, type: typeName })
    }
    const globalish = bind === STB_GLOBAL || bind === STB_WEAK
    if (!globalish) continue
    if (shndx === SHN_UNDEF && fromDynsym && !seenImport.has(name) && imports.length < MAX_IMPORTS) {
      seenImport.add(name)
      imports.push({ module: '', name, address: value })
    } else if (shndx !== SHN_UNDEF && shndx < SHN_LORESERVE && typ === STT_FUNC && exports.length < MAX_IMPORTS) {
      if (!exports.some(e => e.name === name)) exports.push({ name, address: value })
    }
  }
}

function printable(name: string): string {
  if (!name) return ''
  if (!/^[\x20-\x7e]+$/.test(name)) return ''
  return name
}
