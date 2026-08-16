import { BufferReader } from '../utils/buffer-reader.js'
import { sectionEntropy } from '../utils/entropy.js'
import type { SectionInfo, ImportInfo, ExportInfo } from '../types/index.js'

export interface DEXData {
  version: string
  checksum: number
  fileSize: number
  stringCount: number
  typeCount: number
  protoCount: number
  fieldCount: number
  methodCount: number
  classCount: number
  classes: string[]
  methods: { className: string; name: string }[]
  strings: string[]
  sections: SectionInfo[]
  imports: ImportInfo[]
  exports: ExportInfo[]
}

const MAX_ITEMS = 50000

export function parseDEX(data: Uint8Array): DEXData | null {
  if (data.length < 0x70) return null
  if (data[0] !== 0x64 || data[1] !== 0x65 || data[2] !== 0x78 || data[3] !== 0x0A) return null

  const reader = BufferReader.from(data)

  const version = String.fromCharCode(data[4], data[5], data[6])
  const checksum = reader.peekU32(0x08, true)
  const fileSize = reader.peekU32(0x20, true)
  const headerSize = reader.peekU32(0x24, true)

  const stringIdsSize = reader.peekU32(0x38, true)
  const stringIdsOff = reader.peekU32(0x3C, true)
  const typeIdsSize = reader.peekU32(0x40, true)
  const typeIdsOff = reader.peekU32(0x44, true)
  const protoIdsSize = reader.peekU32(0x48, true)
  const protoIdsOff = reader.peekU32(0x4C, true)
  const fieldIdsSize = reader.peekU32(0x50, true)
  const fieldIdsOff = reader.peekU32(0x54, true)
  const methodIdsSize = reader.peekU32(0x58, true)
  const methodIdsOff = reader.peekU32(0x5C, true)
  const classDefsSize = reader.peekU32(0x60, true)
  const classDefsOff = reader.peekU32(0x64, true)

  const strings: string[] = []
  const maxStrings = Math.min(stringIdsSize, MAX_ITEMS)
  for (let i = 0; i < maxStrings; i++) {
    const off = stringIdsOff + i * 4
    if (off + 4 > data.length) break
    const strOff = reader.peekU32(off, true)
    strings.push(strOff < data.length ? readMUTF8(data, strOff) : '')
  }

  const typeNames: string[] = []
  const maxTypes = Math.min(typeIdsSize, MAX_ITEMS)
  for (let i = 0; i < maxTypes; i++) {
    const off = typeIdsOff + i * 4
    if (off + 4 > data.length) break
    const descIdx = reader.peekU32(off, true)
    typeNames.push(strings[descIdx] || `type_${i}`)
  }

  const methods: { className: string; name: string }[] = []
  const maxMethods = Math.min(methodIdsSize, MAX_ITEMS)
  for (let i = 0; i < maxMethods; i++) {
    const off = methodIdsOff + i * 8
    if (off + 8 > data.length) break
    const classIdx = reader.peekU16(off, true)
    const nameIdx = reader.peekU32(off + 4, true)
    methods.push({
      className: typeNames[classIdx] || `class_${classIdx}`,
      name: strings[nameIdx] || `method_${i}`,
    })
  }

  const classes: string[] = []
  const maxClasses = Math.min(classDefsSize, MAX_ITEMS)
  for (let i = 0; i < maxClasses; i++) {
    const off = classDefsOff + i * 32
    if (off + 32 > data.length) break
    const classIdx = reader.peekU32(off, true)
    classes.push(typeNames[classIdx] || `class_${classIdx}`)
  }

  const definedSet = new Set(classes)

  const imports: ImportInfo[] = []
  const seenImports = new Set<string>()
  for (const m of methods) {
    if (definedSet.has(m.className)) continue
    const key = `${m.className}!${m.name}`
    if (seenImports.has(key)) continue
    seenImports.add(key)
    imports.push({ module: m.className, name: m.name })
    if (imports.length >= MAX_ITEMS) break
  }

  const exports: ExportInfo[] = classes.map((c, i) => ({ name: c, address: i, ordinal: i }))
  const methodExports: ExportInfo[] = []
  const seenExports = new Set<string>()
  for (const m of methods) {
    if (!definedSet.has(m.className)) continue
    const key = `${m.className}!${m.name}`
    if (seenExports.has(key)) continue
    seenExports.add(key)
    methodExports.push({ name: `${m.className}.${m.name}`, address: methodExports.length, ordinal: methodExports.length })
    if (methodExports.length >= MAX_ITEMS) break
  }

  const sections = buildSections(data, reader, {
    headerSize,
    stringIdsSize, stringIdsOff,
    typeIdsSize, typeIdsOff,
    protoIdsSize, protoIdsOff,
    fieldIdsSize, fieldIdsOff,
    methodIdsSize, methodIdsOff,
    classDefsSize, classDefsOff,
  })

  return {
    version,
    checksum,
    fileSize,
    stringCount: stringIdsSize,
    typeCount: typeIdsSize,
    protoCount: protoIdsSize,
    fieldCount: fieldIdsSize,
    methodCount: methodIdsSize,
    classCount: classDefsSize,
    classes,
    methods: methods.slice(0, MAX_ITEMS),
    strings: strings.slice(0, 5000),
    sections,
    imports,
    exports: [...exports, ...methodExports].slice(0, MAX_ITEMS),
  }
}

function buildSections(data: Uint8Array, reader: BufferReader, counts: Record<string, number>): SectionInfo[] {
  const mk = (name: string, off: number, size: number, perms = 'R', align = 4): SectionInfo => ({
    name,
    rva: off,
    fileOffset: off,
    size,
    entropy: off + size <= data.length && size > 0 ? sectionEntropy(data, off, Math.min(size, data.length - off)) : 0,
    permissions: perms,
    alignment: align,
  })

  const sections: SectionInfo[] = [
    mk('header', 0, counts.headerSize, 'R', 4),
    mk('string_ids', counts.stringIdsOff, counts.stringIdsSize * 4),
    mk('type_ids', counts.typeIdsOff, counts.typeIdsSize * 4),
    mk('proto_ids', counts.protoIdsOff, counts.protoIdsSize * 12),
    mk('field_ids', counts.fieldIdsOff, counts.fieldIdsSize * 8),
    mk('method_ids', counts.methodIdsOff, counts.methodIdsSize * 8),
    mk('class_defs', counts.classDefsOff, counts.classDefsSize * 32, 'R', 4),
    mk('data', reader.peekU32(0x6C, true), reader.peekU32(0x68, true)),
  ]

  return sections.filter(s => s.size > 0 && s.fileOffset < data.length)
}

function readMUTF8(data: Uint8Array, offset: number): string {
  let p = offset
  let b = data[p]
  while (p < data.length && (b & 0x80) !== 0) {
    p++
    b = data[p]
  }
  p++
  const start = p
  while (p < data.length && data[p] !== 0) p++
  try {
    return new TextDecoder('utf-8').decode(data.slice(start, p))
  } catch {
    return ''
  }
}
