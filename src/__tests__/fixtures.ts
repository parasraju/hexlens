export function buildDEX(): Uint8Array {
  const buf = new Uint8Array(0x200)
  const v = new DataView(buf.buffer)

  buf.set([0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00], 0)

  v.setUint32(0x20, buf.length, true)
  v.setUint32(0x24, 0x70, true)
  v.setUint32(0x28, 0x12345678, true)

  v.setUint32(0x38, 3, true)
  v.setUint32(0x3C, 0x70, true)
  v.setUint32(0x40, 2, true)
  v.setUint32(0x44, 0x7C, true)
  v.setUint32(0x48, 0, true)
  v.setUint32(0x4C, 0x7C, true)
  v.setUint32(0x50, 0, true)
  v.setUint32(0x54, 0x7C, true)
  v.setUint32(0x58, 1, true)
  v.setUint32(0x5C, 0xB4, true)
  v.setUint32(0x60, 1, true)
  v.setUint32(0x64, 0xBC, true)
  v.setUint32(0x68, 0, true)
  v.setUint32(0x6C, 0xDC, true)

  const enc = new TextEncoder()

  v.setUint32(0x70, 0x84, true)
  v.setUint32(0x74, 0x98, true)
  v.setUint32(0x78, 0xAC, true)

  v.setUint32(0x7C, 0, true)
  v.setUint32(0x80, 1, true)

  const writeString = (s: string, at: number): void => {
    const bytes = enc.encode(s)
    buf[at] = bytes.length
    buf.set(bytes, at + 1)
  }
  writeString('Lcom/example/Foo;', 0x84)
  writeString('Ljava/lang/Object;', 0x98)
  writeString('bar', 0xAC)

  v.setUint16(0xB4, 1, true)
  v.setUint16(0xB6, 0, true)
  v.setUint32(0xB8, 2, true)

  v.setUint32(0xBC, 0, true)
  v.setUint32(0xC0, 1, true)
  v.setUint32(0xC4, 1, true)
  v.setUint32(0xC8, 0, true)
  v.setUint32(0xCC, 0, true)
  v.setUint32(0xD0, 0, true)
  v.setUint32(0xD4, 0, true)

  return buf
}

export function buildDotNet(): Uint8Array {
  const buf = new Uint8Array(0x4000)
  const v = new DataView(buf.buffer)
  const peOff = 0x80

  buf[0] = 0x4D; buf[1] = 0x5A
  v.setUint32(0x3C, peOff, true)

  buf.set([0x50, 0x45, 0x00, 0x00], peOff)
  v.setUint16(peOff + 4, 0x14C, true)
  v.setUint16(peOff + 6, 1, true)
  v.setUint32(peOff + 8, 0x60000000, true)
  v.setUint16(peOff + 20, 0xE0, true)
  v.setUint16(peOff + 22, 0x0102, true)

  v.setUint16(peOff + 24, 0x10B, true)
  v.setUint32(peOff + 40, 0x1000, true)
  v.setUint32(peOff + 44, 0x400000, true)
  v.setUint32(peOff + 48, 0x1000, true)
  v.setUint32(peOff + 52, 0x200, true)
  v.setUint32(peOff + 80, 0x3000, true)
  v.setUint32(peOff + 84, 0x40, true)
  v.setUint16(peOff + 92, 3, true)
  v.setUint16(peOff + 94, 0x0040, true)
  v.setUint32(peOff + 120, 16, true)

  const dataDirStart = peOff + 24 + 96
  v.setUint32(dataDirStart + 14 * 8, 0x2000, true)
  v.setUint32(dataDirStart + 14 * 8 + 4, 0x48, true)

  const sectionTable = peOff + 24 + 0xE0
  buf.set(enc('.text'), sectionTable)
  v.setUint32(sectionTable + 8, 0x3000, true)
  v.setUint32(sectionTable + 12, 0x1000, true)
  v.setUint32(sectionTable + 16, 0x3000, true)
  v.setUint32(sectionTable + 20, 0x1000, true)
  v.setUint32(sectionTable + 36, 0x60000020, true)

  const comOff = 0x2000
  v.setUint32(comOff, 72, true)
  v.setUint16(comOff + 4, 2, true)
  v.setUint16(comOff + 6, 5, true)
  v.setUint32(comOff + 8, 0x3000, true)
  v.setUint32(comOff + 12, 0x100, true)
  v.setUint32(comOff + 16, 0, true)
  v.setUint32(comOff + 20, 0x06000001, true)

  const metaOff = 0x3000
  v.setUint32(metaOff, 0x424A5342, true)
  v.setUint16(metaOff + 4, 1, true)
  v.setUint16(metaOff + 6, 1, true)
  v.setUint32(metaOff + 12, 12, true)
  buf.set(enc('v4.0.30319\0'), metaOff + 16)
  v.setUint16(metaOff + 28, 0, true)
  v.setUint16(metaOff + 30, 2, true)

  const stream1 = metaOff + 32
  v.setUint32(stream1, 0x40, true)
  v.setUint32(stream1 + 4, 0x40, true)
  buf.set(enc('#Strings\0'), stream1 + 8)

  const stream2 = stream1 + 20
  v.setUint32(stream2, 0x80, true)
  v.setUint32(stream2 + 4, 0x80, true)
  buf.set(enc('#~\0'), stream2 + 8)

  const stringsOff = metaOff + 0x40
  buf[stringsOff] = 0
  buf.set(enc('MyApp'), stringsOff + 1)
  buf[stringsOff + 6] = 0
  buf.set(enc('Program'), stringsOff + 7)
  buf[stringsOff + 14] = 0
  buf.set(enc('Foo'), stringsOff + 15)
  buf[stringsOff + 18] = 0
  buf.set(enc('Bar'), stringsOff + 19)
  buf[stringsOff + 22] = 0
  buf.set(enc('System'), stringsOff + 23)
  buf[stringsOff + 29] = 0
  buf.set(enc('Object'), stringsOff + 30)
  buf[stringsOff + 36] = 0

  const tablesOff = metaOff + 0x80
  v.setUint16(tablesOff + 6, 0, true)
  buf.set([0x43, 0, 0, 0, 1, 0, 0, 0], tablesOff + 8)
  v.setUint32(tablesOff + 24, 1, true)
  v.setUint32(tablesOff + 28, 2, true)
  v.setUint32(tablesOff + 32, 2, true)
  v.setUint32(tablesOff + 36, 1, true)

  let row = tablesOff + 40
  v.setUint16(row, 0, true)
  v.setUint16(row + 2, 1, true)
  v.setUint16(row + 4, 0, true)
  v.setUint16(row + 6, 0, true)
  v.setUint16(row + 8, 0, true)
  row += 10

  v.setUint16(row, 0, true)
  v.setUint16(row + 2, 30, true)
  v.setUint16(row + 4, 23, true)
  row += 6
  v.setUint16(row, 0, true)
  v.setUint16(row + 2, 19, true)
  v.setUint16(row + 4, 15, true)
  row += 6

  v.setUint32(row, 0x1000, true)
  v.setUint16(row + 4, 0, true)
  v.setUint16(row + 6, 0x0086, true)
  v.setUint16(row + 8, 7, true)
  v.setUint16(row + 10, 0, true)
  v.setUint16(row + 12, 0, true)
  row += 14
  v.setUint32(row, 0x1010, true)
  v.setUint16(row + 4, 0, true)
  v.setUint16(row + 6, 0, true)
  v.setUint16(row + 8, 15, true)
  v.setUint16(row + 10, 0, true)
  v.setUint16(row + 12, 0, true)
  row += 14

  v.setUint32(row, 0x8004, true)
  v.setUint16(row + 4, 4, true)
  v.setUint16(row + 6, 0, true)
  v.setUint16(row + 8, 0, true)
  v.setUint16(row + 10, 0, true)
  v.setUint32(row + 12, 0, true)
  v.setUint16(row + 16, 0, true)
  v.setUint16(row + 18, 1, true)
  v.setUint16(row + 20, 0, true)

  return buf
}

function enc(s: string): number[] {
  return Array.from(new TextEncoder().encode(s))
}
