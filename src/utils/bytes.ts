/** Views and ASCII searches that never throw on short or shared buffers. */

export function asBuffer(data: Uint8Array): Buffer {
  if (Buffer.isBuffer(data)) return data
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

function windows(buf: Buffer): Buffer[] {
  const limit = 8 * 1024 * 1024
  if (buf.length <= limit) return [buf]
  const edge = 2 * 1024 * 1024
  return [buf.subarray(0, edge), buf.subarray(buf.length - edge)]
}

export function containsAscii(data: Uint8Array, needle: string): boolean {
  if (!needle) return false
  const buf = asBuffer(data)
  const n = Buffer.from(needle, 'latin1')
  return windows(buf).some(w => w.includes(n))
}

/** The C string that contains `needle`, or null when the marker is absent. */
export function findAsciiString(data: Uint8Array, needle: string, maxLen = 160): string | null {
  if (!needle) return null
  const buf = asBuffer(data)
  const n = Buffer.from(needle, 'latin1')
  for (const w of windows(buf)) {
    const at = w.indexOf(n)
    if (at < 0) continue
    let end = at
    const limit = Math.min(w.length, at + maxLen)
    while (end < limit) {
      const c = w[end]
      if (c === 0 || c < 0x09 || c > 0x7e) break
      end++
    }
    return w.subarray(at, end).toString('latin1')
  }
  return null
}

export function readCString(data: Uint8Array, offset: number, maxLength = 256): string {
  if (!Number.isFinite(offset) || offset < 0 || offset >= data.length) return ''
  const start = offset
  const limit = Math.min(data.length, start + maxLength)
  let end = start
  while (end < limit && data[end] !== 0) end++
  if (end === start) return ''
  return asBuffer(data).subarray(start, end).toString('utf8')
}
