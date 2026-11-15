/**
 * Bounds-checked cursor over an ArrayBuffer view.
 * Reads that would leave the view return zero / empty instead of throwing,
 * so parsers can stop and return whatever they have already decoded.
 */
export class BufferReader {
  private view: DataView
  private _offset: number = 0
  private byteOffset: number
  private byteLength: number

  constructor(private buffer: ArrayBufferLike, byteOffset = 0, byteLength?: number) {
    const available = Math.max(0, buffer.byteLength - byteOffset)
    this.byteOffset = Math.max(0, byteOffset)
    this.byteLength = Math.max(0, Math.min(byteLength ?? available, available))
    this.view = new DataView(buffer as ArrayBuffer, this.byteOffset, this.byteLength)
  }

  static from(data: Uint8Array): BufferReader {
    return new BufferReader(data.buffer, data.byteOffset, data.byteLength)
  }

  get offset(): number {
    return this._offset
  }

  get length(): number {
    return this.byteLength
  }

  get remaining(): number {
    return Math.max(0, this.byteLength - this._offset)
  }

  inBounds(offset: number, size: number): boolean {
    return Number.isFinite(offset) && Number.isFinite(size)
      && offset >= 0 && size >= 0
      && offset + size <= this.byteLength
  }

  seek(offset: number): void {
    if (!Number.isFinite(offset) || offset < 0) {
      this._offset = 0
      return
    }
    this._offset = offset
  }

  skip(bytes: number): void {
    if (!Number.isFinite(bytes) || bytes <= 0) return
    this._offset += bytes
  }

  private take(size: number): boolean {
    if (!this.inBounds(this._offset, size)) {
      this._offset = this.byteLength
      return false
    }
    return true
  }

  readU8(): number {
    if (!this.take(1)) return 0
    const v = this.view.getUint8(this._offset)
    this._offset += 1
    return v
  }

  readU16(littleEndian = true): number {
    if (!this.take(2)) return 0
    const v = this.view.getUint16(this._offset, littleEndian)
    this._offset += 2
    return v
  }

  readU32(littleEndian = true): number {
    if (!this.take(4)) return 0
    const v = this.view.getUint32(this._offset, littleEndian)
    this._offset += 4
    return v
  }

  readU64(littleEndian = true): bigint {
    if (!this.take(8)) return 0n
    const v = this.view.getBigUint64(this._offset, littleEndian)
    this._offset += 8
    return v
  }

  readI32(littleEndian = true): number {
    if (!this.take(4)) return 0
    const v = this.view.getInt32(this._offset, littleEndian)
    this._offset += 4
    return v
  }

  readBytes(length: number): Uint8Array {
    if (!Number.isFinite(length) || length <= 0) return new Uint8Array(0)
    const available = Math.max(0, this.byteLength - this._offset)
    const n = Math.min(length, available)
    if (n === 0 || this._offset < 0) {
      this._offset = this.byteLength
      return new Uint8Array(0)
    }
    const v = new Uint8Array(this.buffer, this.byteOffset + this._offset, n)
    this._offset += n
    return v
  }

  readString(length: number, encoding: 'ascii' | 'utf16' = 'ascii'): string {
    const bytes = this.readBytes(length)
    if (encoding === 'utf16') {
      let s = ''
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const c = bytes[i] | (bytes[i + 1] << 8)
        if (c === 0) break
        s += String.fromCharCode(c)
      }
      return s
    }
    let s = ''
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) break
      s += String.fromCharCode(bytes[i])
    }
    return s
  }

  readCString(maxLength = 256): string {
    let s = ''
    const limit = Math.min(maxLength, this.remaining)
    for (let i = 0; i < limit; i++) {
      const c = this.readU8()
      if (c === 0) break
      s += String.fromCharCode(c)
    }
    return s
  }

  readCStringAt(offset: number, maxLength = 256): string {
    if (!this.inBounds(offset, 1)) return ''
    const saved = this._offset
    this._offset = offset
    const result = this.readCString(maxLength)
    this._offset = saved
    return result
  }

  peekU8(offset: number): number {
    if (!this.inBounds(offset, 1)) return 0
    return this.view.getUint8(offset)
  }

  peekU16(offset: number, littleEndian = true): number {
    if (!this.inBounds(offset, 2)) return 0
    return this.view.getUint16(offset, littleEndian)
  }

  peekU32(offset: number, littleEndian = true): number {
    if (!this.inBounds(offset, 4)) return 0
    return this.view.getUint32(offset, littleEndian)
  }

  peekU64(offset: number, littleEndian = true): bigint {
    if (!this.inBounds(offset, 8)) return 0n
    return this.view.getBigUint64(offset, littleEndian)
  }

  slice(offset: number, length: number): Uint8Array {
    if (!Number.isFinite(offset) || !Number.isFinite(length) || offset < 0 || offset >= this.byteLength || length <= 0) {
      return new Uint8Array(0)
    }
    const n = Math.min(length, this.byteLength - offset)
    return new Uint8Array(this.buffer, this.byteOffset + offset, n)
  }

  hex(offset: number, length: number): string {
    const bytes = this.slice(offset, length)
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }
}
