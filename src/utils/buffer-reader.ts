export class BufferReader {
  private view: DataView
  private _offset: number = 0
  private byteOffset: number
  private byteLength: number

  constructor(private buffer: ArrayBufferLike, byteOffset = 0, byteLength?: number) {
    this.byteOffset = byteOffset
    this.byteLength = byteLength ?? buffer.byteLength - byteOffset
    this.view = new DataView(buffer as ArrayBuffer, byteOffset, this.byteLength)
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
    return this.byteLength - this._offset
  }

  seek(offset: number): void {
    this._offset = offset
  }

  skip(bytes: number): void {
    this._offset += bytes
  }

  readU8(): number {
    const v = this.view.getUint8(this._offset)
    this._offset += 1
    return v
  }

  readU16(littleEndian = true): number {
    const v = this.view.getUint16(this._offset, littleEndian)
    this._offset += 2
    return v
  }

  readU32(littleEndian = true): number {
    const v = this.view.getUint32(this._offset, littleEndian)
    this._offset += 4
    return v
  }

  readU64(littleEndian = true): bigint {
    const v = this.view.getBigUint64(this._offset, littleEndian)
    this._offset += 8
    return v
  }

  readI32(littleEndian = true): number {
    const v = this.view.getInt32(this._offset, littleEndian)
    this._offset += 4
    return v
  }

  readBytes(length: number): Uint8Array {
    const v = new Uint8Array(this.buffer, this.byteOffset + this._offset, length)
    this._offset += length
    return v
  }

  readString(length: number, encoding: 'ascii' | 'utf16' = 'ascii'): string {
    const bytes = this.readBytes(length)
    if (encoding === 'utf16') {
      let s = ''
      for (let i = 0; i < bytes.length; i += 2) {
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
    for (let i = 0; i < maxLength; i++) {
      const c = this.readU8()
      if (c === 0) break
      s += String.fromCharCode(c)
    }
    return s
  }

  readCStringAt(offset: number, maxLength = 256): string {
    const saved = this._offset
    this._offset = offset
    const result = this.readCString(maxLength)
    this._offset = saved
    return result
  }

  peekU8(offset: number): number {
    return this.view.getUint8(offset)
  }

  peekU16(offset: number, littleEndian = true): number {
    return this.view.getUint16(offset, littleEndian)
  }

  peekU32(offset: number, littleEndian = true): number {
    return this.view.getUint32(offset, littleEndian)
  }

  slice(offset: number, length: number): Uint8Array {
    const absOffset = this.byteOffset + offset
    return new Uint8Array(this.buffer, absOffset, length)
  }

  hex(offset: number, length: number): string {
    const bytes = this.slice(offset, length)
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }
}
