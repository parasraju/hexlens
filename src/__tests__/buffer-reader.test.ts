import { describe, it, expect } from 'vitest'
import { BufferReader } from '../utils/buffer-reader.js'

describe('BufferReader', () => {
  it('creates from Uint8Array', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04])
    const reader = BufferReader.from(data)
    expect(reader.offset).toBe(0)
    expect(reader.length).toBe(4)
    expect(reader.remaining).toBe(4)
  })

  it('creates from a slice of a larger buffer', () => {
    const full = new Uint8Array([0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00])
    const slice = full.subarray(2, 6)
    const reader = BufferReader.from(slice)
    expect(reader.length).toBe(4)
    expect(reader.remaining).toBe(4)
  })

  it('readU8 advances offset', () => {
    const data = new Uint8Array([0xAB, 0xCD])
    const reader = BufferReader.from(data)
    expect(reader.readU8()).toBe(0xAB)
    expect(reader.offset).toBe(1)
    expect(reader.readU8()).toBe(0xCD)
    expect(reader.offset).toBe(2)
  })

  it('readU16 little endian', () => {
    const data = new Uint8Array([0x34, 0x12])
    const reader = BufferReader.from(data)
    expect(reader.readU16(true)).toBe(0x1234)
  })

  it('readU16 big endian', () => {
    const data = new Uint8Array([0x12, 0x34])
    const reader = BufferReader.from(data)
    expect(reader.readU16(false)).toBe(0x1234)
  })

  it('readU32 little endian', () => {
    const data = new Uint8Array([0x78, 0x56, 0x34, 0x12])
    const reader = BufferReader.from(data)
    expect(reader.readU32(true)).toBe(0x12345678)
  })

  it('readU32 big endian', () => {
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78])
    const reader = BufferReader.from(data)
    expect(reader.readU32(false)).toBe(0x12345678)
  })

  it('readBytes returns slice', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])
    const reader = BufferReader.from(data)
    const slice = reader.readBytes(3)
    expect(slice).toEqual(new Uint8Array([0x01, 0x02, 0x03]))
    expect(reader.offset).toBe(3)
  })

  it('readBytes works on view into shared buffer', () => {
    const full = new Uint8Array([0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x00])
    const slice = full.subarray(2, 5)
    const reader = BufferReader.from(slice)
    const bytes = reader.readBytes(3)
    expect(bytes).toEqual(new Uint8Array([0x0A, 0x0B, 0x0C]))
  })

  it('readString ASCII', () => {
    const data = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0xFF])
    const reader = BufferReader.from(data)
    expect(reader.readString(5)).toBe('Hello')
  })

  it('readString UTF-16', () => {
    const data = new Uint8Array([0x48, 0x00, 0x69, 0x00])
    const reader = BufferReader.from(data)
    expect(reader.readString(4, 'utf16')).toBe('Hi')
  })

  it('readCString reads null-terminated', () => {
    const data = new Uint8Array([0x41, 0x42, 0x43, 0x00, 0xFF])
    const reader = BufferReader.from(data)
    expect(reader.readCString(10)).toBe('ABC')
    expect(reader.offset).toBe(4)
  })

  it('readCStringAt reads at offset without moving cursor', () => {
    const data = new Uint8Array([0xFF, 0x41, 0x42, 0x00, 0xFF])
    const reader = BufferReader.from(data)
    reader.seek(4)
    expect(reader.readCStringAt(1, 10)).toBe('AB')
    expect(reader.offset).toBe(4)
  })

  it('seek and skip work correctly', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04])
    const reader = BufferReader.from(data)
    reader.seek(2)
    expect(reader.offset).toBe(2)
    reader.skip(1)
    expect(reader.offset).toBe(3)
  })

  it('peekU32 reads without moving offset', () => {
    const data = new Uint8Array([0x78, 0x56, 0x34, 0x12, 0xFF])
    const reader = BufferReader.from(data)
    expect(reader.peekU32(0, true)).toBe(0x12345678)
    expect(reader.offset).toBe(0)
  })

  it('slice returns correct subarray', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])
    const reader = BufferReader.from(data)
    const s = reader.slice(1, 3)
    expect(s).toEqual(new Uint8Array([0x02, 0x03, 0x04]))
  })

  it('hex formats bytes correctly', () => {
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF])
    const reader = BufferReader.from(data)
    expect(reader.hex(0, 4)).toBe('deadbeef')
  })

  it('remaining decreases as offset increases', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05])
    const reader = BufferReader.from(data)
    expect(reader.remaining).toBe(5)
    reader.readU8()
    expect(reader.remaining).toBe(4)
    reader.readU16()
    expect(reader.remaining).toBe(2)
  })

  it('handles empty buffer', () => {
    const data = new Uint8Array(0)
    const reader = BufferReader.from(data)
    expect(reader.length).toBe(0)
    expect(reader.remaining).toBe(0)
  })
})
