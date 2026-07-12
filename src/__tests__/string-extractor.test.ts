import { describe, it, expect } from 'vitest'
import { extractStrings } from '../detectors/string-extractor.js'

describe('extractStrings', () => {
  it('extracts ASCII strings from data', () => {
    const data = new Uint8Array([
      0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
      0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00,
    ])
    const strings = extractStrings(data, 4)
    expect(strings.length).toBe(2)
    expect(strings[0].value).toBe('Hello')
    expect(strings[0].type).toBe('ASCII')
    expect(strings[1].value).toBe('World')
    expect(strings[1].type).toBe('ASCII')
  })

  it('returns empty for no strings', () => {
    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03])
    const strings = extractStrings(data, 4)
    expect(strings.length).toBe(0)
  })

  it('classifies URLs', () => {
    const data = new TextEncoder().encode('prefix https://example.com/path suffix')
    const strings = extractStrings(data, 4)
    expect(strings.some(s => s.type === 'URL' && s.value.includes('https://example.com'))).toBe(true)
  })

  it('classifies domains', () => {
    const data = new TextEncoder().encode('visit example.com now')
    const strings = extractStrings(data, 4)
    expect(strings.some(s => s.type === 'Domain' && s.value.includes('example.com'))).toBe(true)
  })

  it('classifies IP addresses', () => {
    const data = new TextEncoder().encode('192.168.1.1')
    const strings = extractStrings(data, 4)
    expect(strings.some(s => s.type === 'IPv4')).toBe(true)
  })

  it('classifies file paths', () => {
    const data = new TextEncoder().encode('path C:\\Users\\test\\file.txt here')
    const strings = extractStrings(data, 4)
    expect(strings.some(s => s.type === 'FilePath')).toBe(true)
  })

  it('deduplicates strings', () => {
    const data = new TextEncoder().encode('hellohellohello')
    const strings = extractStrings(data, 4)
    const helloStrings = strings.filter(s => s.value === 'hellohellohello')
    expect(helloStrings.length).toBe(1)
  })
})
