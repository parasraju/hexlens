import type { BinaryFormat, Architecture, OperatingSystem, Endianness } from '../types/index.js'

export function detectFormat(data: Uint8Array): { format: BinaryFormat; endianness: Endianness } {
  if (data.length < 4) return { format: 'Unknown', endianness: 'little' }

  if (data[0] === 0x4D && data[1] === 0x5A) {
    const peOffset = new DataView(data.buffer, data.byteOffset + 0x3C, 4).getUint32(0, true)
    if (peOffset + 4 <= data.length) {
      const peSig = data[peOffset] === 0x50 && data[peOffset + 1] === 0x45
      if (peSig) return { format: 'PE', endianness: 'little' }
    }
    return { format: 'PE', endianness: 'little' }
  }

  if (data[0] === 0x7F && data[1] === 0x45 && data[2] === 0x4C && data[3] === 0x46) {
    const eiData = data[5]
    return { format: 'ELF', endianness: eiData === 1 ? 'little' : 'big' }
  }

  if (data[0] === 0xCF && data[1] === 0xFA && data[2] === 0xED && data[3] === 0xFE) {
    return { format: 'Mach-O', endianness: 'little' }
  }
  if (data[0] === 0xCE && data[1] === 0xFA && data[2] === 0xED && data[3] === 0xFE) {
    return { format: 'Mach-O', endianness: 'little' }
  }
  if (data[0] === 0xCA && data[1] === 0xFE && data[2] === 0xBA && data[3] === 0xBE) {
    return { format: 'Mach-O', endianness: 'big' }
  }
  if (data[0] === 0xCA && data[1] === 0xFE && data[2] === 0xBE && data[3] === 0xBA) {
    return { format: 'Mach-O', endianness: 'big' } // fat binary
  }

  if (data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6D) {
    return { format: 'WASM', endianness: 'little' }
  }

  return { format: 'Unknown', endianness: 'little' }
}

export function detectArchitecture(data: Uint8Array, format: BinaryFormat): Architecture {
  if (format === 'PE') {
    if (data.length < 0x3C + 4 + 4 + 2) return 'Unknown'
    const peOffset = new DataView(data.buffer, data.byteOffset + 0x3C, 4).getUint32(0, true)
    const machine = new DataView(data.buffer, data.byteOffset + peOffset + 4, 2).getUint16(0, true)
    switch (machine) {
      case 0x014C: return 'x86'
      case 0x8664: return 'x64'
      case 0x01C4: return 'ARM'
      case 0xAA64: return 'ARM64'
      case 0x01F0: return 'PowerPC'
      case 0x0200: return 'MIPS'
      case 0x5032: return 'RISC-V'
      default: return 'Unknown'
    }
  }

  if (format === 'ELF') {
    const eiClass = data[4]
    const eMachine = new DataView(data.buffer, data.byteOffset + 18, 2).getUint16(0, data[5] === 1)
    switch (eMachine) {
      case 3: return 'x86'
      case 0x3E: return 'x64'
      case 0x28: return 'ARM'
      case 0xB7: return 'ARM64'
      case 0x14: return 'PowerPC'
      case 0x15: return 'PowerPC'
      case 8: return 'MIPS'
      case 0xF3: return 'RISC-V'
      default: return 'Unknown'
    }
  }

  if (format === 'Mach-O') {
    const cputype = new DataView(data.buffer, data.byteOffset + 4, 4).getInt32(0, true)
    switch (cputype) {
      case 7: return 'x86'
      case 0x01000007: return 'x64'
      case 12: return 'ARM'
      case 0x0100000C: return 'ARM64'
      default: return 'Unknown'
    }
  }

  return 'Unknown'
}

export function detectOS(format: BinaryFormat): OperatingSystem {
  switch (format) {
    case 'PE': return 'Windows'
    case 'ELF': return 'Linux'
    case 'Mach-O': return 'macOS'
    case 'WASM': return 'Unknown'
    default: return 'Unknown'
  }
}
