import type { SecurityInfo } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

export function detectSecurity(ctx: PluginContext): SecurityInfo {
  const result: SecurityInfo = {
    aslr: false,
    dep: false,
    cfg: false,
    nx: false,
    pie: false,
    relro: false,
    stackCanaries: false,
    safeSEH: false,
    signed: false,
    certificateValid: null,
    timestampAnomaly: false,
    overlay: false,
  }

  if (ctx.format === 'PE' || ctx.format === '.NET') {
    const pe = ctx.metadata.peData as any
    if (pe) {
      result.aslr = pe.dllCharacteristics ? (pe.dllCharacteristics & 0x40) !== 0 : false
      result.dep = pe.dllCharacteristics ? (pe.dllCharacteristics & 0x100) !== 0 : false
      result.cfg = pe.dllCharacteristics ? (pe.dllCharacteristics & 0x4000) !== 0 : false
      result.safeSEH = pe.dllCharacteristics ? (pe.dllCharacteristics & 0x400) !== 0 : false

      if (pe.sections) {
        for (const s of pe.sections) {
          if (s.permissions.includes('EXEC') && !s.permissions.includes('WRITE')) {
            result.nx = true
          }
        }
      }
    }

    if (ctx.timestamp && ctx.timestamp > 0) {
      const ts = new Date(ctx.timestamp * 1000)
      const now = new Date()
      if (ts > now || ts.getFullYear() < 2000) {
        result.timestampAnomaly = true
      }
    }
  }

  if (ctx.format === 'ELF') {
    const elf = ctx.metadata.elfData as any
    if (elf) {
      if (elf.type === 3) result.pie = true
      if (elf.sections) {
        for (const s of elf.sections) {
          if (s.name === '.got.plt' || s.name === '.dynamic') result.relro = true
        }
      }
      if (ctx.sections?.some(s => s.permissions.includes('EXEC') && !s.permissions.includes('WRITE'))) {
        result.nx = true
      }
    }
  }

  if (ctx.strings?.some(s => /__stack_chk_fail|__security_check_cookie|stack_chk/i.test(s.value))) {
    result.stackCanaries = true
  }

  if (ctx.strings?.some(s => s.value.includes('DigitalSignature') || s.value.includes('PKCS7') || s.value.includes('signed'))) {
    result.signed = true
  }

  const lastSection = ctx.sections?.[ctx.sections.length - 1]
  if (lastSection && ctx.raw) {
    const rawEnd = lastSection.fileOffset + lastSection.size
    if (rawEnd < (ctx.raw as Uint8Array).length - 100) {
      result.overlay = true
    }
  }

  return result
}
