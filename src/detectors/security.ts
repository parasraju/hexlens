import type { BinaryFormat, SecurityInfo } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { hasText, symbolSet } from './evidence.js'

export interface SecurityCheck {
  name: string
  enabled: boolean
}

const EMPTY: SecurityInfo = {
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

export function detectSecurity(ctx: PluginContext): SecurityInfo {
  const result: SecurityInfo = { ...EMPTY }

  if (ctx.format === 'PE' || ctx.format === '.NET') {
    const pe = ctx.metadata.peData as {
      dllCharacteristics?: number
      sections?: { permissions: string }[]
      hasCertificate?: boolean
      fileAlignment?: number
      auxFileEnd?: number
    } | undefined
    const flags = pe?.dllCharacteristics ?? 0
    result.aslr = (flags & 0x40) !== 0
    result.dep = (flags & 0x100) !== 0
    result.cfg = (flags & 0x4000) !== 0
    result.safeSEH = (flags & 0x400) !== 0
    result.nx = result.dep
    result.signed = Boolean(pe?.hasCertificate)
    result.overlay = trailingBytes(ctx, pe?.fileAlignment || 0x200, pe?.auxFileEnd || 0) > Math.max(pe?.fileAlignment || 0x200, 512)

    if (ctx.timestamp && ctx.timestamp > 0) {
      const ts = new Date(ctx.timestamp * 1000)
      const now = new Date()
      if (ts.getTime() > now.getTime() + 24 * 60 * 60 * 1000 || ts.getFullYear() < 1995) {
        result.timestampAnomaly = true
      }
    }
  }

  if (ctx.format === 'ELF') {
    const elf = ctx.metadata.elfData as {
      pie?: boolean
      nx?: boolean | null
      relro?: boolean
      fileCoverageEnd?: number
      type?: number
    } | undefined
    if (elf) {
      result.pie = Boolean(elf.pie)
      result.aslr = result.pie
      result.nx = elf.nx === true
      result.relro = Boolean(elf.relro)
      const covered = elf.fileCoverageEnd ?? 0
      const extra = ctx.raw.length - covered
      result.overlay = covered > 0 && extra > 512
    }
  }

  if (ctx.format === 'Mach-O') {
    const macho = ctx.metadata.machoData as { pie?: boolean; nx?: boolean; symbolCount?: number } | undefined
    if (macho) {
      result.pie = Boolean(macho.pie)
      result.aslr = result.pie
      result.nx = macho.nx !== false
    }
  }

  const symbols = symbolSet(ctx)
  if (symbols.has('__stack_chk_fail') || symbols.has('__security_check_cookie') || hasText(ctx, '__stack_chk_fail') || hasText(ctx, '__security_check_cookie')) {
    result.stackCanaries = true
  }

  return result
}

/** Mitigations that mean something for this format. Inapplicable checks are omitted. */
export function securityChecks(format: BinaryFormat | string, sec: SecurityInfo): SecurityCheck[] {
  if (format === 'PE' || format === '.NET') {
    return [
      { name: 'ASLR', enabled: sec.aslr },
      { name: 'DEP', enabled: sec.dep },
      { name: 'CFG', enabled: sec.cfg },
      { name: 'SafeSEH', enabled: sec.safeSEH },
      { name: 'Stack Canaries', enabled: sec.stackCanaries },
      { name: 'Signed', enabled: sec.signed },
      { name: 'Timestamp Anomaly', enabled: sec.timestampAnomaly },
      { name: 'Overlay', enabled: sec.overlay },
    ]
  }
  if (format === 'ELF') {
    return [
      { name: 'PIE', enabled: sec.pie },
      { name: 'ASLR', enabled: sec.aslr },
      { name: 'NX', enabled: sec.nx },
      { name: 'RELRO', enabled: sec.relro },
      { name: 'Stack Canaries', enabled: sec.stackCanaries },
      { name: 'Overlay', enabled: sec.overlay },
    ]
  }
  if (format === 'Mach-O') {
    return [
      { name: 'PIE', enabled: sec.pie },
      { name: 'ASLR', enabled: sec.aslr },
      { name: 'NX', enabled: sec.nx },
      { name: 'Stack Canaries', enabled: sec.stackCanaries },
    ]
  }
  return []
}

function trailingBytes(ctx: PluginContext, alignment: number, auxFileEnd = 0): number {
  let end = auxFileEnd
  for (const section of ctx.sections) {
    if (section.permissions.includes('UNINIT') || section.permissions.includes('NOBITS')) continue
    if (section.fileOffset <= 0 || section.size <= 0) continue
    end = Math.max(end, section.fileOffset + Math.min(section.size, ctx.raw.length))
  }
  if (end === 0) return 0
  const extra = ctx.raw.length - end
  if (extra <= 0) return 0
  // File alignment padding is not an overlay.
  if (alignment > 0 && extra < alignment) return 0
  return extra
}
