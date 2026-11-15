import type { PluginContext } from '../types/plugin.js'
import { containsAscii, findAsciiString } from '../utils/bytes.js'

export function textMarker(ctx: PluginContext, needle: string): string | null {
  return findAsciiString(ctx.raw, needle)
}

export function hasText(ctx: PluginContext, needle: string): boolean {
  return containsAscii(ctx.raw, needle)
}

export function hasSection(ctx: PluginContext, test: (name: string) => boolean): boolean {
  return ctx.sections.some(s => test(s.name))
}

export function linkedModules(ctx: PluginContext): string[] {
  const mods: string[] = []
  const elf = ctx.metadata.elfData as { needed?: string[] } | undefined
  const macho = ctx.metadata.machoData as { needed?: string[] } | undefined
  if (elf?.needed) mods.push(...elf.needed)
  if (macho?.needed) mods.push(...macho.needed)
  for (const imp of ctx.imports ?? []) {
    if (imp.module) mods.push(imp.module)
  }
  return mods
}

export function hasModule(ctx: PluginContext, pattern: RegExp): boolean {
  return linkedModules(ctx).some(mod => pattern.test(mod))
}

export function symbolSet(ctx: PluginContext): Set<string> {
  const names = new Set<string>()
  for (const imp of ctx.imports ?? []) if (imp.name) names.add(imp.name)
  for (const exp of ctx.exports ?? []) if (exp.name) names.add(exp.name)
  const elf = ctx.metadata.elfData as { symbols?: { name: string }[] } | undefined
  if (elf?.symbols) {
    for (const sym of elf.symbols) if (sym.name) names.add(sym.name)
  }
  return names
}

export function countNames(symbols: Set<string>, names: readonly string[]): number {
  let n = 0
  for (const name of names) if (symbols.has(name)) n++
  return n
}

/** True when a dynamic symbol or a standalone ASCII token is present. */
export function hasApi(ctx: PluginContext, symbols: Set<string>, name: string): boolean {
  if (symbols.has(name)) return true
  // Short tokens show up inside unrelated strings ("bind" inside "binding").
  if (name.length < 8) return false
  return hasText(ctx, name)
}
