import { createHash } from 'node:crypto'
import type { BinaryReport, YaraMatch } from '../types/index.js'

const NAMESPACE = '6f0e2a1c-4b7d-4e58-9c3a-1d8e5f0a2b47'

interface IocList {
  sha256: string
  md5: string
  sha1: string
  imphash: string | null
  urls: string[]
  ips: string[]
  imports: string[]
  yara_matches: string[]
}

export function toIOC(
  report: BinaryReport,
  yaraMatches?: readonly YaraMatch[] | null,
  pretty = true,
): string {
  return JSON.stringify(iocList(report, yaraMatches), null, pretty ? 2 : undefined)
}

export function toSTIX(
  report: BinaryReport,
  yaraMatches?: readonly YaraMatch[] | null,
  pretty = true,
  createdAt = new Date(),
): string {
  const list = iocList(report, yaraMatches)
  const created = createdAt.toISOString()
  const filePattern = [
    `file:hashes.'SHA-256' = '${stixString(list.sha256)}'`,
    `file:hashes.MD5 = '${stixString(list.md5)}'`,
    `file:hashes.'SHA-1' = '${stixString(list.sha1)}'`,
  ].join(' AND ')
  const fileObservation = `[${filePattern}]`
  const shaObservation = `[file:hashes.'SHA-256' = '${stixString(list.sha256)}']`

  const objects: Record<string, unknown>[] = [
    {
      type: 'file',
      spec_version: '2.1',
      id: stixId('file', list.sha256),
      name: report.file.name,
      size: report.file.size,
      hashes: {
        'SHA-256': list.sha256,
        MD5: list.md5,
        'SHA-1': list.sha1,
      },
    },
    indicator(report.file.name, fileObservation, created, list.imphash ? `imphash ${list.imphash}` : undefined),
  ]

  for (const ip of list.ips) {
    objects.push({
      type: 'ipv4-addr',
      spec_version: '2.1',
      id: stixId('ipv4-addr', ip),
      value: ip,
    })
    objects.push(indicator(ip, `${shaObservation} AND [ipv4-addr:value = '${stixString(ip)}']`, created))
  }

  for (const url of list.urls) {
    objects.push({
      type: 'url',
      spec_version: '2.1',
      id: stixId('url', url),
      value: url,
    })
    objects.push(indicator(url, `${shaObservation} AND [url:value = '${stixString(url)}']`, created))
  }

  for (const name of list.imports) {
    objects.push(indicator(name, shaObservation, created, `Import ${name}`))
  }

  for (const rule of list.yara_matches) {
    objects.push(indicator(rule, shaObservation, created, `YARA rule ${rule}`))
  }

  return JSON.stringify({
    type: 'bundle',
    id: stixId('bundle', bundleMaterial(list)),
    spec_version: '2.1',
    objects,
  }, null, pretty ? 2 : undefined)
}

function iocList(report: BinaryReport, yaraMatches?: readonly YaraMatch[] | null): IocList {
  const urls: string[] = []
  const ips: string[] = []
  for (const item of report.strings) {
    if (item.type === 'URL') urls.push(...urlsIn(item.value))
    if (item.type === 'IPv4') ips.push(...ipv4sIn(item.value))
  }
  const imphash = report.metadata.imphash
  return {
    sha256: report.file.sha256,
    md5: report.file.md5,
    sha1: report.file.sha1,
    imphash: typeof imphash === 'string' && imphash.length > 0 ? imphash : null,
    urls: unique(urls),
    ips: unique(ips),
    imports: unique(report.imports.map(item => item.name).filter(name => name.length > 0)),
    yara_matches: unique((yaraMatches ?? []).map(match => match.rule).filter(rule => rule.length > 0)),
  }
}

function indicator(name: string, pattern: string, created: string, description?: string): Record<string, unknown> {
  const object: Record<string, unknown> = {
    type: 'indicator',
    spec_version: '2.1',
    id: stixId('indicator', `${name}|${pattern}`),
    created,
    modified: created,
    name,
    pattern,
    pattern_type: 'stix',
    pattern_version: '2.1',
    valid_from: created,
  }
  if (description) object.description = description
  return object
}

function bundleMaterial(list: IocList): string {
  return [
    list.sha256,
    list.md5,
    list.sha1,
    list.imphash ?? '',
    list.urls.join('\n'),
    list.ips.join('\n'),
    list.imports.join('\n'),
    list.yara_matches.join('\n'),
  ].join('\0')
}

function urlsIn(value: string): string[] {
  return value.match(/\b(?:https?|ftp|ws):\/\/[^\s"'<>]+/g) ?? []
}

function ipv4sIn(value: string): string[] {
  const found: string[] = []
  for (const match of value.matchAll(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g)) {
    const parts = [match[1]!, match[2]!, match[3]!, match[4]!]
    const valid = parts.every(part => {
      if (part.length > 1 && part.startsWith('0')) return false
      const octet = Number(part)
      return octet >= 0 && octet <= 255
    })
    if (valid) found.push(parts.join('.'))
  }
  return found
}

function unique(values: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const value of values) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function stixString(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
}

function stixId(type: string, material: string): string {
  return `${type}--${uuidv5(`${type}|${material}`)}`
}

function uuidv5(name: string): string {
  const namespace = Buffer.from(NAMESPACE.replace(/-/g, ''), 'hex')
  const hash = createHash('sha1').update(namespace).update(name, 'utf8').digest()
  const bytes = Buffer.from(hash.subarray(0, 16))
  bytes[6] = (bytes[6]! & 0x0f) | 0x50
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
