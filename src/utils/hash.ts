import { createHash } from 'node:crypto'

export function sha256(data: Buffer | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex')
}

export function sha1(data: Buffer | Uint8Array): string {
  return createHash('sha1').update(data).digest('hex')
}

export function md5(data: Buffer | Uint8Array): string {
  return createHash('md5').update(data).digest('hex')
}

export function hashes(data: Buffer | Uint8Array): { sha256: string; sha1: string; md5: string } {
  return {
    sha256: sha256(data),
    sha1: sha1(data),
    md5: md5(data),
  }
}

export function computeImphash(imports: { module: string; name: string }[]): string {
  const list: string[] = []
  for (const imp of imports) {
    if (!imp.name) continue
    list.push(`${imp.module.toLowerCase()}.${imp.name.toLowerCase()}`)
  }
  if (list.length === 0) return ''
  list.sort()
  return md5(Buffer.from(list.join(',')))
}
