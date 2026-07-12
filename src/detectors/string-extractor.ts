import type { StringInfo } from '../types/index.js'

const ASCII_MIN = 4
const IPV4_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
const DOMAIN_RE = /\b[a-zA-Z0-9][a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/
const URL_RE = /\b(?:https?|ftp|ws):\/\/[^\s"'<>]+/
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
const FILEPATH_RE = /[a-zA-Z]:\\(?:[^\\])+/
const REGPATH_RE = /[A-Z]+\\(?:[A-Z]+\\(?:[^\\])+)/
const UA_RE = /(?:Mozilla|Chrome|Safari|Firefox|Edge|Opera)\/[\d.]+/
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

const MAX_SCAN_SIZE = 5 * 1024 * 1024

export function extractStrings(data: Uint8Array, minLength = 4): StringInfo[] {
  const strings: StringInfo[] = []
  const seen = new Set<string>()

  if (data.length > MAX_SCAN_SIZE * 2) {
    const head = data.slice(0, MAX_SCAN_SIZE)
    const tail = data.slice(data.length - MAX_SCAN_SIZE)
    const mid = data.slice(
      Math.floor(data.length / 2) - Math.floor(MAX_SCAN_SIZE / 2),
      Math.floor(data.length / 2) + Math.floor(MAX_SCAN_SIZE / 2)
    )
    extractASCIIStrings(head, minLength, strings, seen)
    extractASCIIStrings(tail, minLength, strings, seen)
    extractASCIIStrings(mid, minLength, strings, seen)
  } else {
    extractASCIIStrings(data, minLength, strings, seen)
  }

  if (data.length <= MAX_SCAN_SIZE) {
    extractUTF16Strings(data, minLength, strings, seen)
  }

  return strings
}

function extractASCIIStrings(data: Uint8Array, minLength: number, result: StringInfo[], seen: Set<string>): void {
  const decoder = new TextDecoder('ascii', { fatal: false })
  let start = -1
  for (let i = 0; i < data.length; i++) {
    const c = data[i]
    if (c >= 0x20 && c <= 0x7E) {
      if (start === -1) start = i
    } else {
      if (start !== -1) {
        const len = i - start
        if (len >= minLength) {
          const s = decoder.decode(data.slice(start, i))
          addString(s, start, 'ASCII', result, seen)
        }
        start = -1
      }
    }
  }
  if (start !== -1) {
    const len = data.length - start
    if (len >= minLength) {
      const s = decoder.decode(data.slice(start))
      addString(s, start, 'ASCII', result, seen)
    }
  }

  for (const s of result) {
    classifyString(s)
  }
}

function extractUTF16Strings(data: Uint8Array, minLength: number, result: StringInfo[], seen: Set<string>): void {
  let start = -1
  for (let i = 0; i < data.length - 1; i += 2) {
    const c = data[i] | (data[i + 1] << 8)
    if (c >= 0x20 && c <= 0x7E && data[i + 1] === 0) {
      if (start === -1) start = i
    } else {
      if (start !== -1) {
        const len = (i - start) / 2
        if (len >= minLength) {
          let s = ''
          for (let j = start; j < i; j += 2) {
            s += String.fromCharCode(data[j] | (data[j + 1] << 8))
          }
          if (!seen.has(s)) {
            seen.add(s)
            result.push({ value: s, type: 'UTF-16', offset: start })
          }
        }
        start = -1
      }
    }
  }
}

function addString(s: string, offset: number, type: StringInfo['type'], result: StringInfo[], seen: Set<string>): void {
  if (s.length < 4) return
  if (seen.has(s)) return
  seen.add(s)
  result.push({ value: s, type, offset })
}

function classifyString(si: StringInfo): void {
  const { value } = si
  if (!value) return

  if (URL_RE.test(value)) {
    si.type = 'URL'
    return
  }

  const charCount = value.replace(/[^a-zA-Z0-9.-]/g, '').length
  if (charCount >= 4 && DOMAIN_RE.test(value) && value.includes('.')) {
    const parts = value.split('.')
    if (parts.length >= 2 && parts[parts.length - 1].length >= 2) {
      si.type = 'Domain'
    }
  }

  if (IPV4_RE.test(value)) {
    si.type = 'IPv4'
  }

  if (FILEPATH_RE.test(value) && (value.includes('\\') || value.startsWith('/'))) {
    si.type = 'FilePath'
  }

  if (REGPATH_RE.test(value) && value.includes('\\')) {
    si.type = 'RegistryPath'
  }

  if (UA_RE.test(value)) {
    si.type = 'UserAgent'
  }

  if (value.length > 20 && BASE64_RE.test(value)) {
    si.type = 'Base64'
  }
}


