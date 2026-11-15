export function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0
  const freq = new Array<number>(256).fill(0)
  for (let i = 0; i < data.length; i++) {
    freq[data[i]]++
  }
  let entropy = 0
  const len = data.length
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len
      entropy -= p * Math.log2(p)
    }
  }
  return Math.round(entropy * 100) / 100
}

export function sectionEntropy(data: Uint8Array, offset: number, size: number): number {
  if (!Number.isFinite(offset) || !Number.isFinite(size) || offset < 0 || size <= 0 || offset >= data.length) {
    return 0
  }
  const end = Math.min(data.length, offset + size)
  if (end <= offset) return 0
  return shannonEntropy(data.subarray(offset, end))
}
