export function shannonEntropy(data: Uint8Array): number {
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
  const slice = data.slice(offset, offset + size)
  return shannonEntropy(slice)
}
