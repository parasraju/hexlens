export interface FunctionInfo {
  name: string
  address: number
  estimatedSize: number
  type: 'entry' | 'main' | 'constructor' | 'destructor' | 'exception' | 'init' | 'thread' | 'unknown'
}

export function discoverFunctions(
  entryPoint: number,
  imports: { name: string; module: string }[],
  exports: { name: string; address: number }[],
  strings: { value: string; offset: number }[],
): FunctionInfo[] {
  const functions: FunctionInfo[] = []

  functions.push({
    name: 'entry_point',
    address: entryPoint,
    estimatedSize: 16,
    type: 'entry',
  })

  if (strings.some(s => s.value === 'main' || s.value === '_main' || s.value === 'mainCRTStartup')) {
    functions.push({
      name: 'main',
      address: 0,
      estimatedSize: 64,
      type: 'main',
    })
  }

  if (strings.some(s => s.value.includes('__init') || /\.init_array/.test(s.value))) {
    functions.push({
      name: '_init',
      address: 0,
      estimatedSize: 32,
      type: 'init',
    })
  }

  if (strings.some(s => s.value.includes('__cxa_atexit') || s.value.includes('__cxa_finalize'))) {
    functions.push({
      name: '__cxa_atexit',
      address: 0,
      estimatedSize: 16,
      type: 'destructor',
    })
  }

  if (strings.some(s => /exception|__CxxFrameHandler/i.test(s.value))) {
    functions.push({
      name: '__CxxFrameHandler',
      address: 0,
      estimatedSize: 32,
      type: 'exception',
    })
  }

  const threadStrs = strings.filter(s => /CreateThread|pthread_create|BeginThread/i.test(s.value))
  if (threadStrs.length > 0) {
    functions.push({
      name: 'thread_entry',
      address: threadStrs[0].offset,
      estimatedSize: 64,
      type: 'thread',
    })
  }

  for (const exp of exports) {
    if (!functions.some(f => f.name === exp.name)) {
      functions.push({
        name: exp.name,
        address: exp.address,
        estimatedSize: 32,
        type: 'unknown',
      })
    }
  }

  return functions
}
