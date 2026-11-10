declare module 'libyara-wasm' {
  export interface YaraWasmVector<T> {
    size(): number
    get(index: number): T
  }

  export interface YaraWasmCompileError {
    message: string
    lineNumber: number
    warning: boolean
  }

  export interface YaraWasmResolvedMatch {
    location: number
    matchLength: number
    data: string
    stringIdentifier: string
    dataLength: number
  }

  export interface YaraWasmMeta {
    identifier: string
    data: string
  }

  export interface YaraWasmMatchedRule {
    ruleName: string
    resolvedMatches: YaraWasmVector<YaraWasmResolvedMatch>
    metadata: YaraWasmVector<YaraWasmMeta>
  }

  export interface YaraWasmRunResult {
    matchedRules: YaraWasmVector<YaraWasmMatchedRule>
    compileErrors: YaraWasmVector<YaraWasmCompileError>
    consoleLogs: YaraWasmVector<string>
  }

  export interface YaraWasmModule {
    run(data: Uint8Array, rules: string): YaraWasmRunResult
  }

  const factory: () => Promise<YaraWasmModule>
  export default factory
}
