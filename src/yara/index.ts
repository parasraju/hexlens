import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import type {
  YaraWasmCompileError,
  YaraWasmModule,
  YaraWasmVector,
} from 'libyara-wasm'
import type { YaraMatch } from '../types/index.js'

let modulePromise: Promise<YaraWasmModule> | null = null

function loadModule(): Promise<YaraWasmModule> {
  if (!modulePromise) {
    modulePromise = import('libyara-wasm').then(module => module.default())
  }
  return modulePromise
}

function toArray<T>(vector: YaraWasmVector<T>): T[] {
  const items: T[] = []
  for (let i = 0; i < vector.size(); i++) items.push(vector.get(i))
  return items
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function compileErrors(errors: YaraWasmVector<YaraWasmCompileError>): YaraWasmCompileError[] {
  return toArray(errors).filter(error => !error.warning)
}

/**
 * A compiled YARA rule file, backed by libyara compiled to WebAssembly.
 *
 * Rule files are read and validated once, then matched against file contents
 * in memory. Includes are not supported by the WebAssembly build, so rules
 * must be self-contained.
 */
export class YaraScanner {
  private constructor(
    /** Absolute path of the loaded rule file. */
    readonly path: string,
    private readonly rules: string,
    private readonly module: YaraWasmModule,
  ) {}

  static async load(path: string): Promise<YaraScanner> {
    const rulesPath = resolve(path)

    let rules: string
    try {
      rules = await readFile(rulesPath, 'utf-8')
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code === 'ENOENT') throw new Error(`YARA rule file not found: ${rulesPath}`)
      throw new Error(`Cannot read YARA rule file ${rulesPath}: ${errorMessage(err)}`)
    }

    if (rules.trim().length === 0) {
      throw new Error(`YARA rule file is empty: ${rulesPath}`)
    }

    const module = await loadModule()
    let validation
    try {
      validation = module.run(new Uint8Array(0), rules)
    } catch (err) {
      throw new Error(`Cannot compile YARA rule file ${rulesPath}: ${errorMessage(err)}`)
    }

    const errors = compileErrors(validation.compileErrors)
    if (errors.length > 0) {
      const detail = errors.map(error => `line ${error.lineNumber}: ${error.message}`).join('; ')
      throw new Error(`Invalid YARA rule file ${rulesPath}: ${detail}`)
    }

    return new YaraScanner(rulesPath, rules, module)
  }

  /** Match a file's bytes against the loaded rules. */
  match(data: Uint8Array, file: string): YaraMatch[] {
    const result = this.module.run(data, this.rules)
    return toArray(result.matchedRules).map(rule => ({
      file,
      rule: rule.ruleName,
      meta: Object.fromEntries(toArray(rule.metadata).map(item => [item.identifier, item.data])),
      strings: toArray(rule.resolvedMatches).map(match => ({
        identifier: match.stringIdentifier,
        offset: match.location,
        length: match.matchLength,
      })),
    }))
  }
}
