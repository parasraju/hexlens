import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import { analyze } from '../analyze.js'
import { diff } from '../diff/index.js'
import { scan } from '../scan/index.js'
import type { ScanSummary } from '../scan/index.js'
import type {
  BinaryReport,
  McpAnalyzeResult,
  McpDiffResult,
  McpScanResult,
} from '../types/index.js'
import { VERSION } from '../version.js'
import { YaraScanner } from '../yara/index.js'

const analyzeInput = {
  path: z.string().describe('Path to the binary file'),
  yaraRules: z.string().optional().describe('Path to a YARA rule file'),
}

const scanInput = {
  target: z.string().describe('File or directory to scan. Defaults to the current directory.').default('.'),
}

const diffInput = {
  fileA: z.string().describe('Path to the first file'),
  fileB: z.string().describe('Path to the second file'),
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function errnoCode(err: unknown): string | undefined {
  if (typeof err !== 'object' || err === null || !('code' in err)) return undefined
  return typeof err.code === 'string' ? err.code : undefined
}

function publicError(path: string, err: unknown): string {
  const code = errnoCode(err)
  if (code === 'ENOENT') return `file not found: ${path}`
  if (code === 'EACCES' || code === 'EPERM') return `file not readable: ${path}`
  if (err instanceof Error && err.message.length > 0) return err.message
  return `cannot read ${path}`
}

function imphashOf(metadata: Record<string, unknown>): string | null {
  return typeof metadata.imphash === 'string' ? metadata.imphash : null
}

function detectedName(item: { name: string } | null): string | null {
  return item ? item.name : null
}

function unrecognizedMessage(report: BinaryReport, path: string): string {
  const note = report.metadata.note
  const detail = typeof note === 'string' ? note : 'Not a recognized binary.'
  return `${detail} File: ${path}`
}

function jsonResult(data: unknown): CallToolResult {
  const text = JSON.stringify(data)
  const parsed: unknown = JSON.parse(text)
  if (!isRecord(parsed)) {
    return {
      isError: true,
      content: [{ type: 'text', text: 'MCP result was not a JSON object' }],
    }
  }
  return {
    content: [{ type: 'text', text }],
    structuredContent: parsed,
  }
}

function errorResult(message: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: message }],
  }
}

async function runTool(work: () => Promise<unknown>): Promise<CallToolResult> {
  try {
    return jsonResult(await work())
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return errorResult(message)
  }
}

async function analyzeForTool(path: string, yaraRules?: string): Promise<McpAnalyzeResult> {
  const resolved = resolve(path)
  const rulesPath = yaraRules === undefined ? undefined : resolve(yaraRules)
  try {
    const scanner = rulesPath === undefined ? null : await YaraScanner.load(rulesPath)
    const report = await analyze(resolved)
    if (report.format === 'Unknown') throw new Error(unrecognizedMessage(report, resolved))
    if (!scanner) return report
    const yaraMatches = scanner.match(await readFile(resolved), resolved)
    return { ...report, yaraMatches }
  } catch (err) {
    throw new Error(publicError(resolved, err))
  }
}

function summarizeScan(summary: ScanSummary): McpScanResult {
  return {
    root: summary.root,
    skipped: summary.skipped,
    errors: summary.errors.map(error => ({ path: error.path, message: error.message })),
    durationMs: summary.durationMs,
    files: summary.files.map(file => ({
      path: file.path,
      relativePath: file.relativePath,
      format: file.report.format,
      architecture: file.report.architecture,
      size: file.report.file.size,
      sha256: file.report.file.sha256,
      imphash: imphashOf(file.report.metadata),
      compiler: detectedName(file.report.compiler),
      packer: detectedName(file.report.packer),
      language: detectedName(file.report.language),
      risk: file.risk,
      flags: file.flags.map(flag => ({
        code: flag.code,
        label: flag.label,
        severity: flag.severity,
      })),
    })),
  }
}

async function scanForTool(target: string): Promise<McpScanResult> {
  const resolved = resolve(target)
  try {
    return summarizeScan(await scan(resolved))
  } catch (err) {
    throw new Error(publicError(resolved, err))
  }
}

async function diffForTool(fileA: string, fileB: string): Promise<McpDiffResult> {
  const resolvedA = resolve(fileA)
  const resolvedB = resolve(fileB)
  try {
    return await diff(resolvedA, resolvedB)
  } catch (err) {
    throw new Error(publicError(resolvedA, err))
  }
}

function createHexlensMcpServer(): McpServer {
  const server = new McpServer({ name: 'hexlens', version: VERSION })

  server.registerTool(
    'hexlens_analyze',
    {
      description: 'Analyze one binary and return the HexLens report as JSON, including format, compiler, packer, language, sections, imports, exports, strings, and imphash. Pass yaraRules to include YARA matches.',
      inputSchema: analyzeInput,
      annotations: { readOnlyHint: true },
    },
    async ({ path, yaraRules }) => runTool(() => analyzeForTool(path, yaraRules)),
  )

  server.registerTool(
    'hexlens_scan',
    {
      description: 'Scan a file or directory and return a per-file summary of each recognized binary.',
      inputSchema: scanInput,
      annotations: { readOnlyHint: true },
    },
    async ({ target }) => runTool(() => scanForTool(target)),
  )

  server.registerTool(
    'hexlens_diff',
    {
      description: 'Compare two files and return byte stats plus report-level added, removed, and changed entries.',
      inputSchema: diffInput,
      annotations: { readOnlyHint: true },
    },
    async ({ fileA, fileB }) => runTool(() => diffForTool(fileA, fileB)),
  )

  return server
}

export async function startMcpServer(): Promise<void> {
  const server = createHexlensMcpServer()
  const transport = new StdioServerTransport()
  await server.connect(transport)
}
