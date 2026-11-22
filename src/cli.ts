#!/usr/bin/env node
import { Command } from 'commander'
import { analyze, diffOrExit, scan } from './index.js'
import { startMcpServer } from './mcp/index.js'
import { runTUI } from './tui.js'
import { toJSON, toMarkdown, toTerminal, toHTML, toSARIF, toYAML, toCSV, toIOC, toSTIX, toDiffJSON, toDiffTerminal } from './reporters/index.js'
import { formatYaraMatches } from './reporters/terminal.js'
import { formatScan } from './reporters/scan.js'
import { YaraScanner } from './yara/index.js'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { VERSION } from './version.js'

const program = new Command()

program
  .name('hexlens')
  .description('Binary Intelligence & Reverse Engineering Framework')
  .version(VERSION)

program
  .command('analyze')
  .description('Analyze a binary file')
  .argument('<file>', 'Path to the binary file')
  .option('-f, --format <format>', 'Output format', 'terminal')
  .option('-o, --output <file>', 'Output file path')
  .option('--yara <file>', 'YARA rule file to match the binary against')
  .option('--pretty', 'Pretty-print JSON', true)
  .action(async (file: string, options: { format: string; output?: string; yara?: string; pretty: boolean }) => {
    try {
      const scanner = options.yara ? await YaraScanner.load(options.yara) : null
      console.log('Analyzing binary...')
      const resolved = resolve(file)
      const report = await analyze(resolved)
      const yaraMatches = scanner
        ? scanner.match(await readFile(resolved), resolved)
        : null

      if (options.format === 'ioc' || options.format === 'stix') {
        if (report.format === 'Unknown') {
          const note = typeof report.metadata.note === 'string'
            ? report.metadata.note
            : 'Not a recognized binary.'
          throw new Error(`${note} File: ${resolved}`)
        }
        if (report.metadata.truncated === true) {
          throw new Error(`Truncated or malformed header. Not enough of the file is present to parse program headers or sections. File: ${resolved}`)
        }
      }

      let output: string
      switch (options.format) {
        case 'json':
          output = toJSON(report, options.pretty)
          break
        case 'markdown':
        case 'md':
          output = toMarkdown(report)
          break
        case 'html':
          output = toHTML(report)
          break
        case 'sarif':
          output = toSARIF(report)
          break
        case 'yaml':
        case 'yml':
          output = toYAML(report)
          break
        case 'csv':
          output = toCSV(report)
          break
        case 'ioc':
          output = toIOC(report, yaraMatches, options.pretty)
          break
        case 'stix':
          output = toSTIX(report, yaraMatches, options.pretty)
          break
        case 'terminal':
        default:
          output = toTerminal(report)
          break
      }

      if (yaraMatches) {
        if (options.format === 'json') {
          const parsed = JSON.parse(output) as Record<string, unknown>
          parsed.yaraMatches = yaraMatches
          output = JSON.stringify(parsed, null, options.pretty ? 2 : undefined)
        } else if (options.format === 'terminal') {
          output += formatYaraMatches(yaraMatches)
        }
      }

      if (options.output) {
        await writeFile(resolve(options.output), output, 'utf-8')
        console.log(`Report saved to ${options.output}`)
      } else {
        console.log(output)
      }
    } catch (err) {
      console.error('Analysis failed:', err instanceof Error ? err.message : err)
      process.exit(1)
    }
  })

program
  .command('scan')
  .description('Scan a file or folder and summarize every binary in a triage table')
  .argument('<path>', 'File or directory to scan')
  .option('-f, --format <format>', 'Output format (terminal, json, markdown, html, sarif, yaml, csv)', 'terminal')
  .option('-o, --output <file>', 'Output file path')
  .option('--all', 'Include files with unrecognized formats')
  .option('--no-recursive', 'Only scan files directly inside the directory')
  .option('--hidden', 'Include hidden files and directories')
  .option('--yara <file>', 'YARA rule file to match every scanned file against')
  .option('--pretty', 'Pretty-print JSON', true)
  .action(async (path: string, options: { format: string; output?: string; all?: boolean; recursive: boolean; hidden?: boolean; yara?: string; pretty: boolean }) => {
    try {
      process.stderr.write(`Scanning ${path}...\n`)
      const summary = await scan(resolve(path), {
        recursive: options.recursive,
        includeUnknown: options.all,
        includeHidden: options.hidden,
        yara: options.yara,
      })

      const output = formatScan(summary, options.format, {
        pretty: options.pretty,
        color: !options.output && Boolean(process.stdout.isTTY),
      })

      if (options.output) {
        await writeFile(resolve(options.output), output, 'utf-8')
        console.log(`Report saved to ${options.output}`)
      } else {
        console.log(output)
      }
    } catch (err) {
      console.error('Scan failed:', err instanceof Error ? err.message : err)
      process.exit(1)
    }
  })

program
  .command('diff')
  .description('Compare two binaries (byte diff and report diff)')
  .argument('<file-a>', 'Path to the first binary')
  .argument('<file-b>', 'Path to the second binary')
  .option('-f, --format <format>', 'Output format (terminal, json)', 'terminal')
  .option('-o, --output <file>', 'Output file path')
  .option('--pretty', 'Pretty-print JSON', true)
  .action(async (fileA: string, fileB: string, options: { format: string; output?: string; pretty: boolean }) => {
    if (options.format !== 'terminal' && options.format !== 'json') {
      console.error(`Diff failed: unsupported format "${options.format}" (supported: terminal, json)`)
      process.exit(2)
    }

    const outcome = await diffOrExit(resolve(fileA), resolve(fileB))
    if (outcome.exitCode === 2) {
      console.error(`Diff failed: ${outcome.error}`)
      process.exit(2)
    }

    const output = options.format === 'json'
      ? toDiffJSON(outcome.diff, options.pretty)
      : toDiffTerminal(outcome.diff)

    try {
      if (options.output) {
        await writeFile(resolve(options.output), output, 'utf-8')
        console.log(`Report saved to ${options.output}`)
      } else {
        console.log(output)
      }
    } catch (err) {
      console.error(`Diff failed: cannot write ${options.output}: ${err instanceof Error ? err.message : err}`)
      process.exit(2)
    }

    process.exitCode = outcome.exitCode
  })

program
  .command('mcp')
  .description('Serve analyze, scan, and diff to an AI agent over stdio (Model Context Protocol)')
  .action(async () => {
    try {
      await startMcpServer()
    } catch (err) {
      console.error(err instanceof Error ? err.message : err)
      process.exit(1)
    }
  })

program
  .command('tui')
  .description('Browse an analysis in an interactive terminal UI')
  .argument('<file>', 'Path to the binary file')
  .action(async (file: string) => {
    try {
      const report = await analyze(resolve(file))
      await runTUI(report)
    } catch (err) {
      console.error('Analysis failed:', err instanceof Error ? err.message : err)
      process.exit(1)
    }
  })

program
  .command('formats')
  .description('List supported output formats')
  .action(() => {
    console.log('Supported output formats:')
    console.log('  terminal  - Terminal-formatted summary (default)')
    console.log('  json      - JSON report')
    console.log('  markdown  - Markdown report')
    console.log('  html      - Interactive HTML report')
    console.log('  sarif     - SARIF format for static analysis tools')
    console.log('  yaml      - YAML report')
    console.log('  csv       - CSV report')
    console.log('  ioc       - IOC list from analyze (hashes, URLs, IPs, imports, YARA rule names)')
    console.log('  stix      - STIX 2.1 bundle from analyze')
    console.log('')
    console.log('Batch scan uses terminal, json, markdown, html, sarif, yaml, and csv.')
    console.log('ioc and stix are analyze only.')
  })

program.parse(process.argv)
