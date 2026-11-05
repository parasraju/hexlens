#!/usr/bin/env node
import { Command } from 'commander'
import { analyze, scan } from './index.js'
import { runTUI } from './tui.js'
import { toJSON, toMarkdown, toTerminal, toHTML, toSARIF, toYAML, toCSV } from './reporters/index.js'
import { formatScan } from './reporters/scan.js'
import { writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const program = new Command()

program
  .name('hexlens')
  .description('Binary Intelligence & Reverse Engineering Framework')
  .version('0.3.1')

program
  .command('analyze')
  .description('Analyze a binary file')
  .argument('<file>', 'Path to the binary file')
  .option('-f, --format <format>', 'Output format', 'terminal')
  .option('-o, --output <file>', 'Output file path')
  .option('--pretty', 'Pretty-print JSON', true)
  .action(async (file: string, options: { format: string; output?: string; pretty: boolean }) => {
    try {
      console.log('Analyzing binary...')
      const report = await analyze(resolve(file))

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
        case 'terminal':
        default:
          output = toTerminal(report)
          break
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
  .option('--pretty', 'Pretty-print JSON', true)
  .action(async (path: string, options: { format: string; output?: string; all?: boolean; recursive: boolean; hidden?: boolean; pretty: boolean }) => {
    try {
      process.stderr.write(`Scanning ${path}...\n`)
      const summary = await scan(resolve(path), {
        recursive: options.recursive,
        includeUnknown: options.all,
        includeHidden: options.hidden,
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
    console.log('')
    console.log('Batch scan uses the same formats: hexlens scan <path> --format <format>')
  })

program.parse(process.argv)
