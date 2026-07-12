#!/usr/bin/env node
import { Command } from 'commander'
import { analyze } from './index.js'
import { toJSON, toMarkdown, toTerminal, toHTML, toSARIF, toYAML, toCSV } from './reporters/index.js'
import { writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const program = new Command()

program
  .name('hexlens')
  .description('Binary Intelligence & Reverse Engineering Framework')
  .version('0.1.0')

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
  })

program.parse(process.argv)
