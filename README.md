# HexLens



<div align="center">
<img width="800" height="400" alt="5217075e-69ae-4778-8358-48fa3c6e765d" src="https://github.com/user-attachments/assets/76b396a5-4f83-414e-9e04-0854596ff551" />


</div>

---
**Binary Intelligence & Reverse Engineering Framework**
HexLens is an open-source, TypeScript-first binary intelligence framework that automatically analyzes executable files and produces structured intelligence reports. Given a PE, ELF, Mach-O, or WASM binary, HexLens tells you everything important about it, how it was built, what technologies it uses, how it behaves, and what makes it unique.

```ts
import { analyze } from "hexlens"

const report = await analyze("program.exe")
// => structured intelligence report
```

---

## Features

- **Format Detection** — PE32/PE32+, ELF32/ELF64, Mach-O, WASM, DEX (Android), .NET (managed PE), Universal/Fat binaries detected but treated as Mach-O
- **Architecture Recognition** — x86, x64, ARM, ARM64, MIPS, RISC-V, PowerPC
- **Compiler Fingerprinting** — MSVC, GCC, Clang, MinGW, Rustc, Go, Zig, Delphi, Swift, Nim, TinyCC, Intel Compiler
- **Language Detection** — C, C++, Rust, Go, Swift, Zig, Nim, D, Delphi, Crystal, Odin, Assembly (with confidence scoring)
- **Library Identification** — OpenSSL, SQLite, FFmpeg, Qt, GTK, SDL, GLFW, OpenCV, libcurl, zlib, Electron, Node.js, Python, Lua, JVM, .NET Runtime
- **Security Analysis** — ASLR, DEP, CFG, NX, PIE, RELRO, Stack Canaries, SafeSEH, digital signatures, timestamp anomalies, overlays
- **Packer Detection** — UPX, Themida, VMProtect, MPRESS, ASPack, custom packers via entropy analysis
- **Capability Inference** — Networking, DNS, HTTP, TLS, encryption, file access, clipboard, registry, process creation, code injection, keylogging, anti-debug, anti-VM, persistence, screen capture, driver loading
- **String Intelligence** — ASCII, UTF-16, URLs, domains, IPv4, file paths, registry paths, user-agent strings, base64
- **Import/Export Analysis** — Full import table enumeration, export symbol recovery, **imphash** computation
- **PE Resource Parsing** — version info, icons, manifests, and other embedded resources
- **Managed & Dalvik Metadata** — .NET assembly name/version/CLR runtime, method defs and type refs; DEX classes, methods and string pools
- **Binary Metrics** — Function count estimation, section entropy, complexity scoring, optimization level estimation
- **Graph Generation** — Import graphs, dependency graphs, section graphs (Graphviz, Mermaid, JSON export)
- **Interactive TUI** — Browse any analysis with a keyboard-driven terminal UI (`hexlens tui`)
- **Plugin System** — Extend HexLens with custom detectors without modifying the core
- **Multiple Reporters** — Terminal, JSON, Markdown, HTML, SARIF, YAML, CSV

---

## Installation

```bash
npm install hexlens
```

## CLI Usage

```bash
# Analyze a binary (terminal output is default)
npx hexlens analyze program.exe

# JSON output
npx hexlens analyze program.exe --format json

# Pretty-print JSON
npx hexlens analyze program.exe --format json --pretty

# Save to file
npx hexlens analyze program.exe --format html --output report.html

# Interactive terminal UI
npx hexlens tui program.exe

# See all formats
npx hexlens formats
```

### Output Formats

| Format      | Command                    | Description                                  |
|-------------|----------------------------|----------------------------------------------|
| Terminal    | `--format terminal`        | Color-coded console summary (default)        |
| JSON        | `--format json`            | Full structured report                       |
| Markdown    | `--format md` / `markdown` | Readable markdown document                   |
| HTML        | `--format html`            | Interactive dark-mode report with tables     |
| SARIF       | `--format sarif`           | Static analysis results interchange format   |
| YAML        | `--format yaml` / `yml`    | Compact YAML report                          |
| CSV         | `--format csv`             | Flat key-value CSV for spreadsheets          |

---

## SDK Usage

```ts
import { analyze } from "hexlens"

const report = await analyze("program.exe")

console.log(report.format)         // "PE" | "ELF" | "Mach-O" | "WASM" | "DEX" | ".NET"
console.log(report.architecture)   // "x64" | "ARM" | ...
console.log(report.compiler?.name) // "MSVC"
console.log(report.language?.name) // "C++"
console.log(report.packer?.name)   // null (or "UPX", "MPRESS", etc.)
console.log(report.capabilities)   // [{ name: "Networking", confidence: 95, ... }]
console.log(report.security)       // { aslr: true, dep: true, ... }
console.log(report.imports)        // [{ module: "KERNEL32.dll", name: "CreateFile" }, ...]
console.log(report.metadata.imphash) // "8e65e6f0f6e5c9e2f8d0b3c4a5d6e7f8"
console.log(report.resources)      // [{ name, type: "VERSION", size, offset }]
console.log(report.metadata.assembly) // { name: "MyApp", version: "1.0.0.0", runtime: "v4.0.30319" } (.NET)
console.log(report.metadata.dex)   // { version: "035", classes, methods, strings } (DEX)
```

### Report Structure

```ts
{
  file:      { name, size, sha256, md5, sha1 },
  format:    "PE" | "ELF" | "Mach-O" | "WASM" | "DEX" | ".NET" | "Unknown",
  architecture: "x64" | "ARM" | ...,
  operatingSystem: "Windows" | "Linux" | "macOS" | "Android" | "iOS" | "Unknown",
  endianness: "little" | "big",
  compiler:  { name, confidence, evidence[] } | null,
  language:  { name, confidence, evidence[] } | null,
  packer:    { name, confidence, evidence[] } | null,
  obfuscation: { name, confidence, evidence[] } | null,
  optimization: "Optimized" | "Debug" | "Unknown" | null,
  stripped:  boolean,
  timestamp: number,
  entryPoint: number,
  libraries: [{ name, confidence, evidence[] }],
  imports:   [{ module, name, address? }],
  exports:   [{ name, address, ordinal? }],
  domains:   string[],
  strings:   [{ value, type, offset }],
  capabilities: [{ name, category, confidence, evidence[] }],
  security:  { aslr, dep, cfg, nx, pie, relro, stackCanaries, safeSEH, signed, certificateValid?, timestampAnomaly, overlay },
  sections:  [{ name, rva, fileOffset, size, entropy, permissions, alignment }],
  metrics:   { functionCount, averageFunctionSize, complexityScore, sectionEntropy, symbolDensity, instructionDensity, optimizationEstimate },
  graphs:    { importGraph, dependencyGraph, sectionGraph, ... },
  resources: ResourceInfo[],
  similarBinaries: SimilarityResult[],
  metadata:  Record<string, unknown>,
}
```

---

## Plugin System

Extend HexLens with custom detectors:

```ts
import { createPluginManager } from "hexlens"

const plugins = createPluginManager()
plugins.register({
  name: "My Detector",
  version: "1.0.0",
  description: "Detects custom framework signatures",
  analyze(ctx) {
    if (ctx.strings.some(s => s.value.includes("MyFramework"))) {
      ctx.metadata.myFramework = { detected: true }
    }
  }
})
```

---

## Project Structure

```
src/
├── index.ts           # Main API (analyze function + exports)
├── cli.ts             # CLI entry point
├── tui.ts             # Interactive terminal UI (hexlens tui)
├── types/             # TypeScript type definitions
│   ├── index.ts       # BinaryReport, SectionInfo, etc.
│   └── plugin.ts      # Plugin/Detector interfaces
├── parsers/           # Binary format parsers
│   ├── format-detector.ts
│   ├── pe.ts
│   ├── elf.ts
│   ├── macho.ts
│   ├── wasm.ts
│   ├── dex.ts         # Android DEX (Dalvik)
│   └── dotnet.ts      # .NET managed PE metadata
├── detectors/         # Analysis detectors
│   ├── compiler.ts
│   ├── language.ts
│   ├── library.ts
│   ├── capability.ts
│   ├── security.ts
│   ├── packer.ts
│   └── string-extractor.ts
├── analysis/          # Analysis modules
│   ├── metrics.ts
│   ├── symbols.ts
│   └── functions.ts
├── engine/            # Core engine
│   ├── plugin.ts
│   ├── graph.ts
│   └── similarity.ts
├── reporters/         # Output formatters
│   ├── json.ts
│   ├── html.ts
│   ├── markdown.ts
│   ├── terminal.ts
│   ├── sarif.ts
│   ├── yaml.ts
│   └── csv.ts
└── utils/             # Shared utilities
    ├── buffer-reader.ts
    ├── hash.ts        # sha/md5 + imphash
    ├── index.ts
    └── entropy.ts
```

---

## License

MIT
