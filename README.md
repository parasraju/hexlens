# HexLens

[![npm version](https://img.shields.io/npm/v/hexlens.svg)](https://www.npmjs.com/package/hexlens)
[![GitHub](https://img.shields.io/badge/GitHub-parasraju%2Fhexlens-181717?logo=github)](https://github.com/parasraju/hexlens)

**Binary Intelligence & Reverse Engineering Framework**

HexLens is an open-source, TypeScript-first binary intelligence framework that automatically analyzes executable files and produces structured intelligence reports. Given a PE, ELF, Mach-O, or WASM binary, HexLens tells you everything important about it, how it was built, what technologies it uses, how it behaves, and what makes it unique.

```ts
import { analyze } from "hexlens"

const report = await analyze("program.exe")
// => structured intelligence report
```

---

## Features

- **Format Detection** — PE32/PE32+, ELF32/ELF64, Mach-O (including the first slice of a universal binary), WASM, DEX (Android), .NET (managed PE). Files that match none of these are reported as unrecognized instead of a mitigation checklist.
- **Architecture Recognition** — x86, x64, ARM, ARM64, MIPS, RISC-V, PowerPC
- **Compiler Fingerprinting** — MSVC, GCC, Clang, MinGW, Rustc, Go, Zig, Delphi, Swift, Nim, TinyCC, Intel Compiler
- **Language Detection** — C, C++, Rust, Go, Swift, Zig, Nim, D, Delphi, Crystal, Odin, Assembly (with confidence scoring)
- **Library Identification** — OpenSSL, SQLite, FFmpeg, Qt, GTK, SDL, GLFW, OpenCV, libcurl, zlib, Electron, Node.js, Python, Lua, JVM, .NET Runtime
- **Security Analysis** — ASLR, DEP, CFG, NX, PIE, RELRO, Stack Canaries, SafeSEH, digital signatures, timestamp anomalies, overlays
- **Packer Detection** — UPX, Themida, VMProtect, MPRESS, ASPack, and a small set of packer section names. Ordinary compiler output (including the substring `MPRESS` inside `COMPRESSION`) is not flagged.
- **Capability Inference** — Networking, DNS, HTTP, TLS, encryption, file access, clipboard, registry, process creation, code injection, keylogging, anti-debug, anti-VM, persistence, screen capture, driver loading
- **String Intelligence** — ASCII, UTF-16, URLs, domains, IPv4, file paths, registry paths, user-agent strings, base64
- **Import/Export Analysis** — Full import table enumeration, export symbol recovery, **imphash** computation
- **PE Resource Parsing** — version info, icons, manifests, and other embedded resources
- **Managed & Dalvik Metadata** — .NET assembly name/version/CLR runtime, method defs and type refs; DEX classes, methods and string pools
- **Binary Metrics** — Function count estimation, section entropy, complexity scoring, optimization level estimation
- **Graph Generation** — Import graphs, dependency graphs, section graphs (Graphviz, Mermaid, JSON export)
- **Batch Scanning** — Triage a whole folder in one flag-aware summary table (`hexlens scan ./samples/`)
- **YARA Rule Scanning** — Match every scanned file against a YARA rule file (`--yara rules.yar`), backed by libyara compiled to WebAssembly
- **Binary Diff** — Compare two binaries by raw bytes and by analysis report (`hexlens diff old.bin new.bin`)
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

# Batch scan a folder (recursive by default)
npx hexlens scan ./samples/

# Export the batch scan as JSON, CSV, Markdown, HTML, YAML or SARIF
npx hexlens scan ./samples/ --format json --output scan.json

# Include files whose format is not recognized
npx hexlens scan ./samples/ --all

# Match files against YARA rules
npx hexlens scan ./samples/ --yara rules.yar

# Compare two binaries (byte diff and report diff)
npx hexlens diff old.bin new.bin

# Write the same diff as JSON
npx hexlens diff old.bin new.bin --format json --output diff.json

# See all formats
npx hexlens formats
```

### Batch Scanning

`hexlens scan <path>` walks a file or directory, runs the same `analyze()` pipeline on every
supported binary, and prints a single triage table sorted by risk. Each row includes format,
architecture, compiler, language, risk, and flags such as `PACKED`, `OBFUSC`, `UNSIGNED`,
`NO-ASLR`, `INJECT`, `KEYLOG`, `ANTI-DBG`, `PERSIST`, `OVERLAY`, and `TS-ANOM`.

Unrecognized files are skipped by default; pass `--all` to include them. Use `--no-recursive`
for a flat scan, `--hidden` to include dotfiles, and `--format` to export the scan through the
JSON, CSV, Markdown, HTML, YAML, or SARIF reporters.

```bash
# Scan a single binary too
npx hexlens scan program.exe
```

### YARA Rule Scanning

Pass `--yara <file>` to `scan` or `analyze` to match file contents against a YARA
rule file. Rules are loaded and compiled once at the start of the run. A missing,
unreadable, or invalid rule file aborts with a non-zero exit code instead of
scanning without rules.

```yara
rule HexLens_Test_Marker
{
    meta:
        author = "you"
    strings:
        $mz = "MZ"
        $marker = "HEXLENS_YARA_TEST"
    condition:
        $mz at 0 and $marker
}
```

```bash
npx hexlens scan ./samples/ --yara rules.yar
```

Matched rule names appear in the `FLAGS` column as `YARA:<rule>` and are reported
per file by `--format json`:

```jsonc
{
  "path": "marked.exe",
  "risk": "medium",
  "flags": [ /* ... */ ],
  "report": { /* ... */ },
  "yaraMatches": [
    {
      "file": "marked.exe",
      "rule": "HexLens_Test_Marker",
      "meta": { "author": "you" },
      "strings": [
        { "identifier": "$marker", "offset": 512, "length": 17 }
      ]
    }
  ]
}
```

For a single binary, matched rule names are printed after the report:

```bash
npx hexlens analyze program.exe --yara rules.yar
```

YARA scanning uses [`libyara-wasm`](https://www.npmjs.com/package/libyara-wasm),
a WebAssembly build of libyara. Text strings, hex strings, regular expressions,
string modifiers (`ascii`, `wide`, `nocase`, `fullword`), metadata, tags, and
normal YARA conditions are supported, and bundled modules such as `pe` are
available. `include` directives are not supported by the WebAssembly build, so
rule files must be self-contained. Terminal and JSON are the supported YARA
outputs; the other reporters do not add dedicated YARA sections.

### Binary diff — compare two binaries

`hexlens diff` is a binary diff of two files. It compares two binaries byte for
byte, then runs `analyze()` on each file and lists what changed in the reports.
Binary diffing here means raw bytes plus the analysis report (imphash, imports,
exports, sections, strings, compiler, language, packer, and entry point).

```bash
hexlens diff old.bin new.bin
```

Exit status follows `diff(1)`, so a CI job can tell identical files from a real change:

- `0` — the bytes are identical. Output includes an `identical` line and both files' SHA-256 hashes.
- `1` — one or more bytes differ.
- `2` — a file is missing, unreadable, or not a regular file; the format is not `terminal` or `json`; or `--output` could not be written.

Passing fewer than two file arguments is also an error and exits non-zero
(`error: missing required argument 'file-b'`).

`radiff2` (radare2) does binary diffing, including a disassembly diff, and needs
the radare2 toolchain. BinDiff (zynamics) matches functions across two binaries
and needs IDA. hexlens diff needs neither: it hashes and walks the raw bytes,
then uses the parsers already in this package (PE, ELF, Mach-O, WASM, DEX, and
.NET). It does not match basic blocks, diff control flow, or disassemble, and
it does not aim to replace radiff2 or BinDiff.

The sample below is two real minimal WebAssembly modules. `old.bin` (22 bytes)
imports `env.print`. `new.bin` (33 bytes) imports `env.print` and `env.extra`.
This is the terminal output from `hexlens diff old.bin new.bin` on that pair
(exit code 1):

```
 HexLens Diff — old.bin vs new.bin
────────────────────────────────────────────────────────────
 A: old.bin  22 bytes
    sha256 6febb11c24addaa7bee421ef6299edd8ed981eabe17501dcdc220167d884b4af
 B: new.bin  33 bytes
    sha256 c94ddf4617e708853496ff1b5d5a4e82d84f2e1ecb385064c27f0d765a389935

 Files differ: 13 bytes (60.61% similar)

 Byte differences
────────────────────────────────────────────────────────────
  First 10 of 13 differing offsets:
  0x00000009
    A: 00 00 00 02 [0c] 01 03 65 6e
    B: 00 00 00 02 [17] 02 03 65 6e
  0x0000000a
    A: 00 00 02 0c [01] 03 65 6e 76
    B: 00 00 02 17 [02] 03 65 6e 76
  0x00000016
    A: (past end)
    B: 69 6e 74 00 [03] 65 6e 76 05
  0x00000017
    A: (past end)
    B: 6e 74 00 03 [65] 6e 76 05 65
  0x00000018
    A: (past end)
    B: 74 00 03 65 [6e] 76 05 65 78
  0x00000019
    A: (past end)
    B: 00 03 65 6e [76] 05 65 78 74
  0x0000001a
    A: (past end)
    B: 03 65 6e 76 [05] 65 78 74 72
  0x0000001b
    A: (past end)
    B: 65 6e 76 05 [65] 78 74 72 61
  0x0000001c
    A: (past end)
    B: 6e 76 05 65 [78] 74 72 61 00
  0x0000001d
    A: (past end)
    B: 76 05 65 78 [74] 72 61 00

 Report
────────────────────────────────────────────────────────────
 Format: unchanged (WASM)
 Architecture: unchanged (Unknown)
 Imphash: different
  A: c89fde4fe83607ca1a53e4b7684f3259
  B: eeb642df4eeb2813cf617153e73c6da9
 Imports added (1):
  + env.extra
 Imports removed: none
 Exports added: none
 Exports removed: none
 Sections added: none
 Sections removed: none
 Sections changed (1):
  ~ import  12 -> 23 bytes
 Strings added (1):
  + extra
 Strings removed: none
 Compiler: unchanged (not detected)
 Language: unchanged (not detected)
 Packer: unchanged (not detected)
 Entry point: unchanged (0x00000000)
```

`--format json` prints that same diff as JSON: sizes, hashes, byte stats
(`differingBytes`, `similarity`, and the first 10 offsets with hex context),
plus `added` / `removed` / `changed` arrays for each report category.
`--output <file>` writes the terminal text or the JSON to a file instead of
stdout. Markdown, HTML, CSV, YAML, and SARIF are not diff formats in this
release.

String changes list at most 20 values and then a count of the rest. The
comparison uses the strings `analyze()` already returns. When a report has no
imphash, compiler, language, or packer, the diff says that field is missing or
not detected.

An identical copy of `old.bin` prints `Files are identical.` and both SHA-256
lines (`6febb11c24addaa7bee421ef6299edd8ed981eabe17501dcdc220167d884b4af`) and
exits 0.

## Images 

<img width="1094" height="572" alt="Screenshot 2026-08-16 225046" src="https://github.com/user-attachments/assets/c76474c4-ba66-426e-9c7d-8bb691296919" />


<img width="1098" height="396" alt="Screenshot 2026-08-16 225106" src="https://github.com/user-attachments/assets/fd67b37d-5b17-4cc1-95f8-e11fae5a36a8" />



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

### Batch Scan API

```ts
import { scan } from "hexlens"

const summary = await scan("./samples", { recursive: true, yara: "rules.yar" })

for (const { relativePath, risk, flags, yaraMatches } of summary.files) {
  console.log(relativePath, risk, flags.map(flag => flag.code).join(", "))
  console.log(yaraMatches?.map(match => match.rule))
}
```

`yaraMatches` is only present when a rule file is passed; it is an empty array for
files that did not match.

### Binary diff API

```ts
import { diff } from "hexlens"

const result = await diff("old.bin", "new.bin")

console.log(result.identical)
console.log(result.bytes.differingBytes)
console.log(result.bytes.similarity)
console.log(result.report.imports.added)
console.log(result.report.imphash)
```

On the WebAssembly pair in [Binary diff](#binary-diff--compare-two-binaries),
`result.bytes.differingBytes` is `13`, `result.bytes.similarity` is `60.61`,
and `result.report.imports.added` is `["env.extra"]`. `result.identical` is
`true` only when the bytes match, which is also exit code 0 on the CLI.

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
├── index.ts           # Public API + exports
├── analyze.ts         # Core analyze() implementation
├── cli.ts             # CLI entry point
├── tui.ts             # Interactive terminal UI (hexlens tui)
├── diff/              # Binary diff (bytes + report)
│   └── index.ts
├── scan/              # Batch folder scanning
│   └── index.ts
├── yara/              # YARA rule loading and matching
│   └── index.ts
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
│   ├── csv.ts
│   ├── scan.ts        # Batch triage table / bundle reporters
│   └── diff.ts        # Binary diff terminal and JSON output
└── utils/             # Shared utilities
    ├── buffer-reader.ts
    ├── hash.ts        # sha/md5 + imphash
    ├── index.ts
    └── entropy.ts
```

---

## License

MIT

## Changelog

### 0.6.0

- ELF32 and ELF64 headers are read at the offsets from the System V ABI. `e_entry` is reported, section names resolve, and dynamic imports, `DT_NEEDED` libraries, and symbol tables are recovered.
- PE32 `ImageBase` and `DllCharacteristics` are read after `BaseOfData`. Mach-O load commands are walked by `cmdsize`, including 64-bit segments and `LC_MAIN`.
- Parsers bounds-check every read. Truncated or malformed input returns a partial result instead of throwing.
- Packer detection requires a real marker. High entropy alone, and the letters `MPRESS` inside `COMPRESSION`, no longer flag a packer.
- Unrecognized files print **Not a recognized binary** and omit the security checklist.
- Compiler, language, and library confidence is higher when a version string, ABI marker, or linked library is present, and stays unreported when the only evidence is a generic section name.
- ELF security checks report PIE, NX (`PT_GNU_STACK`), and RELRO (`PT_GNU_RELRO`) instead of Windows-only mitigations.

### 0.5.0

Binary diff (`hexlens diff a.bin b.bin`) — byte-level and report-level comparison.

### 0.4.0

YARA rule scanning via `--yara` for `scan` and `analyze`.
