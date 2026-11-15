import type { CapabilityInfo } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { symbolSet } from './evidence.js'

interface CapabilitySignature {
  name: string
  category: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const signatures: CapabilitySignature[] = [
  {
    name: 'Networking',
    category: 'Network',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const symbols = symbolSet(ctx)
      const sock = ['socket', 'connect', 'bind', 'listen', 'accept', 'WSAStartup', 'WSASocket'].filter(n => symbols.has(n))
      if (sock.length >= 2) { score += 60; evidence.push(sock.slice(0, 4).join(', ')) }
      else if (sock.length === 1) { score += 35; evidence.push(sock[0]) }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'DNS',
    category: 'Network',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const symbols = symbolSet(ctx)
      const dns = ['getaddrinfo', 'gethostbyname', 'DnsQuery_A', 'res_query'].filter(n => symbols.has(n))
      if (dns.length > 0) { score += 55; evidence.push(dns.join(', ')) }
      if ((ctx.domains?.length ?? 0) >= 3) {
        score += 15; evidence.push(`${ctx.domains!.length} domain strings`)
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'HTTP',
    category: 'Network',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.libraries?.some(l => l.name === 'libcurl')) {
        score += 75; evidence.push('libcurl')
      }
      const client = ctx.strings?.some(s =>
        s.value.includes('HTTP/1.')
        || /^(?:GET|POST|PUT|DELETE|HEAD) \//.test(s.value)
        || s.value.includes('User-Agent:'),
      )
      if (client) { score += 20; evidence.push('HTTP client strings') }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'TLS',
    category: 'Network',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /SSL_|TLS_|ssl_|tls_/i.test(s.value))) {
        score += 15; evidence.push('TLS/SSL API references')
      }
      if (ctx.libraries?.some(l => l.name === 'OpenSSL')) {
        score += 20; evidence.push('OpenSSL library detected')
      }
      if (ctx.strings?.some(s => /certificate|X509|PEM_read/i.test(s.value))) {
        score += 10; evidence.push('Certificate handling')
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'File Access',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const symbols = symbolSet(ctx)
      const io = ['CreateFileA', 'CreateFileW', 'CreateFile', 'NtCreateFile'].filter(n => symbols.has(n))
      if (io.length > 0) { score += 55; evidence.push(io[0]) }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Clipboard',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /OpenClipboard|GetClipboardData|SetClipboardData/i.test(s.value))) {
        score += 20; evidence.push('Clipboard API references')
      }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Registry',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /RegOpenKey|RegQueryValue|RegSetValue|RegCreateKey/i.test(s.value))) {
        score += 15; evidence.push('Registry API')
      }
      if (ctx.strings?.some(s => s.type === 'RegistryPath')) {
        score += 10; evidence.push('Registry path strings')
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Camera',
    category: 'Hardware',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /capCreateCaptureWindow|video for windows|DirectShow|MFStartup/i.test(s.value))) {
        score += 15; evidence.push('Camera/capture APIs')
      }
      if (ctx.strings?.some(s => /AVFoundation|AVCapture/i.test(s.value))) score += 10
      return { confidence: Math.min(score, 60), evidence }
    },
  },
  {
    name: 'Microphone',
    category: 'Hardware',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const symbols = symbolSet(ctx)
      if (symbols.has('waveInOpen') || symbols.has('waveInStart')) {
        score += 60; evidence.push('Audio capture API')
      }
      return { confidence: Math.min(score, 55), evidence }
    },
  },
  {
    name: 'Compression',
    category: 'Data',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /compress|decompress|inflate|deflate|zlib|gzip|zip|unzip/i.test(s.value))) {
        score += 10; evidence.push('Compression references')
      }
      return { confidence: Math.min(score, 75), evidence }
    },
  },
  {
    name: 'Encryption',
    category: 'Data',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.libraries?.some(l => l.name === 'OpenSSL')) {
        score += 60; evidence.push('OpenSSL')
      }
      const symbols = symbolSet(ctx)
      const crypto = ['BCryptEncrypt', 'CryptEncrypt', 'CCCrypt'].filter(n => symbols.has(n))
      if (crypto.length > 0) { score += 55; evidence.push(crypto[0]) }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Browser Interaction',
    category: 'Application',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /Mozilla\/\d|Chrome\/\d/.test(s.value))) {
        score += 40; evidence.push('Browser user-agent')
      }
      const symbols = symbolSet(ctx)
      if (symbols.has('NP_Initialize') || symbols.has('NPN_GetURL')) {
        score += 30; evidence.push('NPAPI')
      }
      return { confidence: Math.min(score, 60), evidence }
    },
  },
  {
    name: 'Process Creation',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      const symbols = symbolSet(ctx)
      const spawn = ['CreateProcessA', 'CreateProcessW', 'CreateProcess', 'ShellExecuteA', 'ShellExecuteW', 'execve', 'posix_spawn'].filter(n => symbols.has(n))
      if (spawn.length > 0) { score += 60; evidence.push(spawn[0]) }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Thread Creation',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /CreateThread|pthread_create|BeginThread/i.test(s.value))) {
        score += 15; evidence.push('Thread creation APIs')
      }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Service Installation',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /CreateService|OpenSCManager|StartServiceCtrlDispatcher/i.test(s.value))) {
        score += 60; evidence.push('Service installation APIs')
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Driver Loading',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /ZwLoadDriver|NtLoadDriver/i.test(s.value))) {
        score += 65; evidence.push('Driver loading APIs')
      }
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.isDriver) { score += 25; evidence.push('Native driver binary') }
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Screen Capture',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /BitBlt|CreateCompatibleBitmap|ScreenCapture/i.test(s.value))) {
        score += 55; evidence.push('Screen capture APIs')
      }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Persistence',
    category: 'System',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /CurrentVersion\\Run|\\RunOnce|Software\\Microsoft\\Windows\\CurrentVersion\\Run/.test(s.value))) {
        score += 65; evidence.push('Run-key persistence')
      }
      const symbols = symbolSet(ctx)
      if (symbols.has('RegSetValueExA') || symbols.has('RegSetValueExW')) {
        score += 15; evidence.push('Registry write')
      }
      return { confidence: Math.min(score, 75), evidence }
    },
  },
  {
    name: 'Code Injection',
    category: 'Security',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC/.test(s.value))) {
        score += 70; evidence.push('Code injection APIs')
      }
      if (ctx.strings?.some(s => /SetWindowsHook|SetWinEventHook|AppInit_DLLs/i.test(s.value))) {
        score += 10; evidence.push('DLL injection references')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Keylogging',
    category: 'Security',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /GetAsyncKeyState|SetWindowsHookEx/.test(s.value))) {
        score += 70; evidence.push('Keylogging APIs')
      }
      return { confidence: Math.min(score, 82), evidence }
    },
  },
  {
    name: 'Anti-Debug',
    category: 'Security',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess/.test(s.value))) {
        score += 60; evidence.push('Anti-debugging checks')
      }
      if (ctx.strings?.some(s => /OutputDebugString|PEB|BeingDebugged/i.test(s.value))) {
        score += 10; evidence.push('Debugger detection references')
      }
      return { confidence: Math.min(score, 80), evidence }
    },
  },
  {
    name: 'Anti-VM',
    category: 'Security',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /\b(VMware|VirtualBox|VBoxGuest|vmtoolsd|QEMU)\b/.test(s.value))) {
        score += 55; evidence.push('VM product marker')
      }
      return { confidence: Math.min(score, 65), evidence }
    },
  },
  {
    name: 'Self-Modifying Code',
    category: 'Security',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.sections?.some(s => /WRITE/.test(s.permissions) && /EXEC/.test(s.permissions) && s.size > 0)) {
        score += 60; evidence.push('Writable and executable section')
      }
      return { confidence: Math.min(score, 50), evidence }
    },
  },
]

const CAPABILITY_MIN = 45

export function detectCapabilities(ctx: PluginContext): CapabilityInfo[] {
  const results: CapabilityInfo[] = []

  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence >= CAPABILITY_MIN && result.evidence.length > 0) {
      results.push({ name: sig.name, category: sig.category, confidence: result.confidence, evidence: result.evidence })
    }
  }

  results.sort((a, b) => b.confidence - a.confidence)
  return results
}
