import type { CapabilityInfo } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

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
      if (ctx.strings?.some(s => /socket|connect|bind|listen|accept/i.test(s.value))) {
        score += 10; evidence.push('Socket operations')
      }
      if (ctx.strings?.some(s => /WSAStartup|WSACleanup|WSASocket/i.test(s.value))) {
        score += 10; evidence.push('Winsock API')
      }
      if (ctx.strings?.some(s => /getaddrinfo|gethostbyname/i.test(s.value))) score += 5
      if (ctx.imports?.some(i => /socket|send|recv|WSASend|WSARecv/.test(i.name))) {
        score += 15; evidence.push('Networking imports')
      }
      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'DNS',
    category: 'Network',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /gethostbyname|getaddrinfo|DnsQuery|res_query/i.test(s.value))) {
        score += 15; evidence.push('DNS resolution APIs')
      }
      if (ctx.domains && ctx.domains.length > 0) {
        score += 10; evidence.push(`${ctx.domains.length} domain strings found`)
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
      if (ctx.urls && ctx.urls.length > 0) {
        score += 15; evidence.push(`${ctx.urls.length} URLs found`)
      }
      if (ctx.strings?.some(s => /HTTP\/|https?:\/\//i.test(s.value))) score += 10
      if (ctx.strings?.some(s => /User-Agent|Content-Type|Accept:/i.test(s.value))) {
        score += 10; evidence.push('HTTP header strings')
      }
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
      if (ctx.strings?.some(s => /CreateFile|ReadFile|WriteFile|fopen|fread|fwrite|open|read|write/i.test(s.value))) {
        score += 10; evidence.push('File I/O APIs')
      }
      if (ctx.strings?.some(s => /\.(exe|dll|txt|dat|log|cfg|ini|xml|json|db)$/i.test(s.value))) {
        score += 5; evidence.push('File path/extension references')
      }
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
      if (ctx.strings?.some(s => /waveIn|mic|microphone|audio capture/i.test(s.value))) {
        score += 15; evidence.push('Audio input references')
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
      if (ctx.strings?.some(s => /AES|RSA|DES|SHA|MD5|HMAC|encrypt|decrypt|cipher|crypto/i.test(s.value))) {
        score += 15; evidence.push('Encryption algorithm references')
      }
      if (ctx.libraries?.some(l => l.name === 'OpenSSL')) {
        score += 15; evidence.push('OpenSSL (crypto library)')
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Browser Interaction',
    category: 'Application',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /Chrome|Firefox|Edge|Safari|Opera|browser/i.test(s.value))) {
        score += 10; evidence.push('Browser references')
      }
      if (ctx.strings?.some(s => /NP_|NPP_|NPAPI|ActiveX|Browser/i.test(s.value))) {
        score += 10; evidence.push('Browser plugin/extension APIs')
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
      if (ctx.strings?.some(s => /CreateProcess|CreateRemoteThread|NtCreateProcess|fork|execve/i.test(s.value))) {
        score += 15; evidence.push('Process creation APIs')
      }
      if (ctx.strings?.some(s => /ShellExecute|WinExec|system\(/i.test(s.value))) {
        score += 10; evidence.push('Command execution')
      }
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
      if (ctx.strings?.some(s => /CreateService|OpenSCManager|StartService|InstallService/i.test(s.value))) {
        score += 20; evidence.push('Service installation APIs')
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
      if (ctx.strings?.some(s => /ZwLoadDriver|NtLoadDriver|CreateService.*driver/i.test(s.value))) {
        score += 20; evidence.push('Driver loading APIs')
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
      if (ctx.strings?.some(s => /BitBlt|CreateCompatibleDC|GetDC|ScreenCapture|printscreen|screenshot/i.test(s.value))) {
        score += 20; evidence.push('Screen capture APIs')
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
      if (ctx.strings?.some(s => /Run|RunOnce|Startup|CurrentVersion\\Run|SCHTASKS|TaskScheduler/i.test(s.value))) {
        score += 15; evidence.push('Persistence mechanism references')
      }
      if (ctx.strings?.some(s => /HKCU\\|HKLM\\|HKEY_/i.test(s.value))) {
        score += 5; evidence.push('Registry hive references')
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
      if (ctx.strings?.some(s => /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC/i.test(s.value))) {
        score += 25; evidence.push('Code injection APIs')
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
      if (ctx.strings?.some(s => /SetWindowsHookEx.*WH_KEYBOARD|GetAsyncKeyState|GetKeyState/i.test(s.value))) {
        score += 25; evidence.push('Keylogging APIs')
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
      if (ctx.strings?.some(s => /IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent|ptrace/i.test(s.value))) {
        score += 20; evidence.push('Anti-debugging checks')
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
      if (ctx.strings?.some(s => /VMWare|VirtualBox|QEMU|vbox|vmtoolsd|VBoxGuest/i.test(s.value))) {
        score += 15; evidence.push('VM detection references')
      }
      if (ctx.strings?.some(s => /cpuid|hypervisor|rdtsc/i.test(s.value))) {
        score += 10; evidence.push('VM detection instructions')
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
      if (ctx.sections?.some(s => s.permissions.includes('WRITE') && s.permissions.includes('EXEC'))) {
        score += 20; evidence.push('Writable + executable sections')
      }
      return { confidence: Math.min(score, 50), evidence }
    },
  },
]

export function detectCapabilities(ctx: PluginContext): CapabilityInfo[] {
  const results: CapabilityInfo[] = []

  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence > 20) {
      results.push({ name: sig.name, category: sig.category, confidence: result.confidence, evidence: result.evidence })
    }
  }

  results.sort((a, b) => b.confidence - a.confidence)
  return results
}
