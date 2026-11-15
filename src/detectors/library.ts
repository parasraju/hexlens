import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'
import { countNames, hasApi, hasModule, hasSection, hasText, symbolSet, textMarker } from './evidence.js'

interface LibrarySignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const MIN_CONFIDENCE = 55

function apis(ctx: PluginContext, names: readonly string[], each: number, cap: number): { hits: number; score: number } {
  const symbols = symbolSet(ctx)
  let hits = 0
  for (const name of names) if (hasApi(ctx, symbols, name)) hits++
  return { hits, score: Math.min(cap, hits * each) }
}

const signatures: LibrarySignature[] = [
  {
    name: 'libcurl',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libcurl/i)) { score += 72; evidence.push('linked libcurl') }
      const hit = apis(ctx, ['curl_easy_init', 'curl_easy_setopt', 'curl_easy_perform', 'curl_easy_cleanup', 'curl_global_init', 'curl_version'], 14, 28)
      if (hit.hits > 0) { score += hit.score; evidence.push(`${hit.hits} libcurl APIs`) }
      const version = textMarker(ctx, 'libcurl/')
      if (version) { score += 12; evidence.push(version) }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'OpenSSL',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libssl|libcrypto|ssleay32|libeay32/i)) { score += 70; evidence.push('linked OpenSSL') }
      const version = textMarker(ctx, 'OpenSSL ')
      if (version && /OpenSSL \d/.test(version)) { score += 30; evidence.push(version) }
      const hit = apis(ctx, ['SSL_CTX_new', 'SSL_new', 'OPENSSL_init_ssl', 'EVP_EncryptInit_ex'], 12, 24)
      if (hit.hits > 0) { score += hit.score; evidence.push(`${hit.hits} OpenSSL APIs`) }
      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'zlib',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /(^|\/)libz(\.|$)|zlib1\.dll/i)) { score += 72; evidence.push('linked zlib') }
      const hit = apis(ctx, ['deflateInit_', 'inflateInit_', 'zlibVersion', 'compress2'], 16, 32)
      if (hit.hits > 0) { score += hit.score; evidence.push(`${hit.hits} zlib APIs`) }
      const version = textMarker(ctx, 'deflate 1.') ?? textMarker(ctx, 'inflate 1.')
      if (version) { score += 20; evidence.push(version) }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'SQLite',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libsqlite/i)) { score += 70; evidence.push('linked SQLite') }
      const symbols = symbolSet(ctx)
      const hits = countNames(symbols, ['sqlite3_open', 'sqlite3_exec', 'sqlite3_prepare_v2', 'sqlite3_libversion'])
        + (hasText(ctx, 'sqlite3_open') ? 1 : 0)
      if (hits > 0) { score += Math.min(40, hits * 15); evidence.push('SQLite API') }
      if (hasText(ctx, 'SQLite version ') || hasText(ctx, 'SQLite format 3')) {
        score += 25; evidence.push('SQLite version string')
      }
      return { confidence: Math.min(score, 96), evidence }
    },
  },
  {
    name: 'FFmpeg',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libavcodec|libavformat|libavutil|avcodec|avformat/i)) {
        score += 70; evidence.push('linked FFmpeg')
      }
      if (textMarker(ctx, 'FFmpeg version') || textMarker(ctx, 'Lavf') || textMarker(ctx, 'Lavc')) {
        score += 25; evidence.push('FFmpeg version string')
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'Qt',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libQt\d|Qt\dCore|Qt5Core|Qt6Core/i)) { score += 75; evidence.push('linked Qt') }
      if (hasText(ctx, 'QObject::') || hasText(ctx, 'qt_version_tag')) {
        score += 20; evidence.push('Qt runtime')
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
  {
    name: 'GTK',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libgtk|libgdk/i)) { score += 72; evidence.push('linked GTK') }
      const hit = apis(ctx, ['gtk_init', 'gtk_main', 'g_object_unref'], 12, 24)
      if (hit.hits > 0) { score += hit.score; evidence.push('GTK API') }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'SDL',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libSDL/i)) { score += 72; evidence.push('linked SDL') }
      const hit = apis(ctx, ['SDL_Init', 'SDL_CreateWindow', 'SDL_PollEvent'], 14, 28)
      if (hit.hits > 0) { score += hit.score; evidence.push('SDL API') }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'GLFW',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libglfw/i)) { score += 70; evidence.push('linked GLFW') }
      const hit = apis(ctx, ['glfwInit', 'glfwCreateWindow', 'glfwPollEvents'], 14, 28)
      if (hit.hits > 0) { score += hit.score; evidence.push('GLFW API') }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'OpenCV',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libopencv_/i)) { score += 75; evidence.push('linked OpenCV') }
      if (hasText(ctx, 'opencv_world') || hasText(ctx, 'cv::Mat')) {
        score += 20; evidence.push('OpenCV types')
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Electron',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasText(ctx, 'Electron/') || hasText(ctx, 'ELECTRON_RUN_AS_NODE')) {
        score += 70; evidence.push('Electron runtime')
      }
      if (hasSection(ctx, n => n.toLowerCase().includes('electron'))) score += 15
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Node.js',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libnode/i) || hasText(ctx, 'node::Start') || hasText(ctx, 'NODE_MODULE_VERSION')) {
        score += 70; evidence.push('Node.js runtime')
      }
      const hit = apis(ctx, ['napi_module_register', 'node_api_module_get_api_version'], 15, 20)
      if (hit.hits > 0) score += hit.score
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'Python',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libpython/i)) { score += 72; evidence.push('linked libpython') }
      const version = textMarker(ctx, 'Python/')
      if (version && /Python\/\d/.test(version)) { score += 25; evidence.push(version) }
      const hit = apis(ctx, ['Py_Initialize', 'Py_InitializeEx', 'PyObject_Call', 'PyRun_SimpleString'], 14, 28)
      if (hit.hits > 0) { score += hit.score; evidence.push('Python C API') }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
  {
    name: 'Lua',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /liblua/i)) { score += 70; evidence.push('linked Lua') }
      const hit = apis(ctx, ['luaL_newstate', 'luaL_openlibs', 'lua_pcall'], 16, 32)
      if (hit.hits > 0) { score += hit.score; evidence.push('Lua API') }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'JVM',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (hasModule(ctx, /libjvm|libjli/i)) { score += 70; evidence.push('linked JVM') }
      if (hasText(ctx, 'JNI_CreateJavaVM') || hasText(ctx, 'JNI_OnLoad')) {
        score += 25; evidence.push('JNI entry points')
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: '.NET Runtime',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.format === '.NET') { score += 80; evidence.push('CLI header') }
      if (hasModule(ctx, /mscoree/i) || hasText(ctx, 'mscoree.dll')) {
        score += 30; evidence.push('CLR bootstrap')
      }
      const asm = ctx.metadata.assembly as { runtime?: string } | undefined
      if (asm?.runtime) { score += 15; evidence.push(asm.runtime) }
      return { confidence: Math.min(score, 94), evidence }
    },
  },
]

export function detectLibraries(ctx: PluginContext): DetectedItem[] {
  const results: DetectedItem[] = []
  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence < MIN_CONFIDENCE || result.evidence.length === 0) continue
    results.push({ name: sig.name, confidence: result.confidence, evidence: result.evidence })
  }
  results.sort((a, b) => b.confidence - a.confidence)
  return results
}
