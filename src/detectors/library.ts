import type { DetectedItem } from '../types/index.js'
import type { PluginContext } from '../types/plugin.js'

interface LibrarySignature {
  name: string
  score: (ctx: PluginContext) => { confidence: number; evidence: string[] }
}

const signatures: LibrarySignature[] = [
  {
    name: 'OpenSSL',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /OpenSSL/.test(s.value) || /libssl/.test(s.value) || /libcrypto/.test(s.value))) {
        score += 25; evidence.push('OpenSSL version strings')
      }
      if (ctx.strings?.some(s => /SSL_CTX_|SSL_new|SSL_read/.test(s.value))) {
        score += 20; evidence.push('OpenSSL API symbols')
      }
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.imports?.some((i: any) => i.module === 'libssl' || i.module === 'libcrypto' || i.module === 'ssleay32' || i.module === 'libeay32')) {
          score += 20; evidence.push('OpenSSL import libraries')
        }
      }
      return { confidence: Math.min(score, 95), evidence }
    },
  },
  {
    name: 'SQLite',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /sqlite3_/.test(s.value) || /SQLite/.test(s.value))) {
        score += 25; evidence.push('SQLite API/signature')
      }
      if (ctx.strings?.some(s => s.value.startsWith('sqlite3_')) && ctx.strings.filter(s => s.value.startsWith('sqlite3_')).length > 3) {
        score += 20; evidence.push('Multiple SQLite exports')
      }
      if (ctx.strings?.some(s => s.value.includes('SQLite format 3'))) {
        score += 30; evidence.push('SQLite database header')
      }
      return { confidence: Math.min(score, 97), evidence }
    },
  },
  {
    name: 'FFmpeg',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /av_|avcodec|avformat|avutil/.test(s.value))) {
        score += 25; evidence.push('FFmpeg API symbols')
      }
      if (ctx.strings?.some(s => /FFmpeg/.test(s.value))) {
        score += 20; evidence.push('FFmpeg strings')
      }
      if (ctx.strings?.some(s => /libavcodec\.|libavformat\.|libavutil\./i.test(s.value))) {
        score += 15; evidence.push('FFmpeg library references')
      }
      return { confidence: Math.min(score, 93), evidence }
    },
  },
  {
    name: 'Qt',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /^Q[A-Z]/.test(s.value) && s.value.length > 2 && s.value.length < 40)) {
        score += 15; evidence.push('Qt class names')
      }
      if (ctx.strings?.some(s => /Qt::/.test(s.value) || /QObject::/.test(s.value))) {
        score += 15; evidence.push('Qt namespaced symbols')
      }
      if (ctx.strings?.some(s => /libQt\d/.test(s.value))) {
        score += 20; evidence.push('Qt library references')
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'GTK',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /gtk_/.test(s.value) || /gdk_/.test(s.value))) {
        score += 20; evidence.push('GTK API symbols')
      }
      if (ctx.strings?.some(s => /libgtk/.test(s.value))) {
        score += 15; evidence.push('GTK library')
      }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'SDL',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /SDL_/.test(s.value))) {
        score += 20; evidence.push('SDL API symbols')
      }
      if (ctx.strings?.some(s => /libSDL/.test(s.value))) {
        score += 15; evidence.push('SDL library')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'GLFW',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /glfw[A-Z]/.test(s.value) || /GLFW[A-Z]/.test(s.value))) {
        score += 20; evidence.push('GLFW API')
      }
      if (ctx.strings?.some(s => /libglfw/.test(s.value))) score += 10
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'OpenCV',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /cv::|cv_|opencv/.test(s.value))) {
        score += 20; evidence.push('OpenCV symbols')
      }
      if (ctx.strings?.some(s => /libopencv_/.test(s.value))) {
        score += 15; evidence.push('OpenCV library')
      }
      return { confidence: Math.min(score, 88), evidence }
    },
  },
  {
    name: 'libcurl',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /curl_/.test(s.value) || /libcurl/.test(s.value))) {
        score += 20; evidence.push('libcurl API')
      }
      if (ctx.strings?.some(s => s.value.includes('curl_easy_init') || s.value.includes('curl_easy_perform'))) {
        score += 20; evidence.push('libcurl functions')
      }
      return { confidence: Math.min(score, 93), evidence }
    },
  },
  {
    name: 'zlib',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /deflate|inflate|zlib|z_stream/.test(s.value))) {
        score += 20; evidence.push('zlib symbols')
      }
      if (ctx.strings?.some(s => s.value === 'zlib' || s.value.includes('zlibVersion'))) {
        score += 15; evidence.push('zlib version string')
      }
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'Electron',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /electron/i.test(s.value) || /ELECTRON/.test(s.value))) {
        score += 20; evidence.push('Electron strings')
      }
      if (ctx.strings?.some(s => /node::|v8::/.test(s.value))) score += 10
      if (ctx.sections.some(s => s.name.includes('electron'))) { score += 15; evidence.push('Electron sections') }
      return { confidence: Math.min(score, 85), evidence }
    },
  },
  {
    name: 'Node.js',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /node\.js/i.test(s.value) || /Node\.js/i.test(s.value))) {
        score += 20; evidence.push('Node.js strings')
      }
      if (ctx.strings?.some(s => /node_api_|napi_/.test(s.value))) score += 15
      if (ctx.strings?.some(s => /libnode/.test(s.value))) { score += 15; evidence.push('Node.js library') }
      return { confidence: Math.min(score, 82), evidence }
    },
  },
  {
    name: 'Python',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /Py_|PyObject|PyBytes|PyTuple|PyDict/.test(s.value))) {
        score += 20; evidence.push('Python C API')
      }
      if (ctx.strings?.some(s => /Python\/[\d.]+/.test(s.value))) {
        score += 20; evidence.push('Python version string')
      }
      if (ctx.strings?.some(s => /libpython/.test(s.value))) {
        score += 15; evidence.push('Python library')
      }
      return { confidence: Math.min(score, 93), evidence }
    },
  },
  {
    name: 'Lua',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /lua_|[Ll]ua\s+\d/.test(s.value))) {
        score += 20; evidence.push('Lua API')
      }
      if (ctx.strings?.some(s => /luaL_|luaopen_/.test(s.value))) {
        score += 15; evidence.push('Lua auxiliary library')
      }
      if (ctx.strings?.some(s => /liblua/.test(s.value))) score += 10
      return { confidence: Math.min(score, 90), evidence }
    },
  },
  {
    name: 'JVM',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /jvm|JVM|JNI_/.test(s.value))) score += 15
      if (ctx.strings?.some(s => /Java_/.test(s.value))) { score += 20; evidence.push('JNI function names') }
      if (ctx.strings?.some(s => /jclass|jobject|jmethodID/.test(s.value))) score += 10
      return { confidence: Math.min(score, 78), evidence }
    },
  },
  {
    name: '.NET Runtime',
    score: (ctx) => {
      const evidence: string[] = []
      let score = 0
      if (ctx.strings?.some(s => /mscorlib|System\./.test(s.value))) {
        score += 20; evidence.push('.NET framework references')
      }
      if (ctx.strings?.some(s => /CLR|\.NET/.test(s.value))) score += 15
      if (ctx.strings?.some(s => /managed|garbage collection/i.test(s.value))) score += 10
      if (ctx.metadata.peData) {
        const pe = ctx.metadata.peData as any
        if (pe?.imports?.some((i: any) => i.module === 'mscoree' || i.name === 'CorExeMain' || i.name === 'CorDllMain')) {
          score += 25; evidence.push('.NET CLR imports')
        }
      }
      return { confidence: Math.min(score, 92), evidence }
    },
  },
]

export function detectLibraries(ctx: PluginContext): DetectedItem[] {
  const results: DetectedItem[] = []
  const seen = new Set<string>()

  for (const sig of signatures) {
    const result = sig.score(ctx)
    if (result.confidence > 20 && !seen.has(sig.name)) {
      seen.add(sig.name)
      results.push({ name: sig.name, confidence: result.confidence, evidence: result.evidence })
    }
  }

  results.sort((a, b) => b.confidence - a.confidence)
  return results
}
