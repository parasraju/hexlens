import type { Plugin, PluginManager, PluginContext } from '../types/plugin.js'

export function createPluginManager(): PluginManager {
  const plugins = new Map<string, Plugin>()

  return {
    register(plugin: Plugin): void {
      if (plugins.has(plugin.name)) {
        throw new Error(`Plugin "${plugin.name}" is already registered`)
      }
      plugins.set(plugin.name, plugin)
    },

    unregister(name: string): void {
      plugins.delete(name)
    },

    getPlugins(): Plugin[] {
      return Array.from(plugins.values())
    },

    async runAll(ctx: PluginContext): Promise<void> {
      const results = await Promise.allSettled(
        Array.from(plugins.values()).map(p => p.analyze(ctx))
      )
      for (let i = 0; i < results.length; i++) {
        const result = results[i]
        if (result.status === 'rejected') {
          console.error(`Plugin "${Array.from(plugins.keys())[i]}" failed:`, result.reason)
        }
      }
    },
  }
}
