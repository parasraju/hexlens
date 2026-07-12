import { describe, it, expect } from 'vitest'
import { createPluginManager } from '../engine/plugin.js'
import type { PluginContext } from '../types/plugin.js'

describe('createPluginManager', () => {
  const ctx: PluginContext = {
    raw: new Uint8Array([0x01, 0x02, 0x03]),
    format: 'PE',
    architecture: 'x64',
    sections: [],
    strings: [],
    metadata: {},
    imports: [],
    exports: [],
    domains: [],
    urls: [],
  }

  it('creates a plugin manager', () => {
    const mgr = createPluginManager()
    expect(mgr.register).toBeDefined()
    expect(mgr.unregister).toBeDefined()
    expect(mgr.getPlugins).toBeDefined()
    expect(mgr.runAll).toBeDefined()
  })

  it('register and run a plugin', () => {
    const mgr = createPluginManager()
    let called = false
    mgr.register({
      name: 'test',
      version: '1.0.0',
      description: 'test plugin',
      analyze(c: PluginContext) {
        called = true
        c.metadata.testRan = true
      },
    })
    mgr.runAll(ctx)
    expect(called).toBe(true)
    expect(ctx.metadata.testRan).toBe(true)
  })

  it('unregister removes a plugin', () => {
    const mgr = createPluginManager()
    const plugin = {
      name: 'test',
      version: '1.0.0',
      description: 'test plugin',
      analyze(_ctx: PluginContext) { /* noop */ },
    }
    mgr.register(plugin)
    expect(mgr.getPlugins()).toHaveLength(1)
    mgr.unregister('test')
    expect(mgr.getPlugins()).toHaveLength(0)
  })

  it('getPlugins returns all plugins', () => {
    const mgr = createPluginManager()
    const p1 = { name: 'a', version: '1', description: '', analyze(_ctx: PluginContext) {} }
    const p2 = { name: 'b', version: '1', description: '', analyze(_ctx: PluginContext) {} }
    mgr.register(p1)
    mgr.register(p2)
    expect(mgr.getPlugins()).toHaveLength(2)
    expect(mgr.getPlugins().map(p => p.name)).toEqual(['a', 'b'])
  })

  it('runAll handles all registered plugins', () => {
    const mgr = createPluginManager()
    const order: string[] = []
    mgr.register({
      name: 'first', version: '1', description: '',
      analyze(_ctx: PluginContext) { order.push('first') },
    })
    mgr.register({
      name: 'second', version: '1', description: '',
      analyze(_ctx: PluginContext) { order.push('second') },
    })
    mgr.runAll(ctx)
    expect(order).toEqual(['first', 'second'])
  })
})
