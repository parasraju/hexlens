import type { GraphData, AnalysisGraphs, ImportInfo, SectionInfo } from '../types/index.js'

export function buildCallGraph(): GraphData {
  return { nodes: [], edges: [] }
}

export function buildImportGraph(imports: ImportInfo[]): GraphData {
  const nodes: { id: string; label: string; group: string }[] = []
  const edges: { source: string; target: string; type: string }[] = []
  const moduleMap = new Map<string, Set<string>>()

  for (const imp of imports) {
    if (!moduleMap.has(imp.module)) {
      moduleMap.set(imp.module, new Set())
    }
    moduleMap.get(imp.module)!.add(imp.name)
  }

  for (const [module, functions] of moduleMap) {
    nodes.push({ id: module, label: module, group: 'module' })
    for (const fn of functions) {
      const fnId = `${module}:${fn}`
      nodes.push({ id: fnId, label: fn, group: 'function' })
      edges.push({ source: module, target: fnId, type: 'contains' })
    }
  }

  return { nodes, edges }
}

export function buildSectionGraph(sections: SectionInfo[]): GraphData {
  const nodes = sections.map(s => ({
    id: s.name,
    label: `${s.name} (${(s.entropy).toFixed(2)})`,
    group: s.permissions.includes('EXEC') ? 'code' : s.permissions.includes('WRITE') ? 'data' : 'other',
  }))
  return { nodes, edges: [] }
}

export function buildDependencyGraph(imports: ImportInfo[], libraries: { name: string; confidence: number }[]): GraphData {
  const nodes: { id: string; label: string; group: string }[] = []
  const edges: { source: string; target: string; type: string }[] = []

  nodes.push({ id: 'binary', label: 'Binary', group: 'root' })

  for (const lib of libraries) {
    nodes.push({ id: lib.name, label: `${lib.name} (${lib.confidence}%)`, group: 'library' })
    edges.push({ source: 'binary', target: lib.name, type: 'depends' })
  }

  const moduleSet = new Set(imports.map(i => i.module))
  for (const mod of moduleSet) {
    nodes.push({ id: mod, label: mod, group: 'module' })
    edges.push({ source: 'binary', target: mod, type: 'imports' })
  }

  return { nodes, edges }
}

export function buildAllGraphs(
  imports: ImportInfo[],
  sections: SectionInfo[],
  libraries: { name: string; confidence: number }[],
): AnalysisGraphs {
  return {
    callGraph: buildCallGraph(),
    importGraph: buildImportGraph(imports),
    dependencyGraph: buildDependencyGraph(imports, libraries),
    sectionGraph: buildSectionGraph(sections),
  }
}

export function graphToGraphviz(graph: GraphData): string {
  let output = 'digraph G {\n  rankdir=LR;\n'
  for (const node of graph.nodes) {
    output += `  "${node.id}" [label="${node.label}"`;
    if (node.group === 'code') output += ' shape=box style=filled fillcolor="#e0ffe0"'
    else if (node.group === 'data') output += ' shape=box style=filled fillcolor="#ffe0e0"'
    else if (node.group === 'module') output += ' shape=ellipse style=filled fillcolor="#e0e0ff"'
    else if (node.group === 'library') output += ' shape=box3d style=filled fillcolor="#ffe0ff"'
    else if (node.group === 'root') output += ' shape=doublecircle style=filled fillcolor="#ffffe0"'
    output += '];\n'
  }
  for (const edge of graph.edges) {
    output += `  "${edge.source}" -> "${edge.target}" [label="${edge.type}"];\n`
  }
  output += '}\n'
  return output
}

export function graphToMermaid(graph: GraphData): string {
  let output = 'graph LR\n'
  for (const node of graph.nodes) {
    output += `  ${node.id.replace(/[^a-zA-Z0-9]/g, '_')}["${node.label}"]\n`
  }
  for (const edge of graph.edges) {
    const srcId = edge.source.replace(/[^a-zA-Z0-9]/g, '_')
    const tgtId = edge.target.replace(/[^a-zA-Z0-9]/g, '_')
    output += `  ${srcId} -->|${edge.type}| ${tgtId}\n`
  }
  return output
}
