import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import * as d3 from 'd3'
import { api } from '../api/client'

interface GraphNode extends d3.SimulationNodeDatum {
  id: string
  type: string
  label: string
  value: string
  degree?: number
  high_confidence_node?: boolean
  metadata?: Record<string, unknown>
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  type: string
  metadata?: Record<string, unknown>
}

const NODE_COLORS: Record<string, string> = {
  email: '#ef4444',
  platform: '#22d3ee',
  username: '#71717a',
  display_name: '#71717a',
  photo_url: '#71717a',
  phone: '#71717a',
  domain: '#71717a',
}

const LINK_COLORS: Record<string, string> = {
  shared_username: '#22d3ee',
  breach_confirmed: '#ef4444',
  shared_photo: '#a855f7',
  shared_display_name: '#c084fc',
  same_platform_group: '#3f3f46',
}

function truncate(s: string, max = 20): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

function nodeRadius(d: GraphNode): number {
  switch (d.type) {
    case 'email':
      return 18
    case 'platform':
      return 12
    default:
      return 6
  }
}

export default function GraphView() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const svgRef = useRef<SVGSVGElement>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tooltip, setTooltip] = useState<{
    x: number
    y: number
    node: GraphNode
  } | null>(null)

  useEffect(() => {
    if (!id || !svgRef.current) return

    let cancelled = false
    setLoading(true)
    setError(null)

    api
      .getGraph(id)
      .then(data => {
        if (cancelled || !svgRef.current) return
        renderGraph(svgRef.current, data.nodes, data.links)
        setLoading(false)
      })
      .catch(err => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load graph')
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [id])

  function renderGraph(
    svgEl: SVGSVGElement,
    nodes: GraphNode[],
    links: GraphLink[],
  ) {
    const width = svgEl.clientWidth || 800
    const height = svgEl.clientHeight || 600

    const svg = d3.select(svgEl)
    svg.selectAll('*').remove()

    const g = svg.append('g')

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on('zoom', event => {
        g.attr('transform', event.transform.toString())
      })
    svg.call(zoom)

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink<GraphNode, GraphLink>(links)
          .id(d => d.id)
          .distance(80),
      )
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<GraphNode>().radius(d => nodeRadius(d) + 4))

    const link = g
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', d => LINK_COLORS[d.type] ?? '#52525b')
      .attr('stroke-opacity', 0.8)
      .attr('stroke-width', d => (d.type === 'breach_confirmed' ? 2 : 1))

    const node = g
      .append('g')
      .selectAll<SVGGElement, GraphNode>('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, GraphNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x
            d.fy = d.y
          })
          .on('drag', (event, d) => {
            d.fx = event.x
            d.fy = event.y
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null
            d.fy = null
          }),
      )

    node
      .append('circle')
      .attr('r', d => nodeRadius(d))
      .attr('fill', d => NODE_COLORS[d.type] ?? '#71717a')
      .attr('stroke', d => (d.high_confidence_node ? '#fbbf24' : 'transparent'))
      .attr('stroke-width', 2)

    node
      .append('text')
      .text(d => truncate(d.label || d.value))
      .attr('x', 0)
      .attr('y', d => nodeRadius(d) + 12)
      .attr('text-anchor', 'middle')
      .attr('fill', '#a1a1aa')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')

    node.on('click', (event, d) => {
      event.stopPropagation()
      const rect = svgEl.getBoundingClientRect()
      setTooltip({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
        node: d,
      })
    })

    svg.on('click', () => setTooltip(null))

    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as GraphNode).x ?? 0)
        .attr('y1', d => (d.source as GraphNode).y ?? 0)
        .attr('x2', d => (d.target as GraphNode).x ?? 0)
        .attr('y2', d => (d.target as GraphNode).y ?? 0)

      node.attr('transform', d => `translate(${d.x ?? 0},${d.y ?? 0})`)
    })
  }

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col font-mono">
      <header className="border-b border-zinc-800 bg-zinc-900/60 px-5 py-3 flex items-center gap-3 flex-shrink-0">
        <button
          type="button"
          onClick={() => navigate(`/investigation/${id}`)}
          className="text-zinc-600 hover:text-cyan-400 transition-colors text-sm"
        >
          ← investigation
        </button>
        <div className="h-4 w-px bg-zinc-800" />
        <span className="text-zinc-300 text-sm">Identity graph</span>
        <div className="flex-1" />
        {loading && <span className="text-zinc-600 text-xs">loading…</span>}
      </header>

      <div className="flex-1 relative min-h-0">
        <svg ref={svgRef} className="w-full h-full min-h-[calc(100vh-3rem)]" />

        {error && (
          <div className="absolute inset-0 flex items-center justify-center">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {tooltip && (
          <div
            className="absolute z-10 max-w-xs bg-zinc-900 border border-zinc-700 rounded p-3 text-xs shadow-lg pointer-events-none"
            style={{ left: tooltip.x + 12, top: tooltip.y + 12 }}
          >
            <p className="text-cyan-400 font-medium mb-1">{tooltip.node.type}</p>
            <p className="text-zinc-300 break-all">{tooltip.node.value}</p>
            {tooltip.node.degree !== undefined && (
              <p className="text-zinc-500 mt-1">connections: {tooltip.node.degree}</p>
            )}
            {tooltip.node.metadata && Object.keys(tooltip.node.metadata).length > 0 && (
              <pre className="text-zinc-500 mt-2 whitespace-pre-wrap">
                {JSON.stringify(tooltip.node.metadata, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
