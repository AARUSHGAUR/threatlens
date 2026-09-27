/**
 * IOCRelationshipGraph - interactive force-directed relationship graph.
 *
 * WHY A HAND-ROLLED SIMULATION INSTEAD OF A LIBRARY:
 *  - d3-force would be the obvious choice, but the layout here is small (< 60
 *    nodes) and the algorithm is short enough to read, audit and explain during
 *    a viva - which matters more here than saving 40 KB.
 *  - It is DETERMINISTIC: initial positions are derived from the node index and
 *    the simulation runs a fixed number of iterations with a cooling schedule,
 *    so the same investigation always renders the same picture. A library with a
 *    random initial layout would make screenshots unstable.
 *  - Physics: repulsion between all node pairs (Coulomb), spring attraction
 *    along edges (Hooke) proportional to 1/distance, a weak centring pull, and
 *    an adaptive step size that cools over time. Standard, well-understood model.
 *
 * Interaction: drag nodes, pan the canvas, wheel-zoom, hover for the relation
 * description, click to focus a node's neighbourhood.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CorrelationEdge, CorrelationGraph, CorrelationNode, CorrelationNodeType } from '../api/types';

const NODE_COLOUR: Record<CorrelationNodeType, string> = {
  ioc: '#22d3ee',
  ip: '#f97316',
  domain: '#34d399',
  url: '#fbbf24',
  hash: '#f472b6',
  email: '#94a3b8',
  malware: '#ef4444',
  actor: '#a78bfa',
  campaign: '#818cf8',
  asn: '#64748b',
};

const LEGEND: Array<{ type: CorrelationNodeType; label: string }> = [
  { type: 'ioc', label: 'Subject indicator' },
  { type: 'ip', label: 'IP address' },
  { type: 'domain', label: 'Domain' },
  { type: 'url', label: 'URL' },
  { type: 'hash', label: 'File hash' },
  { type: 'email', label: 'Email' },
  { type: 'malware', label: 'Malware' },
  { type: 'actor', label: 'Threat actor' },
  { type: 'campaign', label: 'Campaign / ATT&CK' },
  { type: 'asn', label: 'Network / ASN' },
];

interface Sim {
  id: string;
  node: CorrelationNode;
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
}

/** Radius lookup with a safe default, so an unmapped entity type can never
 *  produce `NaN` geometry (React would render an invalid SVG attribute). */
const radiusOf = (type: string): number =>
  NODE_RADIUS[type as CorrelationNodeType] ?? 8;

const NODE_RADIUS: Record<CorrelationNodeType, number> = {
  ioc: 13,
  actor: 11,
  malware: 10,
  campaign: 8,
  asn: 10,
  ip: 8,
  domain: 8,
  url: 8,
  hash: 8,
  email: 8,
};

const truncate = (s: string, n: number): string => (s.length <= n ? s : `${s.slice(0, n - 1)}…`);

/**
 * Deterministic force-directed layout.
 * Returns positions in a viewBox coordinate space of `width x height`.
 */
function layout(graph: CorrelationGraph, width: number, height: number): Map<string, { x: number; y: number }> {
  const cx = width / 2;
  const cy = height / 2;
  // Slightly taller virtual canvas: labels sit under nodes, so vertical room is
  // what actually prevents overlap in a dense graph.
  const count = graph.nodes.length;

  const sims: Sim[] = graph.nodes.map((node, index) => {
    // Subject at the centre; others on a golden-angle spiral so the initial
    // state is spread out but fully deterministic.
    if (node.isSubject) {
      return { id: node.id, node, x: cx, y: cy, vx: 0, vy: 0, r: NODE_RADIUS[node.type] };
    }
    const angle = index * 2.399963229728653; // golden angle in radians
    const radius = Math.min(width, height) * 0.32 * Math.sqrt(index / Math.max(1, count));
    return {
      id: node.id,
      node,
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      r: radiusOf(node.type),
    };
  });

  const index = new Map(sims.map((s, i) => [s.id, i]));
  const links = graph.edges
    .map((e) => ({ s: index.get(e.source), t: index.get(e.target) }))
    .filter((l): l is { s: number; t: number } => l.s !== undefined && l.t !== undefined);

  const ITERATIONS = 280;
  for (let step = 0; step < ITERATIONS; step += 1) {
    const cooling = 1 - step / ITERATIONS;
    const alpha = 0.9 * cooling * cooling;

    // Repulsion (Coulomb) between every pair.
    for (let i = 0; i < sims.length; i += 1) {
      for (let j = i + 1; j < sims.length; j += 1) {
        const a = sims[i];
        const b = sims[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let distSq = dx * dx + dy * dy;
        if (distSq < 0.01) {
          // Deterministic jitter for coincident nodes (no RNG).
          dx = ((i % 7) - 3) * 0.5 + 0.1;
          dy = ((j % 5) - 2) * 0.5 + 0.1;
          distSq = dx * dx + dy * dy;
        }
        const dist = Math.sqrt(distSq);
        const force = (9000 / distSq) * alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        // Guard the accumulation: a single non-finite force would otherwise
        // poison a node's position for every remaining iteration and render
        // `NaN` into the SVG attributes.
        if (!Number.isFinite(fx) || !Number.isFinite(fy)) continue;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }

    // Spring attraction along edges.
    for (const link of links) {
      const a = sims[link.s];
      const b = sims[link.t];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const target = a.node.isSubject || b.node.isSubject ? 205 : 150;
      const force = ((dist - target) / dist) * 0.05 * alpha;
      const fx = dx * force;
      const fy = dy * force;
      if (!Number.isFinite(fx) || !Number.isFinite(fy)) continue;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    // Weak centring keeps disconnected components on screen.
    for (const s of sims) {
      s.vx += (cx - s.x) * 0.008 * alpha;
      s.vy += (cy - s.y) * 0.008 * alpha;
      s.vx *= 0.82;
      s.vy *= 0.82;
      const stepX = Math.max(-14, Math.min(14, s.vx));
      const stepY = Math.max(-14, Math.min(14, s.vy));
      if (Number.isFinite(stepX)) s.x += stepX;
      if (Number.isFinite(stepY)) s.y += stepY;
    }
  }

  // Clamp inside the viewBox and repair any non-finite position by falling
  // back to the centre, so the renderer can trust every coordinate.
  const margin = 26;
  for (const s of sims) {
    s.x = Number.isFinite(s.x) ? s.x : cx;
    s.y = Number.isFinite(s.y) ? s.y : cy;
    s.x = Math.max(margin + s.r, Math.min(width - margin - s.r, s.x));
    s.y = Math.max(margin + s.r, Math.min(height - margin - s.r, s.y));
  }

  return new Map(sims.map((s) => [s.id, { x: s.x, y: s.y }]));
}

/**
 * Greedy, deterministic label de-collision.
 *
 * Nodes are placed in priority order (subject first, then by importance) and a
 * label is drawn only if its bounding box does not overlap an already-placed one.
 * Without this, a dense graph renders as an unreadable pile of overlapping text.
 */
function placeLabels(
  graph: CorrelationGraph,
  positions: Map<string, { x: number; y: number }>,
): Set<string> {
  const CH = 4.55; // approx advance width per char at 8.5px mono
  const LH = 11;
  const boxes: Array<[number, number, number, number]> = [];
  const visible = new Set<string>();

  const importance = (n: CorrelationNode): number =>
    (n.isSubject ? 1000 : 0) + NODE_RADIUS[n.type] * 10;

  const ordered = [...graph.nodes].sort((a, b) => importance(b) - importance(a));

  for (const node of ordered) {
    const pos = positions.get(node.id);
    if (!pos) continue;
    const text = truncate(node.label, node.type === 'hash' ? 16 : 22);
    const w = text.length * CH;
    const x0 = pos.x - w / 2;
    const x1 = pos.x + w / 2;
    const y0 = pos.y + radiusOf(node.type) + 2;
    const y1 = y0 + LH;
    const clash = boxes.some(
      ([bx0, by0, bx1, by1]) => !(x1 < bx0 - 4 || x0 > bx1 + 4 || y1 < by0 - 2 || y0 > by1 + 2),
    );
    if (clash && !node.isSubject) continue;
    boxes.push([x0, y0, x1, y1]);
    visible.add(node.id);
  }
  return visible;
}

export const IOCRelationshipGraph = ({ graph, height = 470 }: { graph: CorrelationGraph; height?: number }) => {
  const WIDTH = 1000;
  const containerRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [drag, setDrag] = useState<{ id: string; dx: number; dy: number } | null>(null);
  const [pan, setPan] = useState<{ x: number; y: number; startX: number; startY: number } | null>(null);
  const [hover, setHover] = useState<{ node: CorrelationNode; x: number; y: number } | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [positions, setPositions] = useState<Map<string, { x: number; y: number }> | null>(null);
  const [labelVisible, setLabelVisible] = useState<Set<string>>(new Set());

  // Recompute the layout when the graph changes.
  useEffect(() => {
    const next = layout(graph, WIDTH, height);
    setPositions(next);
    setLabelVisible(placeLabels(graph, next));
    setFocus(null);
  }, [graph, height]);

  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph.nodes]);

  const visibleEdges = useMemo(() => {
    if (!focus) return graph.edges;
    return graph.edges.filter((e) => e.source === focus || e.target === focus);
  }, [graph.edges, focus]);

  const dimmed = useCallback(
    (nodeId: string): boolean => {
      if (!focus) return false;
      if (nodeId === focus) return false;
      return !visibleEdges.some((e) => e.source === nodeId || e.target === nodeId);
    },
    [focus, visibleEdges],
  );

  const toSvg = useCallback(
    (clientX: number, clientY: number): { x: number; y: number } => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return { x: 0, y: 0 };
      return {
        x: ((clientX - rect.left) / rect.width) * WIDTH,
        y: ((clientY - rect.top) / rect.height) * height,
      };
    },
    [height],
  );

  if (graph.nodes.length <= 1) {
    return (
      <div className="empty-state">
        <p>No related entities were reported for this indicator.</p>
        <p className="small">
          The correlation graph is built only from relationships that sources actually returned — nothing is inferred
          to fill the view.
        </p>
      </div>
    );
  }

  return (
    <div className="graph-wrap" ref={containerRef} style={{ height }}>
      <div className="graph-controls">
        <button
          className="btn btn-sm btn-ghost"
          type="button"
          title="Zoom in"
          onClick={() => setView((v) => ({ ...v, k: Math.min(3, v.k * 1.25) }))}
        >
          +
        </button>
        <button
          className="btn btn-sm btn-ghost"
          type="button"
          title="Zoom out"
          onClick={() => setView((v) => ({ ...v, k: Math.max(0.4, v.k / 1.25) }))}
        >
          −
        </button>
        <button
          className="btn btn-sm btn-ghost"
          type="button"
          title="Reset view"
          onClick={() => {
            setView({ x: 0, y: 0, k: 1 });
            setFocus(null);
            const next = layout(graph, WIDTH, height);
            setPositions(next);
            setLabelVisible(placeLabels(graph, next));
          }}
        >
          ⟲
        </button>
      </div>

      {focus ? (
        <div style={{ position: 'absolute', top: 8, left: 8, zIndex: 3 }}>
          <button className="btn btn-sm" type="button" onClick={() => setFocus(null)}>
            Clear focus ✕
          </button>
        </div>
      ) : null}

      <svg
        className="graph-svg"
        viewBox={`0 0 ${WIDTH} ${height}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ height }}
        onMouseDown={(e) => {
          if (e.target === e.currentTarget) setPan({ x: view.x, y: view.y, startX: e.clientX, startY: e.clientY });
        }}
        onMouseMove={(e) => {
          if (drag && positions) {
            const p = toSvg(e.clientX, e.clientY);
            setPositions((prev) => {
              if (!prev) return prev;
              const next = new Map(prev);
              next.set(drag.id, { x: p.x - drag.dx, y: p.y - drag.dy });
              return next;
            });
          } else if (pan) {
            setView((v) => ({ ...v, x: pan.x + (e.clientX - pan.startX), y: pan.y + (e.clientY - pan.startY) }));
          }
        }}
        onMouseUp={() => {
          setDrag(null);
          setPan(null);
        }}
        onMouseLeave={() => {
          setDrag(null);
          setPan(null);
          setHover(null);
        }}
        onWheel={(e) => {
          const factor = e.deltaY > 0 ? 0.9 : 1.1;
          setView((v) => ({ ...v, k: Math.max(0.4, Math.min(3, v.k * factor)) }));
        }}
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b4757" />
          </marker>
          <marker id="arrow-active" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#22d3ee" />
          </marker>
        </defs>

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {positions
            ? visibleEdges.map((edge: CorrelationEdge) => {
                const a = positions.get(edge.source);
                const b = positions.get(edge.target);
                if (!a || !b) return null;
                const active = focus === edge.source || focus === edge.target;
                // Trim the line to the node boundary so the arrowhead is visible.
                const dx = b.x - a.x;
                const dy = b.y - a.y;
                const dist = Math.max(1, Math.hypot(dx, dy));
                const ux = dx / dist;
                const uy = dy / dist;
                const rA = radiusOf(nodeById.get(edge.source)?.type ?? 'ioc');
                const rB = radiusOf(nodeById.get(edge.target)?.type ?? 'ioc');
                const x1 = a.x + ux * rA;
                const y1 = a.y + uy * rA;
                const x2 = b.x - ux * (rB + 3);
                const y2 = b.y - uy * (rB + 3);
                if (![x1, y1, x2, y2].every(Number.isFinite)) return null;
                return (
                  <line
                    key={edge.id}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke={active ? '#22d3ee' : '#2b3644'}
                    strokeWidth={active ? 1.4 : 0.8}
                    strokeOpacity={focus && !active ? 0.25 : 1}
                    markerEnd={active ? 'url(#arrow-active)' : 'url(#arrow)'}
                  />
                );
              })
            : null}

          {positions
            ? graph.nodes.map((node) => {
                const pos = positions.get(node.id);
                if (!pos) return null;
                if (focus && dimmed(node.id)) return null;
                const colour = NODE_COLOUR[node.type] ?? '#64748b';
                const isSubject = node.isSubject;
                const radius = radiusOf(node.type);
                return (
                  <g
                    key={node.id}
                    style={{ cursor: 'grab' }}
                    onMouseDown={(e) => {
                      e.stopPropagation();
                      setDrag({ id: node.id, dx: toSvg(e.clientX, e.clientY).x - pos.x, dy: toSvg(e.clientY, e.clientY).y - pos.y });
                    }}
                    onMouseEnter={() => setHover({ node, x: pos.x, y: pos.y })}
                    onMouseLeave={() => setHover(null)}
                    onClick={() => setFocus((f) => (f === node.id ? null : node.id))}
                  >
                    {isSubject ? (
                      <circle cx={pos.x} cy={pos.y} r={radius + 6} fill="none" stroke={colour} strokeWidth={1} strokeDasharray="3 3" opacity={0.7} />
                    ) : null}
                    <circle
                      cx={pos.x}
                      cy={pos.y}
                      r={radius}
                      fill={`${colour}22`}
                      stroke={colour}
                      strokeWidth={isSubject ? 2 : 1.2}
                    />
                    {labelVisible.has(node.id) || hover?.node.id === node.id || focus === node.id ? (
                      <text x={pos.x} y={pos.y + radius + 10} textAnchor="middle" className="graph-node-label">
                        {truncate(node.label, node.type === 'hash' ? 16 : 22)}
                      </text>
                    ) : null}
                  </g>
                );
              })
            : null}
        </g>
      </svg>

      {hover ? (
        <div
          className="graph-tip"
          style={{
            left: `${(hover.x / WIDTH) * 100}%`,
            top: `${(hover.y / height) * 100}%`,
            transform: 'translate(12px, -50%)',
          }}
        >
          <div className="graph-tip-rel" style={{ color: NODE_COLOUR[hover.node.type] }}>
            {hover.node.type}
            {hover.node.isSubject ? ' · subject' : ''}
          </div>
          <div className="mono" style={{ wordBreak: 'break-all', marginTop: 3 }}>
            {hover.node.label}
          </div>
          {hover.node.meta
            ? Object.entries(hover.node.meta)
                .filter(([, v]) => v !== null && v !== undefined && v !== '')
                .slice(0, 3)
                .map(([k, v]) => (
                  <div key={k} className="tiny dim">
                    {k}: {String(v)}
                  </div>
                ))
            : null}
          {focus === null ? <div className="tiny dim mt-2">click to focus · drag to move</div> : null}
        </div>
      ) : null}

      <div className="graph-legend">
        {LEGEND.filter((l) => graph.nodes.some((n) => n.type === l.type)).map((l) => (
          <span key={l.type} className="graph-legend-item">
            <span className="graph-legend-swatch" style={{ background: NODE_COLOUR[l.type] }} />
            {l.label}
          </span>
        ))}
        <span className="graph-legend-item dim">
          {graph.nodes.length} entities · {graph.edges.length} relationships
        </span>
      </div>
    </div>
  );
};
