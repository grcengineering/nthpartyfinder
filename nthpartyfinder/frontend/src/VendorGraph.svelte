<script lang="ts">
  import { onMount, onDestroy, untrack } from 'svelte';
  import { SvelteFlow, Controls, Background, MiniMap, BackgroundVariant, type Node } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';

  import RootNode from './nodes/RootNode.svelte';
  import VendorNode from './nodes/VendorNode.svelte';
  import LoadMoreNode from './nodes/LoadMoreNode.svelte';
  import VendorTooltip from './components/VendorTooltip.svelte';
  import FitViewHelper from './components/FitViewHelper.svelte';

  import type { XYFlowNode, XYFlowEdge, Relationship, DiscoverySource, AggregatedVendor, LayerBand } from './lib/transform';
  import { aggregateVendors, buildChildrenMap } from './lib/transform';

  let { relationships: relationshipsProp = [], rootDomain: rootDomainProp = '' }:
    { relationships?: Relationship[]; rootDomain?: string } = $props();

  // The graph data is constructed once at mount from the initial props (main.ts
  // mounts with fixed props and never updates them). Snapshot the initial values
  // with untrack() so the one-time read does not register a reactive dependency.
  const relationships = untrack(() => relationshipsProp);
  const rootDomain = untrack(() => rootDomainProp);

  const VENDORS_PER_PAGE = 8;
  const ROOT_RADIUS = 300;
  const ROOT_SPACING = 160;
  const CHILD_RADIUS = 280;
  const CHILD_SPACING = 160;
  const NODE_W = 120;
  const NODE_H = 95;

  // Data layer
  const vendors = aggregateVendors(relationships);
  const childrenMap = buildChildrenMap(relationships);
  for (const [domain, children] of childrenMap) {
    if (vendors.has(domain)) vendors.get(domain)!.children = Array.from(children);
  }

  // Build edges
  const allEdges: XYFlowEdge[] = [];
  const addedEdgeKeys = new Set<string>();
  for (const rel of relationships) {
    const key = `${rel.nth_party_customer_domain}->${rel.nth_party_domain}`;
    if (addedEdgeKeys.has(key)) continue;
    addedEdgeKeys.add(key);
    const vendor = vendors.get(rel.nth_party_domain);
    allEdges.push({
      id: `e-${key}`, source: rel.nth_party_customer_domain, target: rel.nth_party_domain,
      type: 'straight', hidden: true,
      data: { recordType: rel.nth_party_record_type, layer: vendor?.layer || rel.nth_party_layer }
    });
  }

  // Build nodes
  const rootChildren = childrenMap.get(rootDomain) || new Set();
  const allNodes: XYFlowNode[] = [{
    id: rootDomain, type: 'root',
    data: {
      label: rootDomain, organization: rootDomain, domain: rootDomain, layer: 0,
      childCount: rootChildren.size, hasChildren: rootChildren.size > 0, expanded: false,
      discoveryCount: 1, sources: []
    },
    position: { x: 0, y: 0 }, hidden: false
  }];

  for (const [domain, vendor] of vendors) {
    if (domain === rootDomain) continue;
    const children = childrenMap.get(domain) || new Set();
    allNodes.push({
      id: domain, type: 'vendor',
      data: {
        label: domain, organization: vendor.organization, domain, layer: vendor.layer,
        layers: vendor.layers,
        childCount: children.size, hasChildren: children.size > 0, expanded: false,
        discoveryCount: vendor.discoveryCount, sources: vendor.sources
      },
      position: { x: 0, y: 0 }, hidden: true
    });
  }

  let nodes = $state.raw<XYFlowNode[]>(allNodes);
  let edges = $state.raw<XYFlowEdge[]>(allEdges);

  const expandedNodes = new Set<string>();
  const paginationState = new Map<string, { shown: number; total: number }>();
  const placedBy = new Map<string, string>();

  let fitViewHelper = $state<FitViewHelper | undefined>(undefined);

  let tooltipVisible = $state(false);
  let tooltipDomain = $state('');
  let tooltipOrganization = $state('');
  let tooltipSources = $state<DiscoverySource[]>([]);
  let tooltipPosition = $state({ x: 0, y: 0 });

  const layerBands: LayerBand[] = [
    { layer: 0, label: 'Target Organization', y: 0, height: 0, width: 0 },
    { layer: 1, label: 'Layer 1 — Direct Vendors', y: 0, height: 0, width: 0 },
    { layer: 2, label: 'Layer 2 — Sub-processors', y: 0, height: 0, width: 0 }
  ];

  function handleShowVendorInfo(e: Event) {
    const detail = (e as CustomEvent).detail;
    const vendor = vendors.get(detail.domain);
    tooltipDomain = detail.domain;
    tooltipOrganization = vendor?.organization || '';
    tooltipSources = detail.sources || [];
    tooltipPosition = { x: window.innerWidth / 2 - 140, y: window.innerHeight / 3 };
    tooltipVisible = true;
  }

  function handleNodeAction(e: Event) {
    const detail = (e as CustomEvent).detail;
    if (detail.action === 'expand') {
      const nodeId = detail.domain;
      if (expandedNodes.has(nodeId)) collapseNode(nodeId);
      else expandNode(nodeId);
    }
  }

  onMount(() => {
    window.addEventListener('show-vendor-info', handleShowVendorInfo);
    window.addEventListener('node-action', handleNodeAction);
    expandNode(rootDomain);
  });

  onDestroy(() => {
    window.removeEventListener('show-vendor-info', handleShowVendorInfo);
    window.removeEventListener('node-action', handleNodeAction);
  });

  const nodeTypes: any = { root: RootNode, vendor: VendorNode, loadMore: LoadMoreNode };

  function handleNodeClick({ node }: { node: Node; event: MouseEvent | TouchEvent }) {
    const nodeId = node?.id;
    if (!nodeId) return;
    const current = nodes.find(n => n.id === nodeId);
    if (!current) return;
    if (current.type === 'loadMore' && current.data.parentId) { loadMoreVendors(current.data.parentId); return; }
    if (current.type === 'root' && current.data.hasChildren) {
      if (expandedNodes.has(nodeId)) collapseNode(nodeId); else expandNode(nodeId);
    }
  }

  // ─── Active layers computation ───
  // Computes which layers each node is actively connected at based on
  // currently visible edges. Updates node.data.activeLayers so VendorNode
  // can show/hide concentric ring borders with smooth transitions.
  function updateActiveLayers() {
    const currentEdges = edges;
    const currentNodes = nodes;

    // Build map: nodeId -> set of layers it's actively connected at
    const activeLayerMap = new Map<string, Set<number>>();

    for (const edge of currentEdges) {
      if (edge.hidden) continue;

      // The target node is connected at the layer determined by its source's layer + 1
      const sourceNode = currentNodes.find(n => n.id === edge.source);
      if (!sourceNode) continue;
      const connectionLayer = (sourceNode.data.layer || 0) + 1;

      const targetId = edge.target;
      if (!activeLayerMap.has(targetId)) {
        activeLayerMap.set(targetId, new Set());
      }
      activeLayerMap.get(targetId)!.add(connectionLayer);
    }

    // Update nodes with their active layers
    nodes = nodes.map(n => {
      if (n.type !== 'vendor') return n;
      const activeLayers = activeLayerMap.get(n.id);
      const newActiveLayers = activeLayers ? Array.from(activeLayers).sort((a, b) => a - b) : [n.data.layer];

      // Only update if changed (avoid unnecessary re-renders)
      const current = n.data.activeLayers || [n.data.layer];
      if (JSON.stringify(current) === JSON.stringify(newActiveLayers)) return n;

      return { ...n, data: { ...n.data, activeLayers: newActiveLayers } };
    });
  }

  // ─── Radial ring computation ───
  function computeRing(
    cx: number, cy: number, count: number, baseRadius: number, minSpacing: number
  ): { x: number; y: number; angle: number }[] {
    if (count === 0) return [];
    const circ = count * minSpacing;
    const r = Math.max(baseRadius, circ / (2 * Math.PI));
    const step = (2 * Math.PI) / count;
    const start = -Math.PI / 2;
    return Array.from({ length: count }, (_, i) => {
      const a = start + i * step;
      return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a), angle: a };
    });
  }

  // ─── Collision detection ───
  function getVisibleRects(excludeIds: Set<string>): { x: number; y: number; w: number; h: number }[] {
    const rects: { x: number; y: number; w: number; h: number }[] = [];
    for (const n of nodes) {
      if (n.hidden || excludeIds.has(n.id)) continue;
      rects.push({ x: n.position.x - NODE_W / 2, y: n.position.y - NODE_H / 2, w: NODE_W, h: NODE_H });
    }
    return rects;
  }

  function overlaps(
    ax: number, ay: number, aw: number, ah: number,
    bx: number, by: number, bw: number, bh: number
  ): boolean {
    return ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
  }

  function hasCollision(x: number, y: number, rects: { x: number; y: number; w: number; h: number }[]): boolean {
    const pad = 20;
    for (const r of rects) {
      if (overlaps(x - NODE_W / 2 - pad, y - NODE_H / 2 - pad, NODE_W + pad * 2, NODE_H + pad * 2, r.x, r.y, r.w, r.h)) {
        return true;
      }
    }
    return false;
  }

  // Resolve collisions using a spiral search: try the initial radial position,
  // then push outward. If that direction is blocked, rotate the angle slightly
  // and try again. This handles cases where an existing node sits directly
  // in the radial path.
  function resolveRadialCollisions(
    positions: { x: number; y: number; angle: number }[],
    cx: number, cy: number,
    excludeIds: Set<string>
  ): { x: number; y: number; angle: number }[] {
    const existingRects = getVisibleRects(excludeIds);
    const placedRects: { x: number; y: number; w: number; h: number }[] = [];

    return positions.map(pos => {
      let { x, y, angle } = pos;
      const baseRadius = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);

      // Spiral search: try increasing radius at the original angle,
      // then try rotating ±15°, ±30°, ±45° at each radius step
      const angleOffsets = [0, 0.26, -0.26, 0.52, -0.52, 0.78, -0.78]; // ~15° increments
      let found = false;

      for (let radiusStep = 0; radiusStep < 8 && !found; radiusStep++) {
        const r = baseRadius + radiusStep * 60;
        for (const angleOff of angleOffsets) {
          const testAngle = angle + angleOff;
          const testX = cx + r * Math.cos(testAngle);
          const testY = cy + r * Math.sin(testAngle);
          if (!hasCollision(testX, testY, existingRects) && !hasCollision(testX, testY, placedRects)) {
            x = testX;
            y = testY;
            angle = testAngle;
            found = true;
            break;
          }
        }
      }

      placedRects.push({ x: x - NODE_W / 2, y: y - NODE_H / 2, w: NODE_W, h: NODE_H });
      return { x, y, angle };
    });
  }

  function doFitView() {
    updateActiveLayers();
    if (fitViewHelper) fitViewHelper.fit();
  }

  // ─── EXPAND ───
  function expandNode(nodeId: string) {
    const children = childrenMap.get(nodeId);
    if (!children || children.size === 0) return;

    const childArray = Array.from(children);
    if (!paginationState.has(nodeId)) {
      paginationState.set(nodeId, { shown: 0, total: childArray.length });
    }
    const pagination = paginationState.get(nodeId)!;
    const endIndex = Math.min(pagination.shown + VENDORS_PER_PAGE, childArray.length);
    const allVisible = childArray.slice(0, endIndex);

    const parentNode = nodes.find(n => n.id === nodeId);
    const parentPos = parentNode?.position || { x: 0, y: 0 };
    const parentLayer = parentNode?.data.layer || 0;
    const isRoot = nodeId === rootDomain;

    const remaining = childArray.length - endIndex;
    const hasLoadMore = remaining > 0;

    // Separate shared vs new nodes
    const toPlace: string[] = [];
    const alreadyVisible: string[] = [];
    for (const childId of allVisible) {
      const childNode = nodes.find(n => n.id === childId);
      if (childNode && !childNode.hidden && placedBy.has(childId) && placedBy.get(childId) !== nodeId) {
        alreadyVisible.push(childId);
      } else {
        toPlace.push(childId);
      }
    }

    const slotsNeeded = toPlace.length;
    const radius = isRoot ? ROOT_RADIUS : CHILD_RADIUS;
    const spacing = isRoot ? ROOT_SPACING : CHILD_SPACING;

    // Compute clean radial ring
    let ring = computeRing(parentPos.x, parentPos.y, slotsNeeded, radius, spacing);

    // For non-root expansions, resolve collisions with existing visible nodes
    if (!isRoot && ring.length > 0) {
      const excludeIds = new Set([...toPlace, nodeId, `loadMore-${nodeId}`]);
      ring = resolveRadialCollisions(ring, parentPos.x, parentPos.y, excludeIds);
    }

    // Map positions
    const positionMap = new Map<string, { x: number; y: number }>();
    toPlace.forEach((id, i) => { if (i < ring.length) positionMap.set(id, ring[i]); });
    const loadMoreId = `loadMore-${nodeId}`;
    if (hasLoadMore) {
      positionMap.set(loadMoreId, { x: parentPos.x, y: parentPos.y + 120 });
    }

    // Update node positions
    nodes = nodes.map(n => {
      const pos = positionMap.get(n.id);
      if (pos) {
        placedBy.set(n.id, nodeId);
        return { ...n, hidden: false, position: { x: pos.x, y: pos.y } };
      }
      if (alreadyVisible.includes(n.id)) return { ...n, hidden: false };
      if (n.id === nodeId) return { ...n, data: { ...n.data, expanded: true } };
      return n;
    });

    // Layer colors for edges
    const layerEdgeColors: Record<number, string> = {
      1: '#3b82f6', 2: '#10b981', 3: '#f59e0b', 4: '#ef4444'
    };

    // Show edges
    edges = edges.map(e => {
      if (e.source === nodeId && allVisible.includes(e.target)) {
        const isShared = alreadyVisible.includes(e.target);
        if (isShared) {
          // Use the child's layer from this parent's perspective (parentLayer + 1)
          const deeperLayer = parentLayer + 1;
          const edgeColor = layerEdgeColors[deeperLayer] || layerEdgeColors[4] || '#94a3b8';
          return {
            ...e, hidden: false, type: 'straight',
            style: `stroke: ${edgeColor}; stroke-width: 1; stroke-dasharray: 6 4;`
          };
        }
        return {
          ...e, hidden: false, type: 'straight',
          style: 'stroke: #b0bec5; stroke-width: 1.5;'
        };
      }
      return e;
    });

    pagination.shown = endIndex;
    expandedNodes.add(nodeId);

    updateLoadMoreNode(nodeId, remaining, parentLayer + 1, positionMap.get(loadMoreId));

    // Global separation pass: push apart any overlapping visible nodes
    separateOverlappingNodes();
    doFitView();
  }

  // Global separation pass: iterates over ALL visible non-root, non-loadMore node
  // pairs and pushes apart any that overlap. Runs multiple iterations to resolve
  // chain collisions (A pushes B into C, so C needs pushing too).
  // Root node is anchored (never moves). Root's direct children on the ring are
  // also anchored — only deeper nodes get pushed.
  function separateOverlappingNodes() {
    const pad = 30; // Minimum gap between node edges
    const rootPos = nodes.find(n => n.id === rootDomain)?.position || { x: 0, y: 0 };

    // Identify anchored nodes: root + root's direct ring children
    const anchored = new Set<string>([rootDomain]);
    const rootPagination = paginationState.get(rootDomain);
    if (rootPagination) {
      const rootChildArray = Array.from(childrenMap.get(rootDomain) || []);
      rootChildArray.slice(0, rootPagination.shown).forEach(id => anchored.add(id));
    }
    // LoadMore nodes for root are also anchored
    anchored.add(`loadMore-${rootDomain}`);

    const iterations = 5;

    for (let iter = 0; iter < iterations; iter++) {
      const currentNodes = nodes.filter(n => !n.hidden && n.type !== 'group');
      let anyMoved = false;

      for (let i = 0; i < currentNodes.length; i++) {
        for (let j = i + 1; j < currentNodes.length; j++) {
          const a = currentNodes[i];
          const b = currentNodes[j];

          // Check overlap with padding
          const ax = a.position.x, ay = a.position.y;
          const bx = b.position.x, by = b.position.y;
          const overlapX = (NODE_W + pad) - Math.abs(ax - bx);
          const overlapY = (NODE_H + pad) - Math.abs(ay - by);

          if (overlapX > 0 && overlapY > 0) {
            // Nodes overlap — compute push direction
            let dx = bx - ax;
            let dy = by - ay;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 1) { dx = 1; dy = 0; } // Prevent zero-distance
            else { dx /= dist; dy /= dist; }

            // Push amount: half the overlap along the smaller axis
            const push = Math.min(overlapX, overlapY) / 2 + 5;

            const aAnchored = anchored.has(a.id);
            const bAnchored = anchored.has(b.id);

            if (aAnchored && bAnchored) continue; // Both anchored, skip

            if (aAnchored) {
              // Only push B
              currentNodes[j] = { ...b, position: { x: bx + dx * push * 2, y: by + dy * push * 2 } };
            } else if (bAnchored) {
              // Only push A
              currentNodes[i] = { ...a, position: { x: ax - dx * push * 2, y: ay - dy * push * 2 } };
            } else {
              // Push both apart equally
              currentNodes[i] = { ...a, position: { x: ax - dx * push, y: ay - dy * push } };
              currentNodes[j] = { ...b, position: { x: bx + dx * push, y: by + dy * push } };
            }
            anyMoved = true;
          }
        }
      }

      if (!anyMoved) break; // Converged

      // Apply positions back to the store
      const posMap = new Map<string, { x: number; y: number }>();
      for (const n of currentNodes) posMap.set(n.id, n.position);

      nodes = nodes.map(n => {
        const newPos = posMap.get(n.id);
        if (newPos && !anchored.has(n.id)) {
          return { ...n, position: newPos };
        }
        return n;
      });

      // Also move loadMore nodes that belong to pushed parents
      nodes = nodes.map(n => {
        if (n.type === 'loadMore' && n.data.parentId) {
          const parentPos = posMap.get(n.data.parentId);
          if (parentPos && !anchored.has(n.data.parentId)) {
            return { ...n, position: { x: parentPos.x, y: parentPos.y + 120 } };
          }
        }
        return n;
      });
    }
  }

  // ─── COLLAPSE ───
  function collapseNode(nodeId: string) {
    const children = childrenMap.get(nodeId);
    if (!children) return;
    const childArray = Array.from(children);

    for (const childId of childArray) {
      if (expandedNodes.has(childId)) collapseNode(childId);
    }

    const loadMoreId = `loadMore-${nodeId}`;

    for (const childId of childArray) {
      if (placedBy.get(childId) === nodeId) placedBy.delete(childId);
    }

    nodes = nodes.filter(n => n.id !== loadMoreId).map(n => {
      if (childArray.includes(n.id)) {
        if (placedBy.has(n.id)) return n; // Shared node stays visible
        return { ...n, hidden: true };
      }
      if (n.id === nodeId) return { ...n, data: { ...n.data, expanded: false } };
      return n;
    });

    edges = edges.map(e => e.source === nodeId ? { ...e, hidden: true } : e);
    expandedNodes.delete(nodeId);
    paginationState.delete(nodeId);
    doFitView();
  }

  function loadMoreVendors(parentId: string) { expandNode(parentId); }

  function updateLoadMoreNode(parentId: string, remaining: number, layer: number, pos?: { x: number; y: number }) {
    const loadMoreId = `loadMore-${parentId}`;
    nodes = nodes.filter(n => n.id !== loadMoreId);
    edges = edges.filter(e => e.target !== loadMoreId);
    if (remaining <= 0) return;

    nodes = [...nodes, {
      id: loadMoreId, type: 'loadMore',
      data: { label: `+ ${remaining} more`, organization: '', domain: '', layer,
        childCount: remaining, hasChildren: false, expanded: false,
        discoveryCount: 0, sources: [], parentId },
      position: pos || { x: 0, y: 0 }, hidden: false
    }];

    edges = [...edges, {
      id: `e-loadMore-${parentId}`, source: parentId, target: loadMoreId,
      type: 'straight', hidden: false
    }];
  }

  function closeTooltip() { tooltipVisible = false; }

  export function resetView() {
    for (const nodeId of Array.from(expandedNodes)) collapseNode(nodeId);
    expandedNodes.clear();
    paginationState.clear();
    placedBy.clear();
    tooltipVisible = false;
    nodes = nodes.filter(n => n.type !== 'loadMore');
    nodes = nodes.map(n => ({ ...n, hidden: n.id !== rootDomain, data: { ...n.data, expanded: false } }));
    edges = edges.map(e => ({ ...e, hidden: true }));
    expandNode(rootDomain);
  }
</script>

<div class="vendor-graph-container">
  <div class="graph-controls">
    <button class="btn btn-primary" onclick={resetView}>Reset View</button>
  </div>

  <div class="layer-bands-overlay">
    {#each layerBands as band}
      <div class="layer-band-label" data-layer={band.layer}>{band.label}</div>
    {/each}
  </div>

  <SvelteFlow
    bind:nodes bind:edges {nodeTypes} fitView
    minZoom={0.05}
    maxZoom={2}
    onnodeclick={handleNodeClick}
    defaultEdgeOptions={{ type: 'straight', style: 'stroke: #b0bec5; stroke-width: 1.5;' }}
  >
    <Controls />
    <Background variant={BackgroundVariant.Dots} gap={24} />
    <MiniMap />
    <FitViewHelper bind:this={fitViewHelper} />
  </SvelteFlow>

  <VendorTooltip
    domain={tooltipDomain} organization={tooltipOrganization}
    sources={tooltipSources} position={tooltipPosition}
    visible={tooltipVisible} onclose={closeTooltip}
  />
</div>

<style>
  .vendor-graph-container { width: 100%; height: 100%; position: relative; }
  .graph-controls { position: absolute; top: 10px; left: 10px; z-index: 10; display: flex; gap: 8px; }
  .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; font-weight: 500; }
  .btn-primary { background-color: #6366f1; color: white; }
  .btn-primary:hover { background-color: #4f46e5; }

  .layer-bands-overlay {
    position: absolute; top: 10px; right: 10px; z-index: 10;
    display: flex; flex-direction: column; gap: 4px; pointer-events: none;
  }
  .layer-band-label {
    padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
    letter-spacing: 0.5px; text-transform: uppercase; opacity: 0.8;
  }
  .layer-band-label[data-layer="0"] { background: rgba(99, 102, 241, 0.15); color: #6366f1; }
  .layer-band-label[data-layer="1"] { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
  .layer-band-label[data-layer="2"] { background: rgba(16, 185, 129, 0.15); color: #10b981; }

  :global(.svelte-flow) { background-color: #eef2f9; }
  :global(.svelte-flow .svelte-flow__edge path) { stroke: #b0bec5; stroke-width: 1.5; }
  :global(.svelte-flow .svelte-flow__edge:hover path) { stroke: #6366f1; stroke-width: 2.5; }

  :global(.svelte-flow .svelte-flow__handle) {
    width: 1px; height: 1px; background: transparent; border: none; opacity: 0;
  }

</style>
