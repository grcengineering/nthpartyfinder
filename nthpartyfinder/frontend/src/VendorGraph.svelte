<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { writable } from 'svelte/store';
  import { SvelteFlow, Controls, Background, MiniMap, BackgroundVariant } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';

  import RootNode from './nodes/RootNode.svelte';
  import VendorNode from './nodes/VendorNode.svelte';
  import LoadMoreNode from './nodes/LoadMoreNode.svelte';
  import VendorTooltip from './components/VendorTooltip.svelte';

  import type { XYFlowNode, XYFlowEdge, Relationship, DiscoverySource, AggregatedVendor } from './lib/transform';
  import { transformToXyflow, buildChildrenMap } from './lib/transform';

  // Props
  export let relationships: Relationship[] = [];
  export let rootDomain: string = '';

  // Pagination constant
  const VENDORS_PER_PAGE = 10;

  // Transform data with deduplication
  const { nodes: initialNodes, edges: initialEdges, vendors } = transformToXyflow(relationships, rootDomain);

  // Stores
  const nodes = writable<XYFlowNode[]>(initialNodes);
  const edges = writable<XYFlowEdge[]>(initialEdges);

  // Track expanded state and pagination
  const expandedNodes = new Set<string>([rootDomain]);
  const paginationState = new Map<string, { shown: number; total: number }>();

  // Build children map for expand/collapse (using unique children)
  const childrenMap = buildChildrenMap(relationships);

  // Tooltip state
  let tooltipVisible = false;
  let tooltipDomain = '';
  let tooltipOrganization = '';
  let tooltipSources: DiscoverySource[] = [];
  let tooltipPosition = { x: 0, y: 0 };

  // Listen for vendor info events from VendorNode (global event bus bypasses xyflow data pipeline)
  function handleShowVendorInfo(e: Event) {
    const detail = (e as CustomEvent).detail;
    const vendor = vendors.get(detail.domain);

    tooltipDomain = detail.domain;
    tooltipOrganization = vendor?.organization || '';
    tooltipSources = detail.sources || [];

    tooltipPosition = {
      x: window.innerWidth / 2 - 140,
      y: window.innerHeight / 3
    };
    tooltipVisible = true;
  }

  onMount(() => {
    window.addEventListener('show-vendor-info', handleShowVendorInfo);
  });

  onDestroy(() => {
    window.removeEventListener('show-vendor-info', handleShowVendorInfo);
  });

  // Node types (cast to any to avoid strict type checking with SvelteFlow)
  const nodeTypes: any = {
    root: RootNode,
    vendor: VendorNode,
    loadMore: LoadMoreNode
  };

  // Handle node click for expand/collapse
  function handleNodeClick(event: CustomEvent) {
    const nodeId = event.detail.node?.id;
    if (!nodeId) return;

    const node = $nodes.find(n => n.id === nodeId);
    if (!node) return;

    // Handle load more node
    if (node.type === 'loadMore' && node.data.parentId) {
      loadMoreVendors(node.data.parentId);
      return;
    }

    // Toggle expand/collapse for nodes with children
    if (node.data.hasChildren) {
      if (expandedNodes.has(nodeId)) {
        collapseNode(nodeId);
      } else {
        expandNode(nodeId);
      }
    }
  }

  function expandNode(nodeId: string) {
    const children = childrenMap.get(nodeId);
    if (!children || children.size === 0) return;

    const childArray = Array.from(children);

    // Initialize pagination if needed
    if (!paginationState.has(nodeId)) {
      paginationState.set(nodeId, { shown: 0, total: childArray.length });
    }
    const pagination = paginationState.get(nodeId)!;

    // Calculate slice to show
    const startIndex = pagination.shown;
    const endIndex = Math.min(startIndex + VENDORS_PER_PAGE, childArray.length);
    const toShow = childArray.slice(startIndex, endIndex);

    // Calculate positions for new nodes
    const parentNode = $nodes.find(n => n.id === nodeId);
    const parentPos = parentNode?.position || { x: 0, y: 0 };
    const parentLayer = parentNode?.data.layer || 0;

    // Layout constants for vertical (top-down) layout
    const LAYER_SPACING = 180;  // Vertical distance between layers
    const NODE_SPACING = 280;   // Horizontal distance between siblings

    // Show nodes
    nodes.update(ns => {
      return ns.map(n => {
        if (toShow.includes(n.id)) {
          // Calculate horizontal position based on visible siblings (top-down layout)
          const siblingIndex = toShow.indexOf(n.id);
          const totalWidth = (toShow.length - 1) * NODE_SPACING;
          const startX = parentPos.x - totalWidth / 2;

          return {
            ...n,
            hidden: false,
            position: {
              x: startX + siblingIndex * NODE_SPACING,
              y: parentPos.y + LAYER_SPACING
            }
          };
        }
        if (n.id === nodeId) {
          return { ...n, data: { ...n.data, expanded: true } };
        }
        return n;
      });
    });

    // Show edges
    edges.update(es => {
      return es.map(e => {
        if (e.source === nodeId && toShow.includes(e.target)) {
          return { ...e, hidden: false };
        }
        return e;
      });
    });

    pagination.shown = endIndex;
    expandedNodes.add(nodeId);

    // Update or add load more node
    const remaining = childArray.length - pagination.shown;
    updateLoadMoreNode(nodeId, remaining, parentLayer + 1, parentPos);
  }

  function collapseNode(nodeId: string) {
    const children = childrenMap.get(nodeId);
    if (!children) return;

    const childArray = Array.from(children);

    // Recursively collapse children first
    for (const childId of childArray) {
      if (expandedNodes.has(childId)) {
        collapseNode(childId);
      }
    }

    // Hide children nodes and edges
    nodes.update(ns => {
      return ns.map(n => {
        if (childArray.includes(n.id)) {
          return { ...n, hidden: true };
        }
        if (n.id === nodeId) {
          return { ...n, data: { ...n.data, expanded: false } };
        }
        // Hide load more node for this parent
        if (n.type === 'loadMore' && n.data.parentId === nodeId) {
          return { ...n, hidden: true };
        }
        return n;
      });
    });

    edges.update(es => {
      return es.map(e => {
        if (e.source === nodeId) {
          return { ...e, hidden: true };
        }
        return e;
      });
    });

    expandedNodes.delete(nodeId);
    paginationState.delete(nodeId);
  }

  function loadMoreVendors(parentId: string) {
    expandNode(parentId);
  }

  function updateLoadMoreNode(parentId: string, remaining: number, layer: number, parentPos: { x: number; y: number }) {
    const loadMoreId = `loadMore-${parentId}`;
    const LAYER_SPACING = 180;
    const NODE_SPACING = 280;

    // Remove existing load more node
    nodes.update(ns => ns.filter(n => n.id !== loadMoreId));
    edges.update(es => es.filter(e => e.target !== loadMoreId));

    if (remaining <= 0) return;

    // Calculate position at right of siblings (top-down layout)
    const pagination = paginationState.get(parentId);
    const shown = pagination?.shown || VENDORS_PER_PAGE;
    const totalWidth = (shown) * NODE_SPACING;
    const loadMoreX = parentPos.x - totalWidth / 2 + shown * NODE_SPACING;

    // Add new load more node
    const newNode: XYFlowNode = {
      id: loadMoreId,
      type: 'loadMore',
      data: {
        label: `+ ${remaining} more`,
        organization: '',
        domain: '',
        layer: layer,
        childCount: remaining,
        hasChildren: false,
        expanded: false,
        discoveryCount: 0,
        sources: [],
        parentId: parentId
      },
      position: { x: loadMoreX, y: parentPos.y + LAYER_SPACING },
      hidden: false
    };

    nodes.update(ns => [...ns, newNode]);

    // Add edge to load more node
    edges.update(es => [...es, {
      id: `e-loadMore-${parentId}`,
      source: parentId,
      target: loadMoreId,
      type: 'smoothstep',
      hidden: false
    }]);
  }


  function closeTooltip() {
    tooltipVisible = false;
  }

  // Public methods
  export function resetView() {
    for (const nodeId of expandedNodes) {
      if (nodeId !== rootDomain) {
        collapseNode(nodeId);
      }
    }
  }

  export function expandAll() {
    const toExpand = $nodes.filter(n => n.data.hasChildren && !expandedNodes.has(n.id) && !n.hidden);
    for (const node of toExpand) {
      expandNode(node.id);
    }
  }
</script>

<div class="vendor-graph-container">
  <div class="graph-controls">
    <button class="btn btn-primary" on:click={resetView}>Reset View</button>
    <button class="btn btn-secondary" on:click={expandAll}>Expand All</button>
  </div>

  <SvelteFlow
    {nodes}
    {edges}
    {nodeTypes}
    fitView
    on:nodeclick={handleNodeClick}
  >
    <Controls />
    <Background variant={BackgroundVariant.Dots} />
    <MiniMap />
  </SvelteFlow>

  <VendorTooltip
    domain={tooltipDomain}
    organization={tooltipOrganization}
    sources={tooltipSources}
    position={tooltipPosition}
    visible={tooltipVisible}
    on:close={closeTooltip}
  />
</div>

<style>
  .vendor-graph-container {
    width: 100%;
    height: 100%;
    position: relative;
  }

  .graph-controls {
    position: absolute;
    top: 10px;
    left: 10px;
    z-index: 10;
    display: flex;
    gap: 8px;
  }

  .btn {
    padding: 8px 16px;
    border-radius: 6px;
    border: none;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    transition: background-color 0.2s;
  }

  .btn-primary {
    background-color: #6366f1;
    color: white;
  }

  .btn-primary:hover {
    background-color: #4f46e5;
  }

  .btn-secondary {
    background-color: #e5e7eb;
    color: #374151;
  }

  .btn-secondary:hover {
    background-color: #d1d5db;
  }

  :global(.svelte-flow) {
    background-color: #fafafa;
  }
</style>
