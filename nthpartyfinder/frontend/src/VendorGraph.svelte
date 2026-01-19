<script lang="ts">
  import { writable } from 'svelte/store';
  import { SvelteFlow, Controls, Background, MiniMap, BackgroundVariant } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';

  import RootNode from './nodes/RootNode.svelte';
  import VendorNode from './nodes/VendorNode.svelte';
  import LoadMoreNode from './nodes/LoadMoreNode.svelte';

  import type { XYFlowNode, XYFlowEdge, Relationship } from './lib/transform';
  import { buildRelationshipMap } from './lib/transform';

  // Props
  export let initialNodes: XYFlowNode[] = [];
  export let initialEdges: XYFlowEdge[] = [];
  export let rootDomain: string = '';
  export let relationships: Relationship[] = [];

  // Layer limits for progressive disclosure
  const LAYER_LIMITS: Record<number, number> = { 1: 50, 2: 10, 3: 5 };
  const DEFAULT_LIMIT = 5;

  function getLayerLimit(layer: number): number {
    return LAYER_LIMITS[layer] || DEFAULT_LIMIT;
  }

  // Stores
  const nodes = writable<XYFlowNode[]>(initialNodes);
  const edges = writable<XYFlowEdge[]>(initialEdges);

  // Track expanded state and visibility
  const expandedNodes = new Set<string>([rootDomain]);
  const visibilityCount = new Map<string, { shown: number; total: number }>();

  // Relationship map for quick lookup
  const relationshipMap = buildRelationshipMap(relationships);

  // Node types
  const nodeTypes = {
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
    if (node.type === 'loadMore') {
      loadMoreVendors(node.data.parentId);
      return;
    }

    // Toggle expand/collapse
    if (node.data.hasChildren) {
      if (expandedNodes.has(nodeId)) {
        collapseNode(nodeId);
      } else {
        expandNode(nodeId);
      }
    }
  }

  function expandNode(nodeId: string) {
    const children = relationshipMap.get(nodeId) || [];
    if (children.length === 0) return;

    // Get layer info from parent
    const parentNode = $nodes.find(n => n.id === nodeId);
    const childLayer = (parentNode?.data.layer || 0) + 1;
    const limit = getLayerLimit(childLayer);

    // Initialize or get visibility tracking
    if (!visibilityCount.has(nodeId)) {
      visibilityCount.set(nodeId, { shown: 0, total: children.length });
    }
    const visibility = visibilityCount.get(nodeId)!;

    // Calculate how many to show
    const startIndex = visibility.shown;
    const endIndex = Math.min(startIndex + limit, children.length);
    const toShow = children.slice(startIndex, endIndex);

    // Show nodes and edges
    nodes.update(ns => {
      return ns.map(n => {
        if (toShow.some(rel => rel.nth_party_domain === n.id)) {
          return { ...n, hidden: false };
        }
        if (n.id === nodeId) {
          return { ...n, data: { ...n.data, expanded: true } };
        }
        return n;
      });
    });

    edges.update(es => {
      return es.map(e => {
        if (e.source === nodeId && toShow.some(rel => rel.nth_party_domain === e.target)) {
          return { ...e, hidden: false };
        }
        return e;
      });
    });

    visibility.shown = endIndex;
    expandedNodes.add(nodeId);

    // Add load more node if needed
    const remaining = children.length - visibility.shown;
    if (remaining > 0) {
      addLoadMoreNode(nodeId, remaining, childLayer);
    }
  }

  function collapseNode(nodeId: string) {
    const children = relationshipMap.get(nodeId) || [];

    // Recursively collapse children first
    for (const child of children) {
      if (expandedNodes.has(child.nth_party_domain)) {
        collapseNode(child.nth_party_domain);
      }
    }

    // Hide children nodes and edges
    nodes.update(ns => {
      return ns.map(n => {
        if (children.some(rel => rel.nth_party_domain === n.id)) {
          return { ...n, hidden: true };
        }
        if (n.id === nodeId) {
          return { ...n, data: { ...n.data, expanded: false } };
        }
        // Also hide load more nodes for this parent
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
    visibilityCount.delete(nodeId);
  }

  function loadMoreVendors(parentId: string) {
    expandNode(parentId);
  }

  function addLoadMoreNode(parentId: string, remaining: number, layer: number) {
    const loadMoreId = `loadMore-${parentId}`;
    const parentNode = $nodes.find(n => n.id === parentId);
    const parentPos = parentNode?.position || { x: 0, y: 0 };

    // Remove existing load more node if any
    nodes.update(ns => ns.filter(n => n.id !== loadMoreId));
    edges.update(es => es.filter(e => e.target !== loadMoreId));

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
        parentId: parentId
      } as any,
      position: { x: parentPos.x + 200, y: parentPos.y + 100 },
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

  // Public methods for external control
  export function resetView() {
    // Collapse all except root
    for (const nodeId of expandedNodes) {
      if (nodeId !== rootDomain) {
        collapseNode(nodeId);
      }
    }
  }

  export function expandAll() {
    const toExpand = $nodes.filter(n => n.data.hasChildren && !expandedNodes.has(n.id));
    for (const node of toExpand) {
      expandNode(node.id);
    }
  }

  export function focusNode(nodeId: string) {
    // Ensure node is visible by expanding parents
    const node = $nodes.find(n => n.id === nodeId);
    if (node?.hidden) {
      // Find parent and expand
      const rel = relationships.find(r => r.nth_party_domain === nodeId);
      if (rel) {
        focusNode(rel.nth_party_customer_domain);
        expandNode(rel.nth_party_customer_domain);
      }
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
