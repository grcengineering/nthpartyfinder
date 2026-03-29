// ELK layout engine integration for collision-free vendor graph positioning.
// ELK handles compound/group nodes natively — when a vendor node expands,
// its children become contained inside a compound ELK node. ELK then
// recomputes ALL positions so nothing overlaps.
//
// KEY DESIGN DECISION: The root node is NEVER a compound group. Its children
// are always independent top-level nodes connected by edges, giving a clean
// radial/layered spread. Only non-root vendor nodes become compound groups
// when expanded (like Wiz's CVE findings container).

import ELK from 'elkjs/lib/elk.bundled.js';
import type { XYFlowNode, XYFlowEdge } from './transform';

const elk = new ELK();

// Node dimensions for ELK layout computation
const ROOT_WIDTH = 120;
const ROOT_HEIGHT = 100;
const VENDOR_WIDTH = 120;
const VENDOR_HEIGHT = 95;
const LOADMORE_WIDTH = 100;
const LOADMORE_HEIGHT = 80;
const GROUP_PADDING = 25;
const CHILD_COLS = 3;
const CHILD_H_GAP = 15;
const CHILD_V_GAP = 15;

interface ElkNode {
  id: string;
  width: number;
  height: number;
  children?: ElkNode[];
  layoutOptions?: Record<string, string>;
  x?: number;
  y?: number;
}

interface ElkEdge {
  id: string;
  sources: string[];
  targets: string[];
}

interface ElkGraph {
  id: string;
  layoutOptions: Record<string, string>;
  children: ElkNode[];
  edges: ElkEdge[];
}

// Compute the dimensions of a group node that contains N children in a grid
function computeGroupDimensions(childCount: number): { width: number; height: number } {
  const cols = Math.min(childCount, CHILD_COLS);
  const rows = Math.ceil(childCount / cols);
  const width = cols * VENDOR_WIDTH + (cols - 1) * CHILD_H_GAP + GROUP_PADDING * 2;
  const height = rows * VENDOR_HEIGHT + (rows - 1) * CHILD_V_GAP + GROUP_PADDING * 2 + 35;
  return { width: Math.max(width, 200), height: Math.max(height, 150) };
}

export async function computeElkLayout(
  xyNodes: XYFlowNode[],
  xyEdges: XYFlowEdge[],
  expandedNodes: Set<string>,
  childrenMap: Map<string, Set<string>>,
  paginationState: Map<string, { shown: number; total: number }>,
  rootDomain: string
): Promise<Map<string, { x: number; y: number; width?: number; height?: number }>> {

  const visibleNodes = xyNodes.filter(n => !n.hidden && n.type !== 'group');
  const visibleEdges = xyEdges.filter(e => !e.hidden);

  // Track which nodes are children inside a NON-ROOT expanded group
  const childOfGroup = new Map<string, string>(); // childId -> parentGroupId
  for (const parentId of expandedNodes) {
    // ROOT node children are NEVER grouped — they stay as independent top-level nodes
    if (parentId === rootDomain) continue;

    const children = childrenMap.get(parentId);
    if (!children) continue;
    const pagination = paginationState.get(parentId);
    if (!pagination) continue;
    const childArray = Array.from(children);
    const visibleChildren = childArray.slice(0, pagination.shown);
    for (const childId of visibleChildren) {
      childOfGroup.set(childId, parentId);
    }
    const loadMoreId = `loadMore-${parentId}`;
    if (xyNodes.find(n => n.id === loadMoreId && !n.hidden)) {
      childOfGroup.set(loadMoreId, parentId);
    }
  }

  // Build top-level ELK nodes
  const topLevelNodes: ElkNode[] = [];
  const processedIds = new Set<string>();

  for (const node of visibleNodes) {
    if (processedIds.has(node.id)) continue;
    if (childOfGroup.has(node.id)) continue; // Will be added as child of its group

    if (expandedNodes.has(node.id) && node.id !== rootDomain) {
      // NON-ROOT expanded node: build as compound node with children inside
      const children = childrenMap.get(node.id);
      if (children) {
        const pagination = paginationState.get(node.id);
        const childArray = Array.from(children);
        const visibleChildren = pagination ? childArray.slice(0, pagination.shown) : [];

        const elkChildren: ElkNode[] = [];
        for (const childId of visibleChildren) {
          const childNode = visibleNodes.find(n => n.id === childId);
          if (childNode) {
            elkChildren.push({ id: childId, width: VENDOR_WIDTH, height: VENDOR_HEIGHT });
            processedIds.add(childId);
          }
        }

        // Add loadMore node as child if present
        const loadMoreId = `loadMore-${node.id}`;
        const loadMoreNode = xyNodes.find(n => n.id === loadMoreId && !n.hidden);
        if (loadMoreNode) {
          elkChildren.push({ id: loadMoreId, width: LOADMORE_WIDTH, height: LOADMORE_HEIGHT });
          processedIds.add(loadMoreId);
        }

        if (elkChildren.length > 0) {
          const groupDims = computeGroupDimensions(elkChildren.length);
          topLevelNodes.push({
            id: node.id,
            width: groupDims.width,
            height: groupDims.height,
            children: elkChildren,
            layoutOptions: {
              'elk.algorithm': 'rectpacking',
              'elk.rectpacking.widthApproximation.targetWidth': String(Math.min(elkChildren.length, CHILD_COLS) * (VENDOR_WIDTH + CHILD_H_GAP)),
              'elk.padding': `[top=${GROUP_PADDING + 35},left=${GROUP_PADDING},bottom=${GROUP_PADDING},right=${GROUP_PADDING}]`,
              'elk.spacing.nodeNode': String(CHILD_H_GAP)
            }
          });
        } else {
          topLevelNodes.push({ id: node.id, width: VENDOR_WIDTH, height: VENDOR_HEIGHT });
        }
      }
    } else {
      // Regular node (including ROOT, whether expanded or not)
      const w = node.type === 'root' ? ROOT_WIDTH : (node.type === 'loadMore' ? LOADMORE_WIDTH : VENDOR_WIDTH);
      const h = node.type === 'root' ? ROOT_HEIGHT : (node.type === 'loadMore' ? LOADMORE_HEIGHT : VENDOR_HEIGHT);
      topLevelNodes.push({ id: node.id, width: w, height: h });
    }
    processedIds.add(node.id);
  }

  // Build ELK edges between top-level nodes
  const elkEdges: ElkEdge[] = [];
  const addedEdgeKeys = new Set<string>();
  for (const edge of visibleEdges) {
    let source = edge.source;
    let target = edge.target;

    // If target is inside a group, route edge to the group parent instead
    if (childOfGroup.has(target)) {
      target = childOfGroup.get(target)!;
    }
    // If source is inside a group, route edge from the group parent
    if (childOfGroup.has(source)) {
      source = childOfGroup.get(source)!;
    }

    if (source === target) continue;
    const edgeKey = `${source}->${target}`;
    if (addedEdgeKeys.has(edgeKey)) continue;
    addedEdgeKeys.add(edgeKey);

    // Only add if both endpoints exist as top-level nodes
    if (topLevelNodes.find(n => n.id === source) && topLevelNodes.find(n => n.id === target)) {
      elkEdges.push({ id: `elk-${edgeKey}`, sources: [source], targets: [target] });
    }
  }

  // Use 'stress' algorithm for a radial-like organic spread at the top level.
  // ELK stress minimizes edge lengths while maintaining node separation,
  // producing a natural radial layout centered on the root.
  // Compound children inside groups still use rectpacking (set above per-group).
  const elkGraph: ElkGraph = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'stress',
      'elk.stress.desiredEdgeLength': '200',
      'elk.spacing.nodeNode': '80',
      'elk.spacing.edgeNode': '40',
      'elk.hierarchyHandling': 'INCLUDE_CHILDREN'
    },
    children: topLevelNodes,
    edges: elkEdges
  };

  const layoutResult = await elk.layout(elkGraph);

  // Extract positions
  const positions = new Map<string, { x: number; y: number; width?: number; height?: number }>();

  function extractPositions(elkNodes: any[], offsetX: number, offsetY: number) {
    for (const node of elkNodes) {
      const x = (node.x || 0) + offsetX;
      const y = (node.y || 0) + offsetY;
      positions.set(node.id, { x, y, width: node.width, height: node.height });

      if (node.children && node.children.length > 0) {
        extractPositions(node.children, x, y);
      }
    }
  }

  if (layoutResult.children) {
    extractPositions(layoutResult.children, 0, 0);
  }

  return positions;
}
