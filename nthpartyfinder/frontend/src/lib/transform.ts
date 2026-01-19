// Transform Rust data format to xyflow nodes and edges

export interface Relationship {
  nth_party_domain: string;
  nth_party_organization: string;
  nth_party_customer_domain: string;
  nth_party_layer: number;
  nth_party_record_type: string;
}

export interface XYFlowNode {
  id: string;
  type: string;
  data: {
    label: string;
    organization: string;
    domain: string;
    layer: number;
    childCount: number;
    hasChildren: boolean;
    expanded: boolean;
  };
  position: { x: number; y: number };
  hidden?: boolean;
}

export interface XYFlowEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: string;
  hidden?: boolean;
  data?: {
    recordType: string;
    layer: number;
  };
}

// Build parent -> children map
export function buildRelationshipMap(relationships: Relationship[]): Map<string, Relationship[]> {
  const map = new Map<string, Relationship[]>();

  for (const rel of relationships) {
    const parent = rel.nth_party_customer_domain;
    if (!map.has(parent)) {
      map.set(parent, []);
    }
    map.get(parent)!.push(rel);
  }

  return map;
}

// Calculate hierarchical positions using dagre-like layout
function calculatePositions(
  nodes: Map<string, { layer: number; index: number }>,
  rootDomain: string
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  // Group nodes by layer
  const layerNodes = new Map<number, string[]>();
  for (const [nodeId, { layer }] of nodes) {
    if (!layerNodes.has(layer)) {
      layerNodes.set(layer, []);
    }
    layerNodes.get(layer)!.push(nodeId);
  }

  const horizontalSpacing = 250;
  const verticalSpacing = 150;

  for (const [layer, nodeIds] of layerNodes) {
    const totalWidth = (nodeIds.length - 1) * horizontalSpacing;
    const startX = -totalWidth / 2;

    nodeIds.forEach((nodeId, index) => {
      positions.set(nodeId, {
        x: startX + index * horizontalSpacing,
        y: layer * verticalSpacing
      });
    });
  }

  return positions;
}

export function transformToXyflow(
  relationships: Relationship[],
  rootDomain: string
): { nodes: XYFlowNode[]; edges: XYFlowEdge[] } {
  const nodes: XYFlowNode[] = [];
  const edges: XYFlowEdge[] = [];
  const addedNodes = new Set<string>();
  const nodeLayerInfo = new Map<string, { layer: number; index: number }>();

  // Build relationship map for child counting
  const relationshipMap = buildRelationshipMap(relationships);

  // Add root node
  const rootChildCount = relationshipMap.get(rootDomain)?.length || 0;
  nodeLayerInfo.set(rootDomain, { layer: 0, index: 0 });
  addedNodes.add(rootDomain);

  // Process relationships to collect all nodes
  let edgeIndex = 0;
  for (const rel of relationships) {
    // Add vendor node if not exists
    if (!addedNodes.has(rel.nth_party_domain)) {
      const childCount = relationshipMap.get(rel.nth_party_domain)?.length || 0;
      nodeLayerInfo.set(rel.nth_party_domain, {
        layer: rel.nth_party_layer,
        index: nodeLayerInfo.size
      });
      addedNodes.add(rel.nth_party_domain);
    }

    // Add edge
    edges.push({
      id: `e-${edgeIndex++}`,
      source: rel.nth_party_customer_domain,
      target: rel.nth_party_domain,
      label: formatRecordType(rel.nth_party_record_type),
      type: 'smoothstep',
      hidden: rel.nth_party_layer > 1, // Only show first layer initially
      data: {
        recordType: rel.nth_party_record_type,
        layer: rel.nth_party_layer
      }
    });
  }

  // Calculate positions
  const positions = calculatePositions(nodeLayerInfo, rootDomain);

  // Create node objects
  for (const domain of addedNodes) {
    const layerInfo = nodeLayerInfo.get(domain)!;
    const position = positions.get(domain) || { x: 0, y: 0 };
    const childCount = relationshipMap.get(domain)?.length || 0;

    // Find organization name from relationships
    let organization = domain;
    const rel = relationships.find(r => r.nth_party_domain === domain);
    if (rel) {
      organization = rel.nth_party_organization || domain;
    }

    const isRoot = domain === rootDomain;

    nodes.push({
      id: domain,
      type: isRoot ? 'root' : 'vendor',
      data: {
        label: domain,
        organization: organization,
        domain: domain,
        layer: layerInfo.layer,
        childCount: childCount,
        hasChildren: childCount > 0,
        expanded: isRoot // Root starts expanded
      },
      position,
      hidden: !isRoot && layerInfo.layer > 1 // Only show root and first layer initially
    });
  }

  return { nodes, edges };
}

function formatRecordType(recordType: string): string {
  // Convert record type to readable label
  const typeMap: Record<string, string> = {
    'TXT::Verification': 'DNS',
    'TXT::SPF': 'SPF',
    'MX': 'Email',
    'CNAME': 'CNAME',
    'NS': 'NS',
    'HTTP::Subprocessor': 'Subprocessor',
    'HTTP::WebOrg': 'Web',
    'SaaSTenant': 'SaaS'
  };

  return typeMap[recordType] || recordType.split('::').pop() || recordType;
}
