// Transform Rust data format to xyflow nodes and edges with deduplication

export interface Relationship {
  nth_party_domain: string;
  nth_party_organization: string;
  nth_party_customer_domain: string;
  nth_party_layer: number;
  nth_party_record_type: string;
  nth_party_record?: string;  // Raw record content
}

export interface DiscoverySource {
  recordType: string;
  parentDomain: string;
  rawRecord?: string;
}

export interface AggregatedVendor {
  domain: string;
  organization: string;
  layer: number;
  discoveryCount: number;
  sources: DiscoverySource[];
  children: string[];  // Child vendor domains
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
    discoveryCount: number;
    sources: DiscoverySource[];
    parentId?: string;
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

// Build aggregated vendor map with deduplication
export function aggregateVendors(relationships: Relationship[]): Map<string, AggregatedVendor> {
  const vendors = new Map<string, AggregatedVendor>();

  for (const rel of relationships) {
    const domain = rel.nth_party_domain;

    if (!vendors.has(domain)) {
      vendors.set(domain, {
        domain,
        organization: rel.nth_party_organization || domain,
        layer: rel.nth_party_layer,
        discoveryCount: 0,
        sources: [],
        children: []
      });
    }

    const vendor = vendors.get(domain)!;

    // Use minimum layer (earliest discovery point)
    vendor.layer = Math.min(vendor.layer, rel.nth_party_layer);

    // Add discovery source
    vendor.sources.push({
      recordType: rel.nth_party_record_type,
      parentDomain: rel.nth_party_customer_domain,
      rawRecord: rel.nth_party_record
    });
    vendor.discoveryCount++;

    // Update organization if we have a better one
    if (rel.nth_party_organization && rel.nth_party_organization !== domain) {
      vendor.organization = rel.nth_party_organization;
    }
  }

  return vendors;
}

// Build parent -> children map (deduplicated)
export function buildChildrenMap(relationships: Relationship[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();

  for (const rel of relationships) {
    const parent = rel.nth_party_customer_domain;
    if (!map.has(parent)) {
      map.set(parent, new Set());
    }
    map.get(parent)!.add(rel.nth_party_domain);
  }

  return map;
}

// Build parent -> children map for expand/collapse (returns relationships)
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

// Layout constants - VERTICAL top-to-bottom
const LAYER_SPACING = 180;  // Vertical distance between layers (rows)
const NODE_SPACING = 280;   // Horizontal distance between sibling nodes (columns)

// Calculate vertical positions (top-to-bottom layout)
function calculateVerticalPositions(
  vendors: Map<string, AggregatedVendor>,
  childrenMap: Map<string, Set<string>>,
  rootDomain: string
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  // Group vendors by layer
  const layerNodes = new Map<number, string[]>();

  // Add root at layer 0
  layerNodes.set(0, [rootDomain]);

  // Group other vendors by layer
  for (const [domain, vendor] of vendors) {
    if (domain === rootDomain) continue;
    if (!layerNodes.has(vendor.layer)) {
      layerNodes.set(vendor.layer, []);
    }
    layerNodes.get(vendor.layer)!.push(domain);
  }

  // Calculate positions for each layer (top-to-bottom)
  for (const [layer, domains] of layerNodes) {
    const totalWidth = (domains.length - 1) * NODE_SPACING;
    const startX = -totalWidth / 2;

    domains.forEach((domain, index) => {
      positions.set(domain, {
        x: startX + index * NODE_SPACING,
        y: layer * LAYER_SPACING
      });
    });
  }

  return positions;
}

export function transformToXyflow(
  relationships: Relationship[],
  rootDomain: string
): { nodes: XYFlowNode[]; edges: XYFlowEdge[]; vendors: Map<string, AggregatedVendor> } {
  const nodes: XYFlowNode[] = [];
  const edges: XYFlowEdge[] = [];
  const addedEdges = new Set<string>();

  // Aggregate vendors (deduplication)
  const vendors = aggregateVendors(relationships);
  const childrenMap = buildChildrenMap(relationships);

  // Add children info to vendors
  for (const [domain, children] of childrenMap) {
    if (vendors.has(domain)) {
      vendors.get(domain)!.children = Array.from(children);
    }
  }

  // Calculate positions
  const positions = calculateVerticalPositions(vendors, childrenMap, rootDomain);

  // Add root node
  const rootChildren = childrenMap.get(rootDomain) || new Set();
  nodes.push({
    id: rootDomain,
    type: 'root',
    data: {
      label: rootDomain,
      organization: rootDomain,
      domain: rootDomain,
      layer: 0,
      childCount: rootChildren.size,
      hasChildren: rootChildren.size > 0,
      expanded: true,
      discoveryCount: 1,
      sources: []
    },
    position: positions.get(rootDomain) || { x: 0, y: 0 },
    hidden: false
  });

  // Add vendor nodes
  for (const [domain, vendor] of vendors) {
    if (domain === rootDomain) continue;

    const children = childrenMap.get(domain) || new Set();
    const position = positions.get(domain) || { x: 0, y: vendor.layer * LAYER_SPACING };

    nodes.push({
      id: domain,
      type: 'vendor',
      data: {
        label: domain,
        organization: vendor.organization,
        domain: domain,
        layer: vendor.layer,
        childCount: children.size,
        hasChildren: children.size > 0,
        expanded: false,
        discoveryCount: vendor.discoveryCount,
        sources: vendor.sources
      },
      position,
      hidden: vendor.layer > 1  // Only show layer 1 initially
    });
  }

  // Add edges (deduplicated - one edge per parent-child pair)
  for (const rel of relationships) {
    const edgeKey = `${rel.nth_party_customer_domain}->${rel.nth_party_domain}`;
    if (addedEdges.has(edgeKey)) continue;
    addedEdges.add(edgeKey);

    const vendor = vendors.get(rel.nth_party_domain);
    const layer = vendor?.layer || rel.nth_party_layer;

    edges.push({
      id: `e-${edgeKey}`,
      source: rel.nth_party_customer_domain,
      target: rel.nth_party_domain,
      type: 'smoothstep',
      hidden: layer > 1,
      data: {
        recordType: rel.nth_party_record_type,
        layer: layer
      }
    });
  }

  return { nodes, edges, vendors };
}

export function formatRecordType(recordType: string): string {
  const typeMap: Record<string, string> = {
    'DnsTxtSpf': 'SPF',
    'DnsTxtVerification': 'DNS Verification',
    'DnsTxtDmarc': 'DMARC',
    'DnsTxtDkim': 'DKIM',
    'DnsSubdomain': 'Subdomain',
    'DnsCname': 'CNAME',
    'HttpSubprocessor': 'Subprocessor',
    'DiscoverySaas': 'SaaS Tenant',
    'DNS::TXT::SPF': 'SPF',
    'DNS::TXT::VERIFICATION': 'DNS Verification',
    'DNS::TXT::DMARC': 'DMARC',
    'DNS::SUBDOMAIN': 'Subdomain',
    'DNS::CNAME': 'CNAME',
    'HTTP::SUBPROCESSOR': 'Subprocessor',
    'DISCOVERY::SAAS_TENANT': 'SaaS Tenant'
  };

  return typeMap[recordType] || recordType.split('::').pop() || recordType;
}
