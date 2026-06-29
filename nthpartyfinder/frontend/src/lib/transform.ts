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
  layers: number[];    // All layers this vendor appears at
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
    layers?: number[];
    activeLayers?: number[];
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
  sourceHandle?: string;
  targetHandle?: string;
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
        layers: [rel.nth_party_layer],
        discoveryCount: 0,
        sources: [],
        children: []
      });
    }

    const vendor = vendors.get(domain)!;

    // Track all layers this vendor appears at
    if (!vendor.layers.includes(rel.nth_party_layer)) {
      vendor.layers.push(rel.nth_party_layer);
      vendor.layers.sort((a, b) => a - b);
    }

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
const NODE_WIDTH = 120;     // Compact circular node footprint width
const NODE_HEIGHT = 90;     // Compact circular node footprint height (circle + labels)
const H_GAP = 40;           // Horizontal gap between nodes
const V_GAP = 30;           // Vertical gap between rows within a layer
const LAYER_GAP = 80;       // Extra gap between layers
const MAX_COLS = 10;        // Max nodes per row before wrapping (smaller nodes = more per row)
const NODE_SPACING = NODE_WIDTH + H_GAP; // Total horizontal step

// Layer band info exported for rendering backgrounds
export interface LayerBand {
  layer: number;
  label: string;
  y: number;      // Top of band
  height: number; // Band height
  width: number;  // Band width
}

// Calculate vertical positions with multi-row grid and parent-proximity ordering
function calculateVerticalPositions(
  vendors: Map<string, AggregatedVendor>,
  childrenMap: Map<string, Set<string>>,
  rootDomain: string
): { positions: Map<string, { x: number; y: number }>; layerBands: LayerBand[] } {
  const positions = new Map<string, { x: number; y: number }>();
  const layerBands: LayerBand[] = [];

  // Group vendors by layer
  const layerNodes = new Map<number, string[]>();
  layerNodes.set(0, [rootDomain]);

  for (const [domain, vendor] of vendors) {
    if (domain === rootDomain) continue;
    if (!layerNodes.has(vendor.layer)) {
      layerNodes.set(vendor.layer, []);
    }
    layerNodes.get(vendor.layer)!.push(domain);
  }

  // Sort layers
  const sortedLayers = Array.from(layerNodes.keys()).sort((a, b) => a - b);

  // Build reverse map: child -> parent domain for ordering
  const parentOf = new Map<string, string>();
  for (const [parent, children] of childrenMap) {
    for (const child of children) {
      parentOf.set(child, parent);
    }
  }

  let currentY = 0;

  for (const layer of sortedLayers) {
    let domains = layerNodes.get(layer)!;

    // Order nodes by parent x-position to minimize edge crossings
    if (layer > 0) {
      domains = orderByParentProximity(domains, parentOf, positions);
    }

    // Calculate grid dimensions
    const cols = Math.min(domains.length, MAX_COLS);
    const rows = Math.ceil(domains.length / cols);
    const totalWidth = (cols - 1) * NODE_SPACING;
    const startX = -totalWidth / 2;

    const bandPadding = 20;
    const bandTop = currentY - bandPadding;

    // Position each node in grid
    domains.forEach((domain, index) => {
      const col = index % cols;
      const row = Math.floor(index / cols);
      // For incomplete last row, center it
      const nodesInRow = row < rows - 1 ? cols : domains.length - row * cols;
      const rowWidth = (nodesInRow - 1) * NODE_SPACING;
      const rowStartX = -rowWidth / 2;
      const colInRow = index - row * cols;

      positions.set(domain, {
        x: rowStartX + colInRow * NODE_SPACING,
        y: currentY + row * (NODE_HEIGHT + V_GAP)
      });
    });

    const bandHeight = rows * NODE_HEIGHT + (rows - 1) * V_GAP + bandPadding * 2;
    const bandWidth = Math.max((Math.min(domains.length, MAX_COLS) - 1) * NODE_SPACING + NODE_WIDTH + bandPadding * 2, 400);

    const layerLabels: Record<number, string> = {
      0: 'Target Organization',
      1: 'Layer 1 — Direct Vendors',
      2: 'Layer 2 — Sub-processors',
      3: 'Layer 3 — Nth Parties',
      4: 'Layer 4 — Deep Dependencies'
    };

    layerBands.push({
      layer,
      label: layerLabels[layer] || `Layer ${layer}`,
      y: bandTop,
      height: bandHeight,
      width: bandWidth
    });

    // Advance Y for next layer
    currentY += rows * (NODE_HEIGHT + V_GAP) + LAYER_GAP;
  }

  return { positions, layerBands };
}

// Order domains so children of the same parent are adjacent, sorted by parent x-position
function orderByParentProximity(
  domains: string[],
  parentOf: Map<string, string>,
  positions: Map<string, { x: number; y: number }>
): string[] {
  // Group by parent
  const groups = new Map<string, string[]>();
  const orphans: string[] = [];

  for (const domain of domains) {
    const parent = parentOf.get(domain);
    if (parent && positions.has(parent)) {
      if (!groups.has(parent)) groups.set(parent, []);
      groups.get(parent)!.push(domain);
    } else {
      orphans.push(domain);
    }
  }

  // Sort groups by parent x-position (left to right)
  const sortedParents = Array.from(groups.keys()).sort((a, b) => {
    const ax = positions.get(a)?.x || 0;
    const bx = positions.get(b)?.x || 0;
    return ax - bx;
  });

  // Flatten: ordered groups, then orphans at the end
  const result: string[] = [];
  for (const parent of sortedParents) {
    // Sort children within group alphabetically for consistency
    const children = groups.get(parent)!;
    children.sort((a, b) => a.localeCompare(b));
    result.push(...children);
  }
  orphans.sort((a, b) => a.localeCompare(b));
  result.push(...orphans);

  return result;
}

export function transformToXyflow(
  relationships: Relationship[],
  rootDomain: string
): { nodes: XYFlowNode[]; edges: XYFlowEdge[]; vendors: Map<string, AggregatedVendor>; layerBands: LayerBand[] } {
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
  const { positions, layerBands } = calculateVerticalPositions(vendors, childrenMap, rootDomain);

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
      expanded: false,
      discoveryCount: 1,
      sources: []
    },
    position: positions.get(rootDomain) || { x: 0, y: 0 },
    hidden: false
  });

  // Add vendor nodes — all start hidden, revealed by expand/pagination
  for (const [domain, vendor] of vendors) {
    if (domain === rootDomain) continue;

    const children = childrenMap.get(domain) || new Set();
    const position = positions.get(domain) || { x: 0, y: 0 };

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
      hidden: true
    });
  }

  // Add edges — all start hidden, revealed by expand/pagination
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
      type: 'bezier',
      hidden: true,
      data: {
        recordType: rel.nth_party_record_type,
        layer: layer
      }
    });
  }

  return { nodes, edges, vendors, layerBands };
}

export function formatRecordType(recordType: string): string {
  // Compact labels for the graph tooltip's source groupings. Covers every Rust
  // RecordType variant — keyed by both the serde variant name (DnsTxtSpf) and the
  // hierarchy string (DNS::TXT::SPF) — so no discovery source ever falls back to a
  // raw/misleading code (e.g. TRUST_CENTER::API previously rendered as "API").
  // Mirrors RecordType::discovery_source_label() in src/vendor.rs; keep in sync.
  const typeMap: Record<string, string> = {
    'DnsTxtSpf': 'SPF',
    'DnsTxtVerification': 'DNS Verification',
    'DnsTxtDmarc': 'DMARC',
    'DnsTxtDkim': 'DKIM',
    'DnsSubdomain': 'Subdomain',
    'DnsMx': 'MX',
    'DnsA': 'A Record',
    'DnsAaaa': 'AAAA Record',
    'HttpWellKnown': 'Well-Known',
    'HttpMeta': 'Meta Tag',
    'HttpFile': 'Hosted File',
    'CertDomain': 'TLS Cert',
    'CertSan': 'Cert SAN',
    'ApiEndpoint': 'API Endpoint',
    'ApiWebhook': 'API Webhook',
    'HttpSubprocessor': 'Subprocessor',
    'SubfinderDiscovery': 'Subdomain',
    'SaasTenantProbe': 'SaaS Tenant',
    'CtLogDiscovery': 'CT Log',
    'TrustCenterApi': 'Trust Center',
    'WebTrafficSource': 'Webpage Source',
    'WebTrafficNetwork': 'Webpage Network',
    'Unknown': 'Other',
    'DNS::TXT::SPF': 'SPF',
    'DNS::TXT::VERIFICATION': 'DNS Verification',
    'DNS::TXT::DMARC': 'DMARC',
    'DNS::TXT::DKIM': 'DKIM',
    'DNS::SUBDOMAIN': 'Subdomain',
    'DNS::MX': 'MX',
    'DNS::A': 'A Record',
    'DNS::AAAA': 'AAAA Record',
    'HTTP::WELL_KNOWN': 'Well-Known',
    'HTTP::META': 'Meta Tag',
    'HTTP::FILE': 'Hosted File',
    'CERT::DOMAIN': 'TLS Cert',
    'CERT::SAN': 'Cert SAN',
    'API::ENDPOINT': 'API Endpoint',
    'API::WEBHOOK': 'API Webhook',
    'HTTP::SUBPROCESSOR': 'Subprocessor',
    'DISCOVERY::SUBFINDER': 'Subdomain',
    'DISCOVERY::SAAS_TENANT': 'SaaS Tenant',
    'DISCOVERY::CT_LOG': 'CT Log',
    'TRUST_CENTER::API': 'Trust Center',
    'DISCOVERY::WEBPAGE_SOURCE': 'Webpage Source',
    'DISCOVERY::WEBPAGE_NETWORK': 'Webpage Network',
    'UNKNOWN': 'Other'
  };

  return typeMap[recordType] || recordType.split('::').pop() || recordType;
}
