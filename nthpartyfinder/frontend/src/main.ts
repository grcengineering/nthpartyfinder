import VendorGraph from './VendorGraph.svelte';
import { transformToXyflow } from './lib/transform';

// Type declarations for window.graphData
declare global {
  interface Window {
    graphData: {
      relationships: Array<{
        nth_party_domain: string;
        nth_party_organization: string;
        nth_party_customer_domain: string;
        nth_party_layer: number;
        nth_party_record_type: string;
      }>;
      summary: {
        root_domain: string;
        total_unique_vendors: number;
        max_depth: number;
      };
    };
    vendorGraph: VendorGraph | null;
  }
}

// Initialize when DOM is ready
function init() {
  const container = document.getElementById('vendor-graph');
  if (!container) {
    console.error('vendor-graph container not found');
    return;
  }

  if (!window.graphData) {
    console.error('window.graphData not found');
    return;
  }

  const { nodes, edges } = transformToXyflow(
    window.graphData.relationships,
    window.graphData.summary.root_domain
  );

  window.vendorGraph = new VendorGraph({
    target: container,
    props: {
      initialNodes: nodes,
      initialEdges: edges,
      rootDomain: window.graphData.summary.root_domain,
      relationships: window.graphData.relationships
    }
  });
}

// Wait for DOM
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

export default VendorGraph;
