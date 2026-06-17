import { mount } from 'svelte';
import VendorGraph from './VendorGraph.svelte';

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
        nth_party_record?: string;
      }>;
      summary: {
        root_domain: string;
        total_unique_vendors: number;
        max_depth: number;
      };
    };
    vendorGraph: Record<string, unknown> | null;
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

  // Svelte 5 removed the `new Component()` class API; mount() is the runtime entry.
  window.vendorGraph = mount(VendorGraph, {
    target: container,
    props: {
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
