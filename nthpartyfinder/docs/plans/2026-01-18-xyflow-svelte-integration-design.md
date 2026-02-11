# XYFlow Svelte Integration Design

## Overview

Replace the current vis.js-based vendor relationship graph with @xyflow/svelte for a more modern, beautiful, and responsive visualization.

## Motivation

- vis.js looks dated compared to modern graph visualization libraries
- xyflow provides smoother animations, better edge rendering, and built-in minimap/controls
- Svelte compiles away at build time, resulting in smaller bundle than React

## Architecture

### Build Structure

```
nthpartyfinder/
├── frontend/                    # New directory
│   ├── package.json            # Svelte + xyflow deps
│   ├── vite.config.js          # Build config (IIFE output)
│   └── src/
│       ├── main.ts             # Entry point
│       ├── VendorGraph.svelte  # Main component
│       ├── nodes/              # Custom node components
│       │   ├── RootNode.svelte
│       │   ├── VendorNode.svelte
│       │   └── LoadMoreNode.svelte
│       └── lib/
│           └── transform.ts    # Data transformation
├── static/                     # Build output (gitignored source, committed bundle)
│   └── vendor-graph.js         # Compiled bundle (~150KB)
├── templates/
│   └── report.html             # References/embeds built bundle
└── src/
    └── export.rs               # Reads and embeds JS in HTML
```

### Data Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Rust/Askama    │────▶│  HTML Template   │────▶│  Svelte Bundle  │
│  (generates)    │     │  (embeds JSON)   │     │  (renders graph)│
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

1. Rust generates HTML with JSON data embedded in `window.graphData`
2. Svelte bundle reads `window.graphData` on page load
3. Transform function converts Rust data format to xyflow nodes/edges
4. Svelte component renders the interactive graph

### HTML Integration

```html
<!-- Data injection (same as current) -->
<script>
  window.graphData = {
    relationships: {{ relationships_json|safe }},
    summary: {{ summary_json|safe }}
  };
</script>

<!-- Graph container -->
<div id="vendor-graph" style="height: 600px;"></div>

<!-- Load compiled Svelte bundle (inlined) -->
<script>{{ vendor_graph_js|safe }}</script>
```

## Component Design

### VendorGraph.svelte

```svelte
<script>
  import { SvelteFlow, Controls, Background, MiniMap } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';

  import RootNode from './nodes/RootNode.svelte';
  import VendorNode from './nodes/VendorNode.svelte';
  import LoadMoreNode from './nodes/LoadMoreNode.svelte';

  export let nodes = [];
  export let edges = [];
  export let rootDomain = '';

  const nodeTypes = {
    root: RootNode,
    vendor: VendorNode,
    loadMore: LoadMoreNode
  };
</script>

<SvelteFlow {nodes} {edges} {nodeTypes} fitView>
  <Controls />
  <Background />
  <MiniMap />
</SvelteFlow>
```

### Features to Preserve

- Click node to expand/collapse children
- Layer-based limiting (show X vendors, then "load more")
- Drag to pan, scroll to zoom
- Focus on node when clicking from table
- Export to PNG
- Reset view button

### Visual Improvements

- Smooth bezier edge curves (xyflow default)
- Better node styling with gradients
- Built-in minimap for navigation
- Cleaner controls panel
- Animated transitions

## Implementation Steps

1. **Set up frontend build**
   - Create `frontend/` directory with package.json
   - Configure Vite for IIFE output
   - Install @xyflow/svelte dependencies

2. **Create Svelte components**
   - VendorGraph.svelte (main container)
   - Custom node components (Root, Vendor, LoadMore)
   - Data transformation utilities

3. **Implement interactions**
   - Expand/collapse logic
   - Layer limiting with "load more"
   - PNG export
   - Table-to-graph focus

4. **Integrate with Rust**
   - Modify export.rs to read built JS
   - Update report.html template
   - Remove vis.js references

5. **CI/Build integration**
   - Add frontend build to GitHub Actions
   - Commit pre-built bundle for non-Node users

## Dependencies

```json
{
  "dependencies": {
    "@xyflow/svelte": "^0.1.0"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "@sveltejs/vite-plugin-svelte": "^3.0.0",
    "svelte": "^4.0.0",
    "typescript": "^5.0.0"
  }
}
```

## Bundle Size Estimate

- @xyflow/svelte: ~80KB minified
- Svelte runtime: ~0KB (compiled away)
- Custom code: ~20KB
- **Total: ~100-150KB** (comparable to vis.js ~200KB)

## Migration Strategy

1. Build new graph alongside existing vis.js
2. Feature flag to switch between them
3. Remove vis.js once xyflow is validated
