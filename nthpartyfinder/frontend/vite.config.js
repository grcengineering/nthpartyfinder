import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  // The IIFE lib bundle runs in a plain browser (embedded into the Rust HTML
  // report) where `process` does not exist. @xyflow/svelte 1.x and its
  // @xyflow/system dependency guard their dev-only warnings with
  // `process.env.NODE_ENV === "development"`. Vite does NOT replace
  // `process.env.NODE_ENV` in lib (IIFE) builds, so without this define the
  // first reference (in the node-store constructor that runs at mount) throws
  // `ReferenceError: process is not defined` and the graph never renders.
  // Statically replacing it with "production" both fixes the crash and lets
  // Rollup tree-shake the dev-only warning branches as dead code.
  define: {
    'process.env.NODE_ENV': JSON.stringify('production')
  },
  build: {
    // The bundle is embedded into the HTML report and viewed in current
    // browsers; target modern JS so esbuild 0.28 doesn't try (and fail) to
    // lower modern syntax to the legacy default target.
    target: 'es2022',
    // Output as IIFE for direct browser use
    lib: {
      entry: 'src/main.ts',
      name: 'VendorGraph',
      formats: ['iife'],
      fileName: () => 'vendor-graph.js'
    },
    outDir: '../static',
    emptyOutDir: false,
    // Inline all CSS into the JS bundle
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // Emit the single CSS asset as vendor-graph.css (the Rust report embeds
        // it via include_str!). Rollup/Vite 6 renamed the asset from "style.css"
        // to the lib name and moved it to `names`, so match the extension.
        assetFileNames: (assetInfo) => {
          const name = (assetInfo.names && assetInfo.names[0]) || assetInfo.name || '';
          if (name.endsWith('.css')) {
            return 'vendor-graph.css';
          }
          return name;
        }
      }
    }
  }
});
