import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
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
        // Ensure CSS is inlined
        assetFileNames: (assetInfo) => {
          if (assetInfo.name === 'style.css') {
            return 'vendor-graph.css';
          }
          return assetInfo.name;
        }
      }
    }
  }
});
