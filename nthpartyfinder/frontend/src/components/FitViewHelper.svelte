<script lang="ts">
  import { useSvelteFlow } from '@xyflow/svelte';

  // This component must be a child of SvelteFlow to access the flow context.
  // It exposes fitView as a callable method via bind:this.

  const { fitView } = useSvelteFlow();

  export function fit() {
    // Delay slightly to let Svelte batch DOM updates before fitting
    requestAnimationFrame(() => {
      fitView({ padding: 0.15, duration: 300 });
    });
  }
</script>
