<script lang="ts">
  import { Handle, Position } from '@xyflow/svelte';
  import type { DiscoverySource } from '../lib/transform';

  export let data: {
    label: string;
    organization: string;
    domain: string;
    layer: number;
    childCount: number;
    hasChildren: boolean;
    expanded: boolean;
    discoveryCount: number;
    sources: DiscoverySource[];
  };

  // Color based on layer depth - same icon as root, different gradient colors
  const layerColors: Record<number, { bg: string; shadow: string }> = {
    1: { bg: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)', shadow: 'rgba(59, 130, 246, 0.3)' },
    2: { bg: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', shadow: 'rgba(16, 185, 129, 0.3)' },
    3: { bg: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', shadow: 'rgba(245, 158, 11, 0.3)' },
    4: { bg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)', shadow: 'rgba(239, 68, 68, 0.3)' }
  };

  $: colors = layerColors[data.layer] || layerColors[4];

  function handleInfoClick(event: MouseEvent) {
    event.stopPropagation();
    event.preventDefault();
    // Use global event bus to bypass xyflow's data pipeline (callbacks on node.data get lost)
    window.dispatchEvent(new CustomEvent('show-vendor-info', {
      detail: { domain: data.domain, sources: data.sources }
    }));
  }
</script>

<div
  class="vendor-node"
  class:expanded={data.expanded}
  style="background: {colors.bg}; --shadow-color: {colors.shadow};"
>
  <!-- Top handle for incoming edges (vertical layout) -->
  <Handle type="target" position={Position.Top} />

  <div class="node-icon">🏢</div>
  <div class="node-content">
    <div class="node-domain">{data.domain}</div>
    {#if data.organization && data.organization !== data.domain}
      <div class="node-org">{data.organization}</div>
    {/if}

    <!-- Discovery count badge -->
    {#if data.discoveryCount > 1}
      <div class="discovery-badge">×{data.discoveryCount} sources</div>
    {/if}

    <!-- Child count indicator -->
    {#if data.hasChildren}
      <div class="node-children">
        {data.expanded ? '▲' : '▼'} {data.childCount} vendor{data.childCount !== 1 ? 's' : ''}
      </div>
    {/if}
  </div>

  <!-- Info button -->
  <button class="info-btn nodrag nopan" on:click={handleInfoClick} title="View discovery details">
    ℹ
  </button>

  <!-- Bottom handle for outgoing edges (vertical layout) -->
  {#if data.hasChildren}
    <Handle type="source" position={Position.Bottom} />
  {/if}
</div>

<style>
  /* Styling identical to RootNode except for background color (set via style attribute) */
  .vendor-node {
    color: white;
    padding: 16px 20px;
    border-radius: 12px;
    min-width: 180px;
    box-shadow: 0 4px 12px var(--shadow-color, rgba(99, 102, 241, 0.3));
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    align-items: center;
    gap: 12px;
    /* Ensure content stays within bounds */
    overflow: hidden;
    box-sizing: border-box;
  }

  .vendor-node:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px var(--shadow-color, rgba(99, 102, 241, 0.4));
  }

  .vendor-node.expanded {
    box-shadow: 0 4px 12px var(--shadow-color, rgba(99, 102, 241, 0.4));
  }

  .node-icon {
    font-size: 24px;
  }

  .node-content {
    flex: 1;
    overflow: hidden;
  }

  .node-domain {
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .node-org {
    font-size: 11px;
    opacity: 0.9;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .discovery-badge {
    display: inline-block;
    background: rgba(255, 255, 255, 0.2);
    padding: 2px 6px;
    border-radius: 10px;
    font-size: 10px;
    margin-top: 4px;
  }

  .node-children {
    font-size: 11px;
    opacity: 0.8;
    margin-top: 4px;
  }

  .info-btn {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    border: none;
    background: rgba(255, 255, 255, 0.25);
    color: white;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s;
    padding: 0;
    line-height: 1;
    flex-shrink: 0;
  }

  .info-btn:hover {
    background: rgba(255, 255, 255, 0.4);
  }
</style>
