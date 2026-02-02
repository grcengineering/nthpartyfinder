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
    onShowInfo?: (domain: string, sources: DiscoverySource[]) => void;
  };

  // Color based on layer depth
  const layerColors: Record<number, { bg: string; border: string; shadow: string; icon: string }> = {
    1: { bg: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)', border: '#2563eb', shadow: 'rgba(59, 130, 246, 0.3)', icon: '🔗' },
    2: { bg: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', border: '#059669', shadow: 'rgba(16, 185, 129, 0.3)', icon: '🔗' },
    3: { bg: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', border: '#d97706', shadow: 'rgba(245, 158, 11, 0.3)', icon: '🔗' },
    4: { bg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)', border: '#dc2626', shadow: 'rgba(239, 68, 68, 0.3)', icon: '🔗' }
  };

  $: colors = layerColors[data.layer] || layerColors[4];

  function handleInfoClick(event: MouseEvent) {
    event.stopPropagation();
    if (data.onShowInfo) {
      data.onShowInfo(data.domain, data.sources);
    }
  }
</script>

<div
  class="vendor-node"
  class:expanded={data.expanded}
  class:has-children={data.hasChildren}
  style="background: {colors.bg}; --shadow-color: {colors.shadow};"
>
  <!-- Left handle for incoming edges (horizontal layout) -->
  <Handle type="target" position={Position.Left} />

  <div class="node-icon">{colors.icon}</div>
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
        {data.expanded ? '◀' : '▶'} {data.childCount} vendor{data.childCount !== 1 ? 's' : ''}
      </div>
    {/if}
  </div>

  <!-- Info button -->
  <button class="info-btn" on:click={handleInfoClick} title="View discovery details">
    ℹ
  </button>

  <!-- Right handle for outgoing edges (horizontal layout) -->
  {#if data.hasChildren}
    <Handle type="source" position={Position.Right} />
  {/if}
</div>

<style>
  .vendor-node {
    color: white;
    padding: 16px 20px;
    border-radius: 12px;
    min-width: 180px;
    box-shadow: 0 4px 12px var(--shadow-color, rgba(0,0,0,0.3));
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    align-items: center;
    gap: 12px;
    position: relative;
  }

  .vendor-node:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px var(--shadow-color, rgba(0,0,0,0.4));
  }

  .vendor-node.has-children {
    cursor: pointer;
  }

  .vendor-node.expanded {
    box-shadow: 0 4px 12px var(--shadow-color, rgba(0,0,0,0.4));
  }

  .node-icon {
    font-size: 24px;
    flex-shrink: 0;
  }

  .node-content {
    flex: 1;
    min-width: 0;
  }

  .node-domain {
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 2px;
    word-break: break-all;
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
