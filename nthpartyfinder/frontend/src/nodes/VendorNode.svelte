<script lang="ts">
  import { Handle, Position, type NodeProps } from '@xyflow/svelte';
  import type { DiscoverySource } from '../lib/transform';
  import { icons } from '../lib/icons';

  type VendorData = {
    label: string;
    organization: string;
    domain: string;
    layer: number;
    layers?: number[];
    activeLayers?: number[];  // Layers with currently visible edges — drives ring display
    childCount: number;
    hasChildren: boolean;
    expanded: boolean;
    discoveryCount: number;
    sources: DiscoverySource[];
  };

  let { data }: NodeProps & { data: VendorData } = $props();

  const layerColors: Record<number, { bg: string; shadow: string; ring: string; solid: string }> = {
    1: { bg: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)', shadow: 'rgba(59, 130, 246, 0.35)', ring: 'rgba(59, 130, 246, 0.25)', solid: '#3b82f6' },
    2: { bg: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', shadow: 'rgba(16, 185, 129, 0.35)', ring: 'rgba(16, 185, 129, 0.25)', solid: '#10b981' },
    3: { bg: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', shadow: 'rgba(245, 158, 11, 0.35)', ring: 'rgba(245, 158, 11, 0.25)', solid: '#f59e0b' },
    4: { bg: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)', shadow: 'rgba(239, 68, 68, 0.35)', ring: 'rgba(239, 68, 68, 0.25)', solid: '#ef4444' }
  };

  const colors = $derived(layerColors[data.layer] || layerColors[4]);

  // Build concentric ring shadows from ACTIVE layers only (not all possible layers).
  // activeLayers is set by VendorGraph when edges become visible/hidden.
  // Only show rings for layers BEYOND the primary layer (additional relationships).
  const multiLayerShadow = $derived(buildMultiLayerShadow(data.activeLayers || [data.layer]));

  function buildMultiLayerShadow(activeLayers: number[]): string {
    // Only the primary layer = no extra rings
    const uniqueLayers = [...new Set(activeLayers)].sort((a, b) => a - b);
    if (uniqueLayers.length <= 1) return '';

    // Skip the primary layer — only show rings for ADDITIONAL layers
    const extraLayers = uniqueLayers.filter(l => l !== data.layer);
    if (extraLayers.length === 0) return '';

    const shadows: string[] = [];
    for (let i = 0; i < extraLayers.length; i++) {
      const layer = extraLayers[i];
      const color = (layerColors[layer] || layerColors[4]).solid;
      const offset = (i + 1) * 4;
      shadows.push(`0 0 0 ${offset}px ${color}`);
    }
    return shadows.join(', ');
  }

  let hovered = $state(false);

  function handleExpandClick(event: MouseEvent) {
    event.stopPropagation();
    window.dispatchEvent(new CustomEvent('node-action', {
      detail: { action: 'expand', domain: data.domain }
    }));
  }

  function handleInfoClick(event: MouseEvent) {
    event.stopPropagation();
    window.dispatchEvent(new CustomEvent('show-vendor-info', {
      detail: { domain: data.domain, sources: data.sources }
    }));
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="vendor-node"
  class:expanded={data.expanded}
  class:hovered
  onmouseenter={() => hovered = true}
  onmouseleave={() => hovered = false}
>
  <Handle type="target" position={Position.Top} id="target" style="position: absolute; left: 50%; top: 24px; transform: translate(-50%, -50%);" />

  <div class="node-circle" style="background: {colors.bg}; --shadow-color: {colors.shadow}; --ring-color: {colors.ring};{multiLayerShadow ? ` box-shadow: ${multiLayerShadow};` : ''}">
    <span class="node-icon">{@html icons.building2}</span>
  </div>

  {#if data.hasChildren}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="action-badge expand-badge nodrag nopan"
      class:visible={hovered}
      onclick={handleExpandClick}
      title={data.expanded ? 'Collapse vendors' : `Expand ${data.childCount} vendors`}
    >
      <span class="badge-count">{data.childCount}</span>
      <span class="badge-icon">{@html data.expanded ? icons.chevronUp : icons.chevronDown}</span>
    </div>
  {/if}
  {#if data.discoveryCount > 0}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div
      class="action-badge info-badge nodrag nopan"
      class:visible={hovered}
      onclick={handleInfoClick}
      title="View {data.discoveryCount} discovery sources"
    >
      <span class="badge-count">×{data.discoveryCount}</span>
      <span class="badge-icon">{@html icons.info}</span>
    </div>
  {/if}

  <div class="node-label">{data.domain}</div>
  {#if data.organization && data.organization !== data.domain}
    <div class="node-org">{data.organization}</div>
  {/if}

  {#if data.hasChildren}
    <Handle type="source" position={Position.Bottom} id="source" style="position: absolute; left: 50%; top: 24px; transform: translate(-50%, -50%);" />
  {/if}
</div>

<style>
  .vendor-node {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    cursor: default;
    width: 120px;
    position: relative;
  }

  .node-circle {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px var(--shadow-color, rgba(59, 130, 246, 0.35));
    /* Smooth transition for ring grow/shrink animation */
    transition: box-shadow 0.4s ease, transform 0.2s;
    position: relative;
  }

  .vendor-node:hover .node-circle {
    transform: scale(1.08);
  }

  .vendor-node.expanded .node-circle {
    box-shadow: 0 0 0 3px var(--ring-color, rgba(59, 130, 246, 0.25)), 0 2px 8px var(--shadow-color);
  }

  .node-icon { font-size: 20px; line-height: 1; color: #fff; display: inline-flex; }

  .action-badge {
    position: absolute;
    display: flex;
    align-items: center;
    gap: 2px;
    height: 24px;
    border-radius: 12px;
    padding: 0 8px;
    font-size: 10px;
    font-weight: 700;
    cursor: pointer;
    opacity: 0;
    transform: scale(0.5);
    transition: opacity 0.2s ease, transform 0.2s ease;
    pointer-events: none;
    white-space: nowrap;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
    z-index: 10;
  }

  .action-badge.visible {
    opacity: 1;
    transform: scale(1);
    pointer-events: all;
  }

  .expand-badge { top: -14px; right: -10px; background: #ef4444; color: white; }
  .expand-badge:hover { background: #dc2626; transform: scale(1.1) !important; }
  .info-badge { top: -14px; left: -10px; background: #6366f1; color: white; }
  .info-badge:hover { background: #4f46e5; transform: scale(1.1) !important; }

  .badge-count { font-size: 10px; }
  .badge-icon { font-size: 9px; }

  .node-label {
    font-size: 11px; font-weight: 600; color: #1e293b;
    text-align: center; max-width: 120px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  .node-org {
    font-size: 10px; color: #64748b;
    text-align: center; max-width: 120px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
</style>
