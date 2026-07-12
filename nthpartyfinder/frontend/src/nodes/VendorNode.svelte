<script lang="ts">
  import { Handle, Position, type NodeProps } from '@xyflow/svelte';
  import { clampLayer, type DiscoverySource } from '../lib/transform';
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

  // The node's colour comes entirely from the layer ramp defined once on
  // .vendor-graph-container (--npf-l{N}-fill / --npf-l{N}-solid), which inherits
  // down to here. This component decides WHICH layer it is, never what that
  // layer looks like.
  const layer = $derived(clampLayer(data.layer));

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
      const offset = (i + 1) * 4;
      shadows.push(`0 0 0 ${offset}px var(--npf-l${clampLayer(extraLayers[i])}-solid)`);
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

  <div class="node-circle" style="--layer-fill: var(--npf-l{layer}-fill); --layer-solid: var(--npf-l{layer}-solid);{multiLayerShadow ? ` box-shadow: ${multiLayerShadow};` : ''}">
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
    /* --layer-fill / --layer-solid are set inline from the inherited layer ramp.
       The glow and expanded ring are derived from the layer's own solid so they
       stay in family for every layer; the plain rgba declaration ahead of each
       color-mix() is the fallback for engines without relative colour support. */
    --layer-glow: rgba(15, 23, 42, 0.22);
    --layer-glow: color-mix(in srgb, var(--layer-solid) 35%, transparent);
    --layer-ring: rgba(15, 23, 42, 0.15);
    --layer-ring: color-mix(in srgb, var(--layer-solid) 25%, transparent);

    width: 48px;
    height: 48px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--layer-fill);
    box-shadow: 0 2px 8px var(--layer-glow);
    /* Smooth transition for ring grow/shrink animation */
    transition: box-shadow 0.4s ease, transform 0.2s;
    position: relative;
  }

  .vendor-node:hover .node-circle {
    transform: scale(1.08);
  }

  .vendor-node.expanded .node-circle {
    box-shadow: 0 0 0 3px var(--layer-ring), 0 2px 8px var(--layer-glow);
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

  .expand-badge { top: -14px; right: -10px; background: var(--grc-orange-500, #ef4444); color: var(--text-on-accent, #fff); }
  .expand-badge:hover { background: var(--grc-orange-600, #dc2626); transform: scale(1.1) !important; }
  .info-badge { top: -14px; left: -10px; background: var(--eng-blue-500, #6366f1); color: var(--text-on-accent, #fff); }
  .info-badge:hover { background: var(--eng-blue-600, #4f46e5); transform: scale(1.1) !important; }

  .badge-count { font-size: 10px; font-family: var(--font-mono, inherit); }
  .badge-icon { font-size: 9px; }

  /* Labels sit on the canvas, so they bind to the theme-flipping ink tokens —
     this is what kept them dark-on-dark (invisible) before. */
  .node-label {
    font-size: 11px; font-weight: var(--fw-semibold, 600);
    color: var(--npf-ink, #1e293b);
    font-family: var(--ui-family, inherit);
    text-align: center; max-width: 120px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  .node-org {
    font-size: 10px; color: var(--npf-ink-muted, #64748b);
    text-align: center; max-width: 120px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
</style>
