<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { formatRecordType, type DiscoverySource } from '../lib/transform';

  export let domain: string;
  export let organization: string = '';
  export let sources: DiscoverySource[] = [];
  export let position: { x: number; y: number } = { x: 0, y: 0 };
  export let visible: boolean = false;

  const dispatch = createEventDispatcher();

  function close() {
    dispatch('close');
  }

  // Group sources by record type
  $: groupedSources = sources.reduce((acc, source) => {
    const type = formatRecordType(source.recordType);
    if (!acc[type]) {
      acc[type] = [];
    }
    acc[type].push(source);
    return acc;
  }, {} as Record<string, DiscoverySource[]>);
</script>

{#if visible}
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="tooltip-backdrop" on:click={close}></div>
  <div
    class="tooltip"
    style="left: {position.x}px; top: {position.y}px;"
  >
    <div class="tooltip-header">
      <div class="tooltip-domain">{domain}</div>
      {#if organization && organization !== domain}
        <div class="tooltip-org">{organization}</div>
      {/if}
      <button class="close-btn" on:click={close}>×</button>
    </div>

    <div class="tooltip-content">
      <div class="section-title">Discovery Sources ({sources.length}):</div>

      {#each Object.entries(groupedSources) as [type, typeSources]}
        <div class="source-group">
          <div class="source-type">{type} ({typeSources.length})</div>
          {#each typeSources as source}
            <div class="source-item">
              <span class="source-parent">from {source.parentDomain}</span>
              {#if source.rawRecord}
                <div class="source-record">{source.rawRecord}</div>
              {/if}
            </div>
          {/each}
        </div>
      {/each}
    </div>
  </div>
{/if}

<style>
  .tooltip-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: transparent;
    z-index: 999;
  }

  .tooltip {
    position: fixed;
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    min-width: 280px;
    max-width: 400px;
    max-height: 400px;
    overflow: hidden;
    z-index: 1000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }

  .tooltip-header {
    background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
    color: white;
    padding: 12px 16px;
    position: relative;
  }

  .tooltip-domain {
    font-weight: 600;
    font-size: 14px;
    padding-right: 24px;
  }

  .tooltip-org {
    font-size: 12px;
    opacity: 0.9;
    margin-top: 2px;
  }

  .close-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    width: 24px;
    height: 24px;
    border: none;
    background: rgba(255, 255, 255, 0.2);
    color: white;
    border-radius: 50%;
    cursor: pointer;
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s;
  }

  .close-btn:hover {
    background: rgba(255, 255, 255, 0.3);
  }

  .tooltip-content {
    padding: 12px 16px;
    max-height: 300px;
    overflow-y: auto;
  }

  .section-title {
    font-size: 12px;
    font-weight: 600;
    color: #374151;
    margin-bottom: 8px;
  }

  .source-group {
    margin-bottom: 12px;
  }

  .source-type {
    font-size: 11px;
    font-weight: 600;
    color: #6366f1;
    margin-bottom: 4px;
    padding: 2px 8px;
    background: #eef2ff;
    border-radius: 4px;
    display: inline-block;
  }

  .source-item {
    padding: 6px 0;
    border-bottom: 1px solid #f3f4f6;
  }

  .source-item:last-child {
    border-bottom: none;
  }

  .source-parent {
    font-size: 12px;
    color: #6b7280;
  }

  .source-record {
    font-size: 10px;
    color: #9ca3af;
    font-family: monospace;
    margin-top: 4px;
    padding: 4px 6px;
    background: #f9fafb;
    border-radius: 4px;
    word-break: break-all;
    max-height: 60px;
    overflow-y: auto;
  }
</style>
