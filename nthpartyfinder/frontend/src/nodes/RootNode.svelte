<script lang="ts">
  import { Handle, Position } from '@xyflow/svelte';

  export let data: {
    label: string;
    organization: string;
    domain: string;
    childCount: number;
    hasChildren: boolean;
    expanded: boolean;
  };
</script>

<div class="root-node" class:expanded={data.expanded}>
  <div class="node-icon">🏢</div>
  <div class="node-content">
    <div class="node-domain">{data.domain}</div>
    {#if data.organization && data.organization !== data.domain}
      <div class="node-org">{data.organization}</div>
    {/if}
    {#if data.hasChildren}
      <div class="node-children">
        {data.expanded ? '◀' : '▶'} {data.childCount} vendor{data.childCount !== 1 ? 's' : ''}
      </div>
    {/if}
  </div>
  <!-- Right handle for horizontal layout -->
  <Handle type="source" position={Position.Right} />
</div>

<style>
  .root-node {
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    color: white;
    padding: 16px 20px;
    border-radius: 12px;
    min-width: 180px;
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .root-node:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(99, 102, 241, 0.4);
  }

  .root-node.expanded {
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
  }

  .node-icon {
    font-size: 24px;
  }

  .node-content {
    flex: 1;
  }

  .node-domain {
    font-weight: 600;
    font-size: 14px;
    margin-bottom: 2px;
  }

  .node-org {
    font-size: 11px;
    opacity: 0.9;
  }

  .node-children {
    font-size: 11px;
    opacity: 0.8;
    margin-top: 4px;
  }
</style>
