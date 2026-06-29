<script lang="ts">
  import { Handle, Position, type NodeProps } from '@xyflow/svelte';
  import { icons } from '../lib/icons';

  type RootData = {
    label: string;
    organization: string;
    domain: string;
    childCount: number;
    hasChildren: boolean;
    expanded: boolean;
  };

  let { data }: NodeProps & { data: RootData } = $props();
</script>

<div class="root-node" class:expanded={data.expanded}>
  <!-- Handle at center of circle (56px circle, so top: 28px) -->
  <Handle type="source" position={Position.Bottom} id="source" style="position: absolute; left: 50%; top: 28px; transform: translate(-50%, -50%);" />

  <div class="node-circle">
    <span class="node-icon">{@html icons.building2}</span>
    {#if data.hasChildren}
      <div class="badge">{data.childCount}</div>
    {/if}
  </div>
  <div class="node-label">{data.domain}</div>
  {#if data.hasChildren}
    <div class="node-hint">{data.expanded ? 'Click to collapse' : 'Click to expand'}</div>
  {/if}
</div>

<style>
  .root-node {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    width: 120px;
  }

  .node-circle {
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px rgba(99, 102, 241, 0.35);
    transition: transform 0.2s, box-shadow 0.2s;
    position: relative;
  }

  .root-node:hover .node-circle {
    transform: scale(1.08);
    box-shadow: 0 4px 16px rgba(99, 102, 241, 0.45);
  }

  .root-node.expanded .node-circle {
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25), 0 2px 8px rgba(99, 102, 241, 0.35);
  }

  .node-icon { font-size: 24px; line-height: 1; color: #fff; display: inline-flex; }

  .badge {
    position: absolute;
    top: -4px;
    right: -4px;
    min-width: 20px;
    height: 20px;
    border-radius: 10px;
    background: #ef4444;
    color: white;
    font-size: 10px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0 5px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
  }

  .node-label {
    font-size: 12px;
    font-weight: 600;
    color: #1e293b;
    text-align: center;
    max-width: 120px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .node-hint { font-size: 9px; color: #94a3b8; }
</style>
