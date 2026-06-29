<script lang="ts">
  import { Handle, Position, type NodeProps } from '@xyflow/svelte';
  import { icons } from '../lib/icons';

  type LoadMoreData = {
    label: string;
    childCount: number;
    parentId: string;
  };

  let { data }: NodeProps & { data: LoadMoreData } = $props();
</script>

<div class="load-more-node">
  <!-- Handle at center of circle (40px circle, so top: 20px) -->
  <Handle type="target" position={Position.Top} id="target" style="position: absolute; left: 50%; top: 20px; transform: translate(-50%, -50%);" />

  <div class="node-circle">
    <span class="plus-icon">{@html icons.plus}</span>
  </div>
  <div class="node-label">{data.label}</div>
  <div class="node-hint">Click to load</div>
</div>

<style>
  .load-more-node {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    width: 100px;
  }

  .node-circle {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    border: 2px dashed #9ca3af;
    background: white;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }

  .load-more-node:hover .node-circle {
    border-color: #6366f1;
    background: #f5f3ff;
    transform: scale(1.08);
  }

  .plus-icon {
    font-size: 20px; font-weight: 300; color: #9ca3af; line-height: 1;
  }

  .load-more-node:hover .plus-icon { color: #6366f1; }

  .node-label { font-size: 11px; font-weight: 500; color: #6b7280; text-align: center; }
  .node-hint { font-size: 9px; color: #9ca3af; }
</style>
