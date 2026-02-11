<script lang="ts">
  import { Handle, Position } from '@xyflow/svelte';

  export let data: {
    label: string;
    childCount: number;
    parentId: string;
  };
</script>

<div class="load-more-node">
  <!-- Top handle for vertical layout -->
  <Handle type="target" position={Position.Top} />

  <div class="node-content">
    <div class="node-icon">+</div>
    <div class="node-label">{data.label}</div>
    <div class="node-hint">Click to load</div>
  </div>
</div>

<style>
  .load-more-node {
    background: white;
    border: 2px dashed #9ca3af;
    color: #6b7280;
    padding: 10px 14px;
    border-radius: 8px;
    min-width: 100px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .load-more-node:hover {
    border-color: #6366f1;
    color: #6366f1;
    background: #f5f3ff;
  }

  .node-content {
    text-align: center;
  }

  .node-icon {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 2px;
  }

  .node-label {
    font-size: 12px;
    font-weight: 500;
  }

  .node-hint {
    font-size: 9px;
    opacity: 0.7;
    margin-top: 2px;
  }
</style>
