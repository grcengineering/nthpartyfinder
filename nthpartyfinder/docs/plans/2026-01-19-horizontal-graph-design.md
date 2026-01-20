# Horizontal Vendor Graph with Deduplication

## Overview
Redesign the XYFlow Svelte graph to use horizontal left-to-right layout with vendor deduplication, pagination, and info tooltips.

## Requirements
1. **Horizontal layout**: Root on left, vendors expand rightward
2. **Pagination**: Show 10 vendors per layer, "Load More" for additional
3. **Deduplication**: One node per unique vendor domain
4. **Discovery count**: Show how many times vendor was discovered
5. **Info tooltip**: Button in node opens popover with discovery details

## Data Transformation

### Aggregated Vendor Structure
```typescript
interface AggregatedVendor {
  domain: string;
  organization: string;
  layer: number;           // Minimum layer where discovered
  discoveryCount: number;  // Total discovery sources
  sources: Array<{
    recordType: string;
    parentDomain: string;
    rawRecord?: string;
  }>;
  hasChildren: boolean;
  childCount: number;      // Unique child vendors
}
```

### Deduplication Logic
- Group relationships by `nth_party_domain`
- Use minimum `nth_party_layer` as vendor's layer
- Collect all discovery sources into `sources` array
- Count unique child domains for `childCount`

## Layout

### Position Calculation
```typescript
const HORIZONTAL_SPACING = 280;  // Between layers (columns)
const VERTICAL_SPACING = 80;     // Between nodes in layer (rows)

x = layer * HORIZONTAL_SPACING
y = nodeIndex * VERTICAL_SPACING (centered)
```

### Handle Positions
- Source: `Position.Right`
- Target: `Position.Left`

## Pagination

### Constants
```typescript
const VENDORS_PER_PAGE = 10;
```

### Behavior
1. Expand shows first 10 children
2. "Load More" node if >10 children
3. Click Load More reveals next 10
4. Load More updates/disappears when all shown

## Vendor Node UI

```
┌─────────────────────────────┐
│  google.com           [ℹ]  │
│  Google LLC                 │
│  ×3 sources                 │
│  ▶ 5 vendors               │
└─────────────────────────────┘
```

### Interactions
- Click node body → Expand/collapse
- Click [ℹ] button → Open tooltip

## Tooltip Content

```
┌─────────────────────────────────┐
│ google.com                      │
│ Google LLC                      │
├─────────────────────────────────┤
│ Discovery Sources (3):          │
│ • SPF from klaviyo.com          │
│ • CNAME from app.klaviyo.com    │
│ • Subprocessor page             │
└─────────────────────────────────┘
```

## Files to Modify

1. `frontend/src/lib/transform.ts` - Deduplication logic, horizontal positions
2. `frontend/src/VendorGraph.svelte` - Pagination state management
3. `frontend/src/nodes/VendorNode.svelte` - Info button, discovery count
4. `frontend/src/nodes/RootNode.svelte` - Update handle positions
5. `frontend/src/nodes/LoadMoreNode.svelte` - Update handle positions
6. New: `frontend/src/components/VendorTooltip.svelte` - Tooltip component
