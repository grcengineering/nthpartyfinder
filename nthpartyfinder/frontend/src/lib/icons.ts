// Lucide icons (GRCE Design System icon set) as inline SVG strings for the
// offline graph bundle. currentColor + 1em so they inherit the node's color/size.
// Mirrors lucide-static v0.544.0. Rendered via {@html ...} in the graph nodes.
const wrap = (inner: string): string =>
  `<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;

export const icons = {
  building2: wrap('<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" /><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" /><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" /><path d="M10 6h4" /><path d="M10 10h4" /><path d="M10 14h4" /><path d="M10 18h4" />'),
  chevronUp: wrap('<path d="m18 15-6-6-6 6" />'),
  chevronDown: wrap('<path d="m6 9 6 6 6-6" />'),
  info: wrap('<circle cx="12" cy="12" r="10" /><path d="M12 16v-4" /><path d="M12 8h.01" />'),
  x: wrap('<path d="M18 6 6 18" /><path d="m6 6 12 12" />'),
  plus: wrap('<path d="M5 12h14" /><path d="M12 5v14" />'),
};