# AegisSOC interface design system

**Direction:** premium security operations workstation. The interface is matte, information-dense, editorially restrained, and optimized for long analyst sessions. It borrows the clarity and precision of Vercel, Linear, and Datadog without imitating their branding.

## 1. Color palette

| Token | Hex | Tailwind equivalent |
|---|---|---|
| Background / Base | #090C10 | bg-[#090C10] |
| Surface | #10151B | bg-[#10151B] |
| Elevated surface | #161D25 | bg-[#161D25] |
| Border / subtle | #222B35 | border-[#222B35] |
| Border / strong | #34404D | border-[#34404D] |
| Text / primary | #E9EDF2 | text-[#E9EDF2] |
| Text / secondary | #A0AAB6 | text-[#A0AAB6] |
| Text / disabled | #707C89 | text-[#707C89] |
| Healthy / online | #4B9B7A | text-[#4B9B7A] |
| Warning / latency | #C4934E | text-[#C4934E] |
| Critical / offline | #C77780 | text-[#C77780] |
| Informational / egress | #7699BB | text-[#7699BB] |
| Hover surface | #151D26 | hover:bg-[#151D26] |
| Active surface | #18212B | bg-[#18212B] |
| Focus ring | #7899A4 | ring-[#7899A4] |

Use semantic colors only for status, severity, and telemetry classification. Keep fills subtle and pair color with a label or icon.

## 2. Typography

- Primary family: Geist. Fallbacks: Inter, system UI, sans-serif.
- Monospace family: Geist Mono. Fallbacks: SF Mono, Consolas, system monospace.
- Reserve monospace for IP and MAC addresses, event IDs, hashes, logs, precise timestamps, query syntax, and technical measurements. UI copy and navigation always use the primary family.

| Role | Size / line height | Weight |
|---|---:|---:|
| H1 | 34 / 40 px | 560–600 |
| H2 | 23 / 30 px | 560–600 |
| H3 | 17 / 24 px | 560–600 |
| Body | 13 / 21 px | 400 |
| Body emphasis | 13 / 20 px | 500–560 |
| Table values | 12 / 18 px | 400–500 |
| Metadata | 10 / 16 px | 400–500 |
| Technical data | 10–12 / 16–18 px | 400–500 |
| Section labels | 9 / 14 px | 500 |

Headings use -0.045em to -0.02em tracking. Body text uses -0.005em to 0. Technical values use 0 or 0.01em; do not widen long identifiers. Uppercase metadata may use 0.10em to 0.14em.

## 3. Layout & spacing

- Grid: 12 columns, 24 px gutters, max content width 1,600–1,700 px.
- Spacing scale: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64 px. Do not introduce arbitrary 5/7/13 px layout spacing.
- Density: breathable, data-dense. Use 16–20 px panel padding, 12–14 px table cell padding, 14–18 px between cards, and 40–48 px between major sections.
- Sidebar: 252 px expanded; 68 px compact.
- Header: 64 px.
- Content gutters: 40 px desktop, 24 px tablet, 14 px mobile.
- Prefer two-column analyst workspaces for queue/detail and case/evidence layouts. Collapse below 1,120 px; reduce to a single column on mobile. Preserve table readability with horizontal scrolling.

## 4. UI surfaces & elevation

| Component | Radius |
|---|---:|
| Cards / panels | 5 px |
| Buttons / inputs | 4 px |
| Menus / popovers | 6–8 px |
| Status badges | 3–4 px |

- Standard separator: 1 px solid #222B35.
- Strong grouping separator: 1 px solid #34404D.
- Flat matte surface fills by default.
- Floating menus and dialogs only: 0 10px 28px rgb(0 0 0 / 16%).
- Focus: 1 px border plus restrained 2 px #7899A4 ring.
- Hover and active states change surface and border; never scale or glow.

## 5. Anti-patterns (do not do these)

- No pure red, blue, or yellow as primary colors.
- No glossy gradients, glassmorphism, blur-heavy panels, neon glow, or decorative radial backgrounds.
- No icons heavier than 1.5 px stroke.
- No pill-shaped buttons; reserve compact rounded shapes for semantic status badges only.
- No playful/cartoon elements, emoji decoration, gratuitous animation, oversized empty KPI tiles, or rainbow charts.
- No inconsistent font families for technical values, and no tiny low-contrast table typography.
- No status communicated by color alone; no fake live indicators or unverified uptime claims.
