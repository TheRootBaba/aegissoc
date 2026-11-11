# AegisSOC interface design system

A matte, technical operations console: restrained contrast, compact data surfaces, clear hierarchy, and semantic color used only when it carries operational meaning. The design avoids ornamental gradients, glass effects, inflated cards, and decorative animation.

## 1. Color palette

| Token | Hex | Tailwind equivalent |
|---|---|---|
| Background / Base | `#0B0D10` | `bg-[#0B0D10]` |
| Surface | `#11151A` | `bg-[#11151A]` |
| Elevated surface | `#171D24` | `bg-[#171D24]` |
| Border / subtle | `#242B33` | `border-[#242B33]` |
| Border / strong | `#303943` | `border-[#303943]` |
| Text / primary | `#E7EBEF` | `text-[#E7EBEF]` |
| Text / secondary | `#98A2AD` | `text-[#98A2AD]` |
| Text / disabled | `#59636E` | `text-[#59636E]` |
| Healthy / online | `#3C9B76` | `text-[#3C9B76]` / `bg-[#3C9B76]/10` |
| Warning / latency | `#C18A3A` | `text-[#C18A3A]` / `bg-[#C18A3A]/10` |
| Critical / offline | `#C46B75` | `text-[#C46B75]` / `bg-[#C46B75]/10` |
| Informational / egress | `#648DB8` | `text-[#648DB8]` / `bg-[#648DB8]/10` |
| Hover surface | `#1A222B` | `hover:bg-[#1A222B]` |
| Active surface | `#202A35` | `bg-[#202A35]` |
| Focus ring | `#6B9A9A` | `ring-[#6B9A9A]` |

Semantic accents are for state, severity, and telemetry classification—not large decorative fills. Pair every status color with a readable label or icon; never rely on color alone.

## 2. Typography

- **Primary:** Geist, with a system fallback stack: `Geist, Inter, ui-sans-serif, system-ui, sans-serif`.
- **Monospace:** Geist Mono, then `ui-monospace, SFMono-Regular, Consolas, monospace`.
- Use monospace exclusively for IP/MAC addresses, event IDs, hashes, timestamps when precision matters, log excerpts, code, and technical measurements. Use the primary face for navigation, labels, descriptions, and actions.

| Role | Size / line height | Weight |
|---|---:|---:|
| H1 | 32 / 40 px | 600 |
| H2 | 22 / 30 px | 600 |
| H3 | 16 / 24 px | 600 |
| Body | 13 / 20 px | 400 |
| Body emphasis | 13 / 20 px | 500 |
| Metadata / labels | 11 / 16 px | 500 |
| Dense table values | 12 / 18 px | 400 |
| Technical data | 12 / 18 px | 400 |

UI headings use tight tracking from `-0.025em` to `-0.01em`; body copy uses `0`. Technical data uses `0` or `0.01em`, never artificial wide tracking on long IDs. Uppercase section labels may use `0.08em` at 10–11 px.

## 3. Layout & spacing

- Use a 12-column content grid with a 24 px gutter. Main content max width is 1,600 px; center it on wide displays while keeping the sidebar fixed.
- Use a strict 4 px spacing scale: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64 px. Prefer 8 px increments for major layout rhythm.
- Density is **breathable but data-dense**: 16–20 px card padding, 12–14 px table rows, 24 px section gaps, and 8–12 px control gaps. Avoid oversized empty hero regions.
- Global sidebar: 248 px expanded, 64 px compact. Header: 60 px high. Main content horizontal padding: 32 px desktop, 20 px tablet, 14 px mobile.
- Use two-column analyst workspaces where detail panels add value; collapse to one column below 1,000 px. Tables scroll horizontally rather than crushing technical columns.

## 4. UI surfaces & elevation

- Cards and panels: 6 px radius. Inputs and standard buttons: 5 px. Menus/popovers: 8 px. Status badges may use 4 px; avoid pill geometry elsewhere.
- Standard separators are 1 px solid `#242B33`; stronger grouping uses 1 px solid `#303943`. Do not use translucent borders as the default.
- Default surfaces are flat matte fills. Only floating menus, dialogs, and toasts receive a diffuse shadow: `0 8px 24px rgb(0 0 0 / 18%)`. No persistent card shadows.
- Focus states use a 1 px border plus a restrained 2 px `#6B9A9A` ring. Hover and active states change surface/border, not scale or glow.

## 5. Anti-patterns (do not do these)

- No bright primary colors, including pure red, pure blue, or pure yellow. Use the semantic palette above.
- No heavy glossy gradients, glassmorphism, blur-heavy panels, neon glow, or decorative radial backgrounds.
- No icons heavier than 1.5 px stroke. Prefer crisp 1.5 px line icons with consistent 16–18 px sizing.
- No pill-shaped buttons except status badges when the badge semantics justify it.
- No playful or cartoonish UI elements, oversized emoji, novelty illustrations, or gratuitous motion.
- No excessive corner rounding, huge KPI tiles, rainbow charts, or decorative charts without an operational question.
- No status communicated by color alone; no fake live indicators or unverified uptime claims.
