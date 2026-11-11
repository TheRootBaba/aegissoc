# AegisSOC interface design system — v3

**Direction:** a calm, high-clarity security operations workspace. The visual system uses a 60/30/10 composition rather than an all-dark canvas: warm mineral neutrals provide the working surface, deep blue-green carries navigation and structural weight, and teal is reserved for focused interaction.

## Color composition (60 / 30 / 10)

| Share | Role | Token | Value |
|---:|---|---|---|
| 60% | Main canvas, reading surfaces, tables | Canvas | #F3F5F2 |
| 30% | Navigation, hierarchy, strong structure | Deep blue-green | #173746 |
| 10% | Primary actions, focus, active navigation | Signal teal | #0B8D83 |

Supporting surfaces: white #FFFFFF, soft sage #E9EFEC, border #DCE4E0, strong border #C5D2CC. Primary text #172A32, secondary text #52666C, muted metadata #71838A.

Semantic status colors are independent of the 60/30/10 brand composition: healthy #287B62, warning #98631E, critical #B64C55, informational #456F9B. Use pale tints for backgrounds and always pair a semantic color with a label. Do not use teal to represent severity.

## Typography

- UI and reading family: Inter (400, 500, 600, 650, 700, 750).
- Technical family: IBM Plex Mono (400, 500, 600), reserved for IPs, hashes, event IDs, query syntax, timestamps and machine identifiers.
- Body: 14px / 1.65, weight 400, letter spacing -0.012em.
- H1: clamp(34px, 3vw, 44px) / 1.13, weight 650, tracking -0.055em.
- H2: 25px / 1.28, weight 650, tracking -0.04em.
- H3: 17–19px / 1.4, weight 600.
- Table values: 12–13px / 1.6. Metadata: 11–12px / 1.55.
- Never compress labels or headings to fit. Wrap long identifiers and use horizontal scrolling for genuinely wide tables.

## Layout and rhythm

- 4px base spacing scale: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64px.
- Desktop content gutters: 40px; tablet: 24px; mobile: 14px.
- Main section spacing: 34–40px; card padding: 18–22px; form row gaps: 12–16px.
- Keep dashboard content in a readable max-width; use two-column investigation layouts only when both panes remain usable.
- Inputs and buttons: 40px minimum height; 6px radius. Cards: 9px radius. Avoid pill-shaped primary controls.

## Surfaces and interaction

- Matte surfaces, clear 1px borders, subtle shadows only for separation.
- Teal focus rings must remain visible on keyboard navigation.
- Hover changes background and border, not scale or glow.
- Respect reduced-motion preferences.
- Avoid gradients, glass effects, neon, decorative color fields, low-contrast gray copy, and dense all-caps body text.
- The interface must remain readable at 100% browser zoom and on 320px-wide screens.


## Dashboard v3 implementation notes

The rendered shell uses a deep blue-green navigation rail (#173746) against the mineral canvas (#F3F5F2), with teal (#0B8D83) reserved for primary actions and keyboard focus. The main reading area stays light; cards and tables use white surfaces, clear separators, and comfortable line-height. Inter is loaded at supported weights (400–800) for interface text; IBM Plex Mono is reserved for technical identifiers. Body copy is 15px / 1.7, with section headings around 25px / 1.32. The stylesheet and script use a versioned asset query so browsers do not retain stale pre-v3 files after an upgrade.

Asset risk and response playbook workspaces follow the same spacing, typography, surface, and responsive rules. Long identifiers wrap rather than compressing surrounding text.
