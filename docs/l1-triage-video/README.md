# L1 Triage — End-to-End Animation

## Projects in this folder

- **fp / tp** — the original scenario walkthroughs (False-Positive SCDM-649,
  True-Positive), built on `src/lib/walkthrough.ts` over real comment
  screenshots.
- **deepdive** (`src/deepdive.project.ts`) — the in-depth three-act video
  (~7 min): Act 1 infrastructure map (hub-and-spoke over the Azure
  components), Act 2 full ticket workflow (26-stage growing diagram, verified
  against `routes/webhook.py` + `tools/enrichment.py`), Act 3 the eight
  AI-guardrail families, closing on "probabilistic AI inside deterministic
  rails". Scenes: `src/scenes/infra.tsx`, `workflow.tsx`, `guardrails.tsx`.
- **prodarch** (`src/prodarch.project.ts`) — the production private-tenant
  architecture explainer (~4.5 min): Act 1 two tenants / one codebase, Act 2
  inbound doors + firewall-controlled egress (how Tavily survives), Act 3 the
  promote-only release workflow. Facts verified against
  `docs/PROD-PRIVATE-TENANT-ARCHITECTURE.md`. Scenes:
  `src/scenes/prodtopo.tsx`, `proddoors.tsx`, `prodpromote.tsx`.

Headless render (no editor interaction): start `npm run serve`, then

```bash
NODE_PATH="../../../SOC-Copilot/docs/detection-engineer-video/node_modules" \
  node scripts/render.cjs <project>   # e.g. prodarch → output/prodarch.project.mp4
```

(`scripts/render.cjs` drives the editor with Playwright, clicks RENDER, and
polls the mp4 until its size stabilises. Playwright itself is borrowed from
the SOC-Copilot video project's node_modules.)

A [Motion Canvas](https://motioncanvas.io) project that renders a "growing
diagram" of the SOC-Triage L1 pipeline: each component appears in a box with a
connecting arrow and a short description, the camera follows down the flow, and
a final zoom-out reveals the whole pipeline.

The flow and ordering mirror the real code (`routes/webhook.py`,
`tools/enrichment.py`): webhook → field stabilization → dedup → Phase 1 routing
→ enrichment → MITRE → verdict → comment, with the `issue_updated` decision-
capture loop shown separately. Killswitch-gated steps have a dashed border.

## Prerequisites

- Node.js 18+ and npm.

## Setup

```bash
cd "Office/Office-Lab/SOC-Triage/docs/l1-triage-video"
npm install
```

## Preview (live editor)

```bash
npm run serve
```

Open the URL it prints (usually http://localhost:9000). You get a live preview
with a timeline scrubber — edits to `src/scenes/l1triage.tsx` hot-reload.

## Render to MP4

1. Run `npm run serve` and open the editor.
2. Top bar → **Render** (or the video-camera icon).
3. Output is written to `./output/` as an `.mp4` (the FFmpeg exporter bundles
   ffmpeg, so no system install is needed).

Resolution (1920×1080) and frame rate (30 fps) are preset in
`src/project.meta`; change them there or in the editor's render settings.

## Tuning the animation

Everything lives in `src/scenes/l1triage.tsx`:

- **`PACE`** (top of the scene) — global speed multiplier. Raise it to slow the
  whole thing down for narration (e.g. `1.6`).
- **`STAGES`** — the storyboard array. Each row is one component:
  `title`, `desc` (the side callout), `accent` (colour), `optional` (dashed =
  killswitch-gated), and `from` (which box the arrow comes from). Add, remove,
  reword, or reorder rows here — positions down the spine are auto-assigned.
- **`C`** — the colour palette.
- **`VSTEP`** — vertical spacing between components.

## Notes

- This folder is excluded from the Flask Docker image via the repo-root
  `.dockerignore` and from git via the local `.gitignore` (node_modules, output).
- If `npm install` ever fails on version resolution, the most robust fallback is
  to scaffold a fresh project with `npm init @motion-canvas@latest` (it picks
  mutually-compatible versions and sets up the FFmpeg exporter), then copy
  `src/scenes/l1triage.tsx` in and point `src/project.ts` at it.
