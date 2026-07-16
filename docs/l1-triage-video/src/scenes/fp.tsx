import {makeScene2D} from '@motion-canvas/2d';
import {runScenario, C} from '../lib/walkthrough';

import img001 from '../../assets/001.png';
import img002 from '../../assets/002.png';

/**
 * False-Positive scenario — SCDM-649, example IOC 23.54.67.72.
 *
 * Regions are pixel-mapped to:
 *   001.png (1896x1796): verdict, IP origin, reputation, whitelist
 *   002.png (1852x1262): Confluence RAG, Sentinel/KQL
 * x,y are the region CENTRE in each image's own pixel coordinates.
 */
export default makeScene2D(function* (view) {
  yield* runScenario(view, {
    title: 'L1 Triage enrichment comment  ·  SCDM-649',
    sub: 'Step 2 — what the service writes back  (example IOC: 23.54.67.72)',
    closingSub: 'False-Positive — auto-triaged and routed for sign-off',
    pace: 4 / 3, // 0.75x playback speed (every animation takes 1.333x longer)
    images: [
      {src: img001, w: 1896, h: 1796},
      {src: img002, w: 1852, h: 1262},
    ],
    sections: [
      {label: 'AI Verdict & Recommended Action — the triage decision and next step',
        accent: C.ai, img: 0, x: 950, y: 232, w: 1770, h: 330, hold: 2.1},
      {label: 'IP Origin Enrichment — geo, ISP, network, domain, reverse-DNS',
        accent: C.azure, img: 0, x: 948, y: 812, w: 1760, h: 575, hold: 1.9},
      {label: 'Reputation Lookup — VirusTotal · AbuseIPDB · SOCRadar  →  aggregate verdict',
        accent: C.intel, img: 0, x: 948, y: 1262, w: 1760, h: 310, hold: 1.9},
      {label: 'Direct Whitelist Match — IOC found verbatim in the customer’s Confluence KB',
        accent: C.good, img: 0, x: 948, y: 1610, w: 1760, h: 395, hold: 1.9},
      {label: 'Confluence RAG — customer knowledge retrieved by semantic search',
        accent: C.ai, img: 1, x: 926, y: 340, w: 1760, h: 695, hold: 2.2},
      {label: 'Sentinel Evidence — AI-generated KQL hunt  (0 hits = no comms in this env)',
        accent: C.azure, img: 1, x: 926, y: 975, w: 1760, h: 580, hold: 2.1},
    ],
  });
});
