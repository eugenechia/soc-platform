import {makeScene2D} from '@motion-canvas/2d';
import {runScenario, C} from '../lib/walkthrough';

import img003 from '../../assets/003.png';
import img004 from '../../assets/004.png';

/**
 * True-Positive scenario — example IOC 167.94.145.18 (Trojan:Win32/Pomal).
 *
 * Regions are pixel-mapped to:
 *   003.png (1928x1776): verdict, IP origin, reputation (MALICIOUS), historical
 *   004.png (1846x1274): Confluence RAG, Sentinel/KQL, MITRE ATT&CK
 * x,y are the region CENTRE in each image's own pixel coordinates.
 *
 * Differs from the FP scene: no Whitelist Match (it's malicious), and adds the
 * Historical Correlation + MITRE ATT&CK spotlights.
 */
export default makeScene2D(function* (view) {
  yield* runScenario(view, {
    title: 'L1 Triage enrichment comment  ·  True-Positive case',
    sub: 'Step 2 — what the service writes back  (example IOC: 167.94.145.18)',
    closingSub: 'True-Positive — Trojan:Win32/Pomal flagged for analyst action',
    pace: 4 / 3, // 0.75x playback speed (every animation takes 1.333x longer)
    images: [
      {src: img003, w: 1928, h: 1776},
      {src: img004, w: 1846, h: 1274},
    ],
    sections: [
      {label: 'AI Verdict & Recommended Action — flagged TRUE-POSITIVE (Trojan:Win32/Pomal quarantined)',
        accent: C.bad, img: 0, x: 964, y: 200, w: 1810, h: 290, hold: 2.2},
      {label: 'IP Origin Enrichment — geo, ISP, network, domain, reverse-DNS',
        accent: C.azure, img: 0, x: 964, y: 760, w: 1810, h: 565, hold: 1.9},
      {label: 'Reputation Lookup — SOCRadar flags MALICIOUS 100/100  (attackers · phishing · botnet)',
        accent: C.bad, img: 0, x: 964, y: 1400, w: 1810, h: 660, hold: 2.3},
      {label: 'Historical Correlation — this IOC was previously flagged 50 times across past tickets',
        accent: C.intel, img: 0, x: 964, y: 1748, w: 1810, h: 66, hold: 2.0},
      {label: 'Confluence RAG — customer knowledge retrieved by semantic search',
        accent: C.ai, img: 1, x: 923, y: 172, w: 1780, h: 345, hold: 2.0},
      {label: 'Sentinel Evidence — AI-generated KQL hunt across DeviceNetworkEvents',
        accent: C.azure, img: 1, x: 923, y: 612, w: 1780, h: 545, hold: 2.0},
      {label: 'MITRE ATT&CK — techniques mapped: Persistence · C2  (T1176, T1071.001, T1105)',
        accent: C.ai, img: 1, x: 923, y: 1078, w: 1780, h: 385, hold: 2.3},
    ],
  });
});
