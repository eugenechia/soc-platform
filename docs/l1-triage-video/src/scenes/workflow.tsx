import {makeScene2D, Rect, Txt, Line, Node} from '@motion-canvas/2d';
import {all, waitFor, easeInOutCubic, easeOutCubic, easeOutBack} from '@motion-canvas/core';
import {C, FONT} from '../lib/walkthrough';

/**
 * Deep Dive · Act 2 — a ticket's journey, end to end.
 *
 * The "growing diagram" pattern from the original l1triage scene, extended to
 * the full current pipeline: webhook gatekeeping -> stabilization -> dedup ->
 * context gathering -> Phase 1 routing -> enrichment fan-in -> deterministic
 * verdict -> advisory AI layers -> comment -> decision capture.
 *
 * Order verified against routes/webhook.py (_run_enrichment) and
 * tools/enrichment.py (enrich_ticket). Dashed border = killswitch-gated.
 */

export default makeScene2D(function* (view) {
  const FADEBG = C.bg;
  const PACE = 1;
  const D_CAM = 0.5 * PACE;
  const D_ARROW = 0.26 * PACE;
  const D_CARD = 0.36 * PACE;
  const D_CALL = 0.34 * PACE;

  const SX = -220;
  const W = 380;
  const H = 96;
  const VSTEP = 196;
  const BR_W = 320;
  const BR_H = 72;

  // ------------------------------------------------------------- storyboard
  const STAGES: Array<{
    id: string;
    title: string;
    desc: string | null;
    accent: string;
    optional?: boolean;
    from?: string;
    kind?: 'spine' | 'branch';
    hold?: number;
  }> = [
    {id: 'src', title: 'Source Incident', accent: C.sub,
      desc: 'Suspicious activity in the customer environment', hold: 2.2},
    {id: 'sentinel', title: 'Microsoft Sentinel', accent: C.azure, from: 'src',
      desc: 'An analytics rule fires and raises an incident', hold: 2.2},
    {id: 'logic', title: 'Azure Logic Apps', accent: C.azure, from: 'sentinel',
      desc: 'Opens a Jira ticket — then keeps populating entity fields (IPs, hosts, hashes) for ~20–30s', hold: 3.2},
    {id: 'jira', title: 'Jira Ticket Created', accent: C.jira, from: 'logic',
      desc: 'issue_created webhook fires to /webhook/jira — rejected outright without the shared secret', hold: 3.0},
    {id: 'gate', title: 'Project Allowlist Gate', accent: C.bad, from: 'jira',
      desc: 'FAIL-CLOSED: the project key must be explicitly allowlisted (JIRA_ENRICHMENT_PROJECT). An empty list denies ALL tickets — onboarding a customer is a deliberate act', hold: 4.6},
    {id: 'svc', title: 'L1 Triage Service', accent: C.ai, from: 'gate',
      desc: 'Returns HTTP 200 instantly; enrichment runs on a background thread — Jira never waits on AI', hold: 3.0},
    {id: 'poll', title: 'Field Stabilization', accent: C.azure, from: 'svc',
      desc: 'Polls every 5s (up to 60s) until Sentinel’s entity fields land, then a 30s settling window — never triage a half-populated ticket', hold: 3.8},
    {id: 'dedup', title: 'Deduplication', accent: C.intel, from: 'poll',
      desc: 'Strict-match duplicate within 24h?  Rule-based, not AI   ·   DEDUP_WEBHOOK_ENABLED', hold: 3.2},
    {id: 'dupstop', title: 'Duplicate → close & stop', accent: C.bad,
      from: 'dedup', kind: 'branch', desc: null, hold: 1.6},
    {id: 'hist', title: 'Historical Correlation — 24h', accent: C.sub, from: 'dedup',
      desc: '“This alert fired 50× today, benign every time” — similar alerts in the same project, grouped by prior verdict   ·   HISTORICAL_LOOKUP_ENABLED', hold: 4.2},
    {id: 'pattern', title: 'Alert Pattern Analysis — 30d', accent: C.sub, from: 'hist',
      optional: true,
      desc: 'Longer-horizon correlation, frequency, timing and tuning analysis — currently comment-only while the team validates it   ·   ALERT_PATTERN_ANALYSIS_ENABLED', hold: 4.0},
    {id: 'rag', title: 'Confluence RAG — Customer KB', accent: C.ai, from: 'pattern',
      optional: true,
      desc: 'Hybrid vector + literal-substring search over THIS customer’s pages only — 5s hard timeout, forbidden from raising   ·   RAG_LOOKUP_ENABLED', hold: 4.2},
    {id: 'routing', title: 'Triage Foundation — Phase 1', accent: C.ai, from: 'rag',
      desc: 'Fast routing before deep enrichment:   ① SIEM severity → Jira priority baseline    ② auto-assign to GSOC    ③ LLM priority override — applied ONLY at confidence ≥ 0.7, with a written rationale', hold: 5.4},
    {id: 'kql', title: 'Sentinel Evidence (KQL)', accent: C.azure, from: 'routing',
      optional: true,
      desc: 'AI-generated KQL pulls supporting logs from the customer’s own workspace   ·   KQL_EXPANSION_ENABLED', hold: 3.4},
    {id: 'ioc', title: 'IOC Extraction', accent: C.intel, from: 'kql',
      desc: 'Parses raw Sentinel/Defender entity JSON (not plain strings) + regex fallback; filters private IPs. A schema-mismatch detector FAILS LOUD if indicators are visibly present but none extracted', hold: 5.0},
    {id: 'rep', title: 'Reputation Lookup', accent: C.intel, from: 'ioc',
      desc: 'Per IOC → VirusTotal · AbuseIPDB · SOCRadar (budget-capped 5/ticket), plus an IP-Origin block: country, ISP, network, usage, reverse-DNS', hold: 4.2},
    {id: 'verdict', title: 'Deterministic Verdict', accent: C.good, from: 'rep',
      desc: 'Rules, not the LLM: SOCRadar ≥ 70 / any VT detection / AbuseIPDB > 50 ⇒ True-Positive · no data ⇒ Unknown · else Benign-Positive. The malicious/clean call rests on verifiable evidence', hold: 5.4},
    {id: 'wl', title: 'Whitelist Match', accent: C.intel, from: 'verdict',
      optional: true,
      desc: 'Customer whitelist can override toward benign ONLY — never toward malicious — and hard reputation evidence wins on conflict', hold: 3.8},
    {id: 'mitre', title: 'MITRE ATT&CK Mapping', accent: C.ai, from: 'wl',
      desc: 'Up to 3 ranked techniques, on the cheap model tier   ·   MITRE_MAPPING_ENABLED', hold: 3.0},
    {id: 'insights', title: 'IOC Web-Research Insights', accent: C.ai, from: 'mitre',
      optional: true,
      desc: 'Tavily research + LLM summary for MALICIOUS indicators only, strictly grounded in retrieved sources   ·   IOC_INSIGHTS_ENABLED', hold: 3.6},
    {id: 'cmd', title: 'Command-Line Analysis', accent: C.ai, from: 'insights',
      optional: true,
      desc: 'Process/PowerShell command lines fetched from the customer’s Sentinel, judged for encoded commands & LOLBin abuse. ADVISORY only — never changes the verdict   ·   CMDLINE_ANALYSIS_ENABLED', hold: 4.6},
    {id: 'code', title: 'Security-Code Decode', accent: C.ai, from: 'cmd',
      optional: true,
      desc: 'Windows Event IDs, logon types, NTSTATUS & Kerberos codes in plain English — offline dictionary first, cheap LLM only for unknowns   ·   CODE_EXPLAIN_ENABLED', hold: 4.0},
    {id: 'route', title: 'Label & Route', accent: C.good, from: 'code',
      desc: 'True-Positive → L1 · Benign-Positive / Unknown → L2 review. The ticket is NEVER closed by the AI — a human always makes the final call', hold: 4.4},
    {id: 'rec', title: 'Recommended Next Action', accent: C.ai, from: 'route',
      optional: true,
      desc: 'One synthesized, industry-aware next step for the analyst (≤ 280 chars)   ·   RECOMMENDATION_SYNTHESIS_ENABLED', hold: 3.2},
    {id: 'comment', title: 'Enrichment Comment → Jira', accent: C.jira, from: 'rec',
      desc: '“IOC Enrichment Report (Automated)” — rich ADF with plain-text fallback, timestamps in SGT. 20–30 minutes of manual L1 lookup, delivered before an analyst opens the ticket', hold: 5.0},
    {id: 'capture', title: 'L2 Decision Capture', accent: C.sub, from: 'comment',
      optional: true,
      desc: 'The learning loop: issue_updated logs the analyst’s FINAL label — raw material for future prompt tuning   ·   DECISION_CAPTURE_ENABLED', hold: 3.8},
  ];

  // ------------------------------------------------- assign positions (y down)
  type Stage = (typeof STAGES)[number] & {
    x: number; y: number; card?: Rect; callout?: Txt; arrow?: Line;
  };
  const byId: Record<string, Stage> = {};
  let spineY = 0;
  for (const raw of STAGES) {
    const s = raw as Stage;
    if (s.kind === 'branch') {
      const parent = byId[s.from!];
      s.x = -720;
      s.y = parent.y;
    } else {
      s.x = SX;
      s.y = spineY;
      spineY += VSTEP;
    }
    byId[s.id] = s;
  }
  const lastY = spineY - VSTEP;

  // ----------------------------------------------------------------- scaffold
  view.add(new Rect({width: 1920, height: 1080, fill: FADEBG}));

  // act intro
  const intro = new Node({});
  intro.add(new Txt({
    text: 'Act 2 of 3 — A Ticket’s Journey', y: -50,
    fontFamily: FONT, fontSize: 58, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  intro.add(new Txt({
    text: 'What actually happens when an alert becomes a Jira ticket',
    y: 30, fontFamily: FONT, fontSize: 30, fill: C.sub, opacity: 0,
  }));
  view.add(intro);
  yield* all(...intro.children().map(t => (t as Txt).opacity(1, 0.7)));
  yield* waitFor(2.6);
  yield* intro.opacity(0, 0.6);

  const cam = new Node({position: [0, -120]});
  const links = new Node({});
  const nodes = new Node({});
  cam.add(links);
  cam.add(nodes);
  view.add(cam);

  const title = new Txt({
    text: 'Act 2 — A Ticket’s Journey', x: -905, y: -468, offset: [-1, 0],
    fontFamily: FONT, fontSize: 42, fontWeight: 700, fill: C.text, opacity: 0,
  });
  const subtitle = new Txt({
    text: 'How a Sentinel alert becomes a triaged, enriched Jira ticket',
    x: -903, y: -424, offset: [-1, 0],
    fontFamily: FONT, fontSize: 22, fill: C.sub, opacity: 0,
  });
  const legend = new Txt({
    text: '╌╌  dashed border = optional step (killswitch-gated)',
    x: -905, y: 476, offset: [-1, 0],
    fontFamily: FONT, fontSize: 20, fill: C.sub, opacity: 0,
  });
  const caption = new Txt({
    text: 'The complete L1 triage pipeline — every stage failure-isolated, no stage can block the comment',
    x: 0, y: 480, fontFamily: FONT, fontSize: 26, fill: C.text, opacity: 0,
  });
  view.add(title);
  view.add(subtitle);
  view.add(legend);
  view.add(caption);

  // -------------------------------------------------------------- build cards
  for (const s of STAGES as Stage[]) {
    if (!s.from) continue;
    const p = byId[s.from];
    let start: [number, number];
    let end: [number, number];
    let col: string;
    if (s.kind === 'branch') {
      start = [p.x - W / 2, p.y];
      end = [s.x + BR_W / 2, s.y];
      col = C.bad;
    } else {
      start = [p.x, p.y + H / 2];
      end = [s.x, s.y - H / 2];
      col = C.link;
    }
    const line = new Line({
      points: [start, end], stroke: col, lineWidth: 3,
      endArrow: true, arrowSize: 12, lineCap: 'round', end: 0, opacity: 0.95,
    });
    links.add(line);
    s.arrow = line;
  }
  for (const s of STAGES as Stage[]) {
    const isBranch = s.kind === 'branch';
    const w = isBranch ? BR_W : W;
    const h = isBranch ? BR_H : H;
    const card = new Rect({
      x: s.x, y: s.y, width: w, height: h, radius: 12,
      fill: s.optional ? '#111d30' : C.card,
      stroke: s.accent, lineWidth: 2.5,
      lineDash: s.optional ? [9, 7] : [],
      opacity: 0, scale: 0.9,
      shadowColor: '#00000077', shadowBlur: 18, shadowOffsetY: 6,
    });
    card.add(new Txt({
      text: s.title, fontFamily: FONT,
      fontSize: isBranch ? 21 : 25, fontWeight: 600,
      fill: isBranch ? C.bad : C.text,
      width: w - 28, textWrap: true, textAlign: 'center', lineHeight: 30,
    }));
    nodes.add(card);
    s.card = card;
    if (s.desc) {
      const call = new Txt({
        text: s.desc, fontFamily: FONT, fontSize: 21, fill: C.sub,
        x: s.x + w / 2 + 34, y: s.y, offset: [-1, 0],
        width: 620, textWrap: true, textAlign: 'left', lineHeight: 29,
        opacity: 0,
      });
      nodes.add(call);
      s.callout = call;
    }
  }

  // -------------------------------------------------------------------- intro
  yield* all(title.opacity(1, 0.6), subtitle.opacity(1, 0.6));
  yield* waitFor(0.5 * PACE);
  yield* legend.opacity(1, 0.4);

  // --------------------------------------------------------------- build loop
  for (const s of STAGES as Stage[]) {
    yield* all(
      cam.position.y(-120 - s.y, D_CAM, easeInOutCubic),
      (function* () {
        if (s.arrow) yield* s.arrow.end(1, D_ARROW, easeOutCubic);
        yield* all(
          s.card!.opacity(1, D_CARD),
          s.card!.scale(1, D_CARD, easeOutBack),
          ...(s.callout ? [s.callout.opacity(1, D_CALL)] : []),
        );
      })(),
    );
    yield* waitFor((s.hold ?? 3.0) * PACE);
  }

  // ---------------------------------------------------------------- zoom-out
  yield* waitFor(0.4 * PACE);
  const fit = 1000 / (lastY + H + 120);
  const midY = lastY / 2;
  yield* all(
    cam.scale(fit, 1.5 * PACE, easeInOutCubic),
    cam.position([30, 40 - midY * fit], 1.5 * PACE, easeInOutCubic),
    caption.opacity(1, 1.0 * PACE),
  );
  yield* waitFor(4.5);
  yield* all(cam.opacity(0, 0.5), title.opacity(0, 0.5), subtitle.opacity(0, 0.5),
    legend.opacity(0, 0.5), caption.opacity(0, 0.5));
  yield* waitFor(0.4);
});
