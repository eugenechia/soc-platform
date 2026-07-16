import {makeScene2D, Rect, Txt, Line, Node, Circle} from '@motion-canvas/2d';
import {all, waitFor, easeOutCubic, easeOutBack, easeInOutCubic} from '@motion-canvas/core';
import {C, FONT} from '../lib/walkthrough';

/**
 * Prod Architecture · Act 2 — Two doors in, one gate out.
 *
 * Center: the internal Container App. Left: the two inbound doors (Jira Cloud
 * webhooks through the path-locked App Gateway; analysts over the corporate
 * network). Right: the egress gate — Azure Firewall with a default-deny FQDN
 * allowlist — and the SaaS destinations behind it, with an animated packet
 * tracing the Tavily call. Bottom: the private-endpoint plane that never
 * touches the firewall at all.
 *
 * Facts verified against docs/PROD-PRIVATE-TENANT-ARCHITECTURE.md.
 */

interface Item {
  id: string;
  title: string;
  sub?: string;
  accent: string;
  x: number;
  y: number;
  w: number;
  h: number;
  callout: string;
  dashed?: boolean;
  from?: string;
  to?: string; // arrow direction override: draw from THIS item toward `to`
}

const ITEMS: Item[] = [
  {id: 'aca', title: 'soc-platform — internal Container App',
    sub: 'no public FQDN · UDR 0.0.0.0/0 → firewall',
    accent: C.azure, x: -80, y: -50, w: 520, h: 130,
    callout: 'In production the app has no public address at all. Everything in this act is about the few, deliberate paths that connect it to the world.'},

  // door 1 — jira webhooks
  {id: 'jira', title: 'Jira Cloud', sub: '*.atlassian.net · webhooks',
    accent: C.jira, x: -760, y: -390, w: 330, h: 96,
    callout: 'Jira stays in Atlassian Cloud — tickets are born there, and its webhooks must reach the app within seconds of a new alert. That is the one inbound flow that genuinely comes from the public internet.'},
  {id: 'appgw', title: 'App Gateway WAF v2', sub: 'public listener · PATH-LOCKED',
    accent: C.bad, x: -760, y: -210, w: 330, h: 100, from: 'jira',
    callout: 'So one public door exists: an Application Gateway with a WAF. It forwards exactly ONE path — /webhook/jira — to the app. Every other URL returns 403. Admin UI, dashboards, triage pages: unreachable from the internet.'},
  {id: 'guard', title: 'Three locks on the door',
    sub: 'WAF rules · Atlassian source-IP allowlist · webhook secret',
    accent: C.bad, x: -760, y: -60, w: 330, h: 110, dashed: true,
    callout: 'Defense in depth on that single path: WAF inspection, a network rule admitting only Atlassian’s published egress IP ranges, and the app’s own webhook secret token. Three independent locks.'},

  // door 2 — analysts
  {id: 'analyst', title: 'SOC Analysts', sub: 'corporate network',
    accent: C.intel, x: -760, y: 150, w: 330, h: 96,
    callout: 'The second door is not public at all. Analysts on the corporate network reach the app through the hub’s ExpressRoute or VPN.'},
  {id: 'dns', title: 'Private DNS', sub: 'internal FQDN · resolves only inside the network',
    accent: C.intel, x: -760, y: 310, w: 330, h: 96, from: 'analyst',
    callout: 'Private DNS resolves the app’s internal hostname only inside the network. Entra single sign-on still works unchanged — the browser talks to Microsoft’s identity service directly, so SSO needs no inbound path to the app.'},

  // egress gate
  {id: 'fw', title: 'Azure Firewall', sub: 'default-deny · FQDN allowlist · static egress IP',
    accent: C.intel, x: 560, y: -50, w: 420, h: 120, from: 'aca',
    callout: 'Outbound, there is exactly one gate. The app subnet’s default route forces ALL traffic through the Azure Firewall, which permits HTTPS only to a named allowlist of destinations — and logs everything, allowed or denied.'},
  {id: 'tavily', title: 'api.tavily.com', sub: 'IOC web research · sanitized payloads',
    accent: C.good, x: 560, y: -390, w: 420, h: 90, from: 'fw',
    callout: 'This is how Tavily keeps working in a private tenant: the call leaves through the firewall because api.tavily.com is explicitly allowlisted — and the privacy sanitizer has already stripped anything that could identify a client before the query leaves the app.'},
  {id: 'ti', title: 'VirusTotal · AbuseIPDB', sub: 'IOC reputation',
    accent: C.good, x: 560, y: -260, w: 420, h: 84, from: 'fw',
    callout: 'The threat-intelligence lookups the verdict depends on — VirusTotal and AbuseIPDB — are allowlisted the same way. Named destination, business justification, full logs.'},
  {id: 'atl', title: '*.atlassian.net · SOCRadar', sub: 'Jira REST · Confluence RAG sync',
    accent: C.good, x: 560, y: 130, w: 420, h: 84, from: 'fw',
    callout: 'Jira REST calls go back out through the same gate, as do Confluence page syncs for RAG and the SOCRadar feeds.'},
  {id: 'ms', title: 'Microsoft API planes', sub: 'login.microsoftonline.com · api.loganalytics.io',
    accent: C.good, x: 560, y: 245, w: 420, h: 84, from: 'fw',
    callout: 'Cross-tenant Sentinel and Defender queries for customers traverse Microsoft’s public API endpoints — normal and unavoidable — so the identity and Log Analytics planes are on the allowlist too.'},
  {id: 'deny', title: 'Everything else', sub: 'DENY + LOG',
    accent: C.bad, x: 560, y: 350, w: 420, h: 76, dashed: true, from: 'fw',
    callout: '“No data leaks to the internet” operationalises as: data leaves only to named, justified, logged destinations. Any other connection attempt is denied and logged. A static egress IP is a bonus — SaaS vendors can allowlist us back.'},

  // private plane
  {id: 'pe', title: 'Private-endpoint plane',
    sub: 'Azure OpenAI · Key Vault · Postgres · Files · ACR — Microsoft backbone, never the firewall',
    accent: C.good, x: -80, y: 170, w: 520, h: 110, from: 'aca',
    callout: 'And the heaviest traffic — every LLM prompt, every secret read, every database query — never reaches the firewall at all. It rides private endpoints on the Microsoft backbone, invisible to the internet in both directions.'},
];

export default makeScene2D(function* (view) {
  view.add(new Rect({width: 1920, height: 1080, fill: C.bg}));

  // ------------------------------------------------------------- act intro
  const intro = new Node({});
  intro.add(new Txt({
    text: 'Act 2 of 3 — Two Doors In, One Gate Out', y: -50,
    fontFamily: FONT, fontSize: 58, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  intro.add(new Txt({
    text: 'How traffic reaches a private app — and how Tavily still works',
    y: 30, fontFamily: FONT, fontSize: 30, fill: C.sub, opacity: 0,
  }));
  view.add(intro);
  yield* all(...intro.children().map(t => (t as Txt).opacity(1, 0.7)));
  yield* waitFor(2.6);
  yield* intro.opacity(0, 0.6);

  // ------------------------------------------------------------- scaffold
  const links = new Node({});
  const nodes = new Node({});
  view.add(links);
  view.add(nodes);

  const title = new Txt({
    text: 'Act 2 — Two Doors In, One Gate Out', x: -905, y: -510, offset: [-1, 0],
    fontFamily: FONT, fontSize: 40, fontWeight: 700, fill: C.text, opacity: 0,
  });
  view.add(title);

  const callout = new Node({y: 442, opacity: 0});
  const pill = new Rect({
    width: 1720, height: 118, radius: 30, fill: C.pill, stroke: C.ai,
    lineWidth: 2.5, shadowColor: '#00000088', shadowBlur: 20, shadowOffsetY: 6,
  });
  const pillTxt = new Txt({
    text: '', fontFamily: FONT, fontSize: 25, fontWeight: 500, fill: C.text,
    width: 1640, textAlign: 'center', textWrap: true, lineHeight: 33,
  });
  callout.add(pill);
  callout.add(pillTxt);
  view.add(callout);

  const pos: Record<string, [number, number]> = {};
  for (const it of ITEMS) pos[it.id] = [it.x, it.y];

  const cards: Record<string, Rect> = {};
  const arrows: Record<string, Line> = {};
  for (const it of ITEMS) {
    if (it.from) {
      const line = new Line({
        points: [pos[it.from], [it.x, it.y]],
        stroke: C.link, lineWidth: 3, endArrow: true, arrowSize: 12,
        lineCap: 'round', end: 0, opacity: 0.9,
      });
      links.add(line);
      arrows[it.id] = line;
    }
    const card = new Rect({
      x: it.x, y: it.y, width: it.w, height: it.h, radius: 12,
      fill: C.card, stroke: it.accent, lineWidth: 2.5,
      lineDash: it.dashed ? [9, 7] : [],
      opacity: 0, scale: 0.9,
      shadowColor: '#00000077', shadowBlur: 18, shadowOffsetY: 6,
    });
    card.add(new Txt({
      text: it.title, y: it.sub ? -16 : 0,
      fontFamily: FONT, fontSize: it.id === 'aca' ? 27 : 23, fontWeight: 600,
      fill: C.text, width: it.w - 28, textWrap: true, textAlign: 'center',
      lineHeight: 29,
    }));
    if (it.sub) {
      card.add(new Txt({
        text: it.sub, y: it.h / 2 - 30,
        fontFamily: FONT, fontSize: 18, fill: C.sub,
        width: it.w - 28, textWrap: true, textAlign: 'center', lineHeight: 23,
      }));
    }
    nodes.add(card);
    cards[it.id] = card;
  }

  // extra arrows: appgw → aca, dns → aca (drawn during those reveals)
  const appgwToAca = new Line({
    points: [[-760, -210], [-80, -50]],
    stroke: C.link, lineWidth: 3, endArrow: true, arrowSize: 12,
    lineCap: 'round', end: 0, opacity: 0.9,
  });
  const dnsToAca = new Line({
    points: [[-760, 310], [-80, -50]],
    stroke: C.link, lineWidth: 3, endArrow: true, arrowSize: 12,
    lineCap: 'round', end: 0, opacity: 0.9,
  });
  links.add(appgwToAca);
  links.add(dnsToAca);

  yield* title.opacity(1, 0.5);

  // ------------------------------------------------------------- reveal loop
  for (const it of ITEMS) {
    const card = cards[it.id];
    const arrow = arrows[it.id];
    pillTxt.text(it.callout);
    pill.stroke(it.accent);
    if (arrow) yield* arrow.end(1, 0.26, easeOutCubic);
    yield* all(
      card.opacity(1, 0.34),
      card.scale(1, 0.36, easeOutBack),
      callout.opacity(1, 0.3),
    );
    if (it.id === 'guard') yield* appgwToAca.end(1, 0.3, easeOutCubic);
    if (it.id === 'dns') yield* dnsToAca.end(1, 0.3, easeOutCubic);
    yield* waitFor(Math.max(3.2, it.callout.length * 0.028));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- tavily packet trace
  pillTxt.text('Watch one Tavily call end to end: sanitized query → app subnet default route → firewall FQDN match → api.tavily.com. One path out, every hop logged.');
  pill.stroke(C.good);
  const packet = new Circle({
    x: -80, y: -50, size: 26, fill: C.good, opacity: 0,
    shadowColor: C.good, shadowBlur: 24,
  });
  view.add(packet);
  yield* callout.opacity(1, 0.3);
  yield* packet.opacity(1, 0.25);
  yield* all(packet.x(560, 1.1, easeInOutCubic), packet.y(-50, 1.1, easeInOutCubic));
  yield* waitFor(0.35); // pause at the firewall — rule match
  yield* packet.y(-390, 1.0, easeInOutCubic);
  yield* packet.opacity(0, 0.4);
  yield* waitFor(2.6);
  yield* callout.opacity(0, 0.22);

  // ------------------------------------------------------------- outro
  pillTxt.text('Two doors in — one of them path-locked and triple-guarded. One gate out — default-deny with a named allowlist. Act 3: how releases cross the tenant boundary.');
  pill.stroke(C.good);
  yield* callout.opacity(1, 0.4);
  yield* waitFor(4.8);
  yield* all(callout.opacity(0, 0.5), title.opacity(0, 0.5),
    links.opacity(0, 0.5), nodes.opacity(0, 0.5));
  yield* waitFor(0.4);
});
