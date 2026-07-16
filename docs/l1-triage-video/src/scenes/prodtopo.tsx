import {makeScene2D, Rect, Txt, Line, Node} from '@motion-canvas/2d';
import {all, waitFor, easeOutCubic, easeOutBack} from '@motion-canvas/core';
import {C, FONT} from '../lib/walkthrough';

/**
 * Prod Architecture · Act 1 — Two tenants, one codebase.
 *
 * Top strip: the unchanged dev/staging loop (Mac Studio → GitHub → dev ACR →
 * dev ACA). Below it, the new production tenant is revealed piece by piece:
 * spoke VNet with the internal Container App, the private-endpoint subnet,
 * the ops hub (firewall, ExpressRoute/VPN, private DNS) and the App Gateway.
 * Closes on the promote-only arrow from dev ACR into prod ACR.
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
}

const DEV_ITEMS: Item[] = [
  {id: 'mac', title: 'Mac Studio', sub: 'VS Code + Claude Code',
    accent: C.sub, x: -740, y: -400, w: 300, h: 92,
    callout: 'Nothing changes about how the platform is BUILT. Development stays on the Mac Studio, exactly as today.'},
  {id: 'gh', title: 'GitHub', sub: 'eugenechia/SOC-Platform', from: 'mac',
    accent: C.sub, x: -380, y: -400, w: 300, h: 92,
    callout: 'Code is pushed to GitHub — still the single source of truth for every line that will ever reach production.'},
  {id: 'devacr', title: 'dev ACR', sub: 'socplatformreg · release tags', from: 'gh',
    accent: C.azure, x: -20, y: -400, w: 320, h: 92,
    callout: 'Images are built into the dev registry. When a build is proven, it gets an immutable release tag — vX.Y.Z — and that exact artifact is what production will receive.'},
  {id: 'devaca', title: 'dev ACA', sub: 'public FQDN · probe tickets', from: 'devacr',
    accent: C.azure, x: 360, y: -400, w: 340, h: 92,
    callout: 'The current tenant keeps running as dev/staging: open to the internet, cheap, and safe to fire probe tickets at. It is where every feature is validated first.'},
];

const PROD_ITEMS: Item[] = [
  {id: 'aca', title: 'ACA internal environment — soc-platform',
    sub: 'VNet-injected · workload profiles · internal ingress ONLY',
    accent: C.azure, x: -120, y: -60, w: 560, h: 130,
    callout: 'The same container image runs in the prod tenant, but the Container Apps environment is injected into a virtual network with INTERNAL ingress only. No public FQDN exists. Same code, same env-var contract — only the network around it changes.'},
  {id: 'appgw', title: 'App Gateway WAF v2', sub: 'the ONE public door · path-locked', from: 'aca',
    accent: C.bad, x: -690, y: -130, w: 380, h: 100,
    callout: 'One tightly-constrained public entry point exists — an Application Gateway with a web application firewall. Act 2 shows why it is needed and how little it exposes.'},
  {id: 'fw', title: 'Azure Firewall', sub: 'hub · default-deny egress', from: 'aca',
    accent: C.intel, x: -690, y: 60, w: 380, h: 100,
    callout: 'The ops team’s hub provides an Azure Firewall. The app subnet’s default route sends ALL outbound traffic through it — nothing in the spoke can reach the internet directly.'},
  {id: 'er', title: 'ExpressRoute / VPN', sub: 'hub · corporate network', from: 'aca',
    accent: C.intel, x: -690, y: 250, w: 380, h: 100,
    callout: 'Analysts reach the app over the corporate network through the hub’s ExpressRoute or VPN. Private DNS resolves the internal hostname — from the office it just works; from the internet it does not exist.'},
  {id: 'pe_acr', title: 'ACR Premium', sub: 'private endpoint', from: 'aca',
    accent: C.good, x: 620, y: -280, w: 420, h: 84,
    callout: 'The production registry is ACR Premium — the only tier that supports private endpoints. The app pulls images entirely over the Microsoft backbone.'},
  {id: 'pe_kv', title: 'Key Vault', sub: 'private endpoint · ops-populated secrets', from: 'aca',
    accent: C.good, x: 620, y: -140, w: 420, h: 84,
    callout: 'Key Vault holds the same 26+ secret names as dev, but every VALUE is entered by the ops team. Production secrets never exist on the dev side.'},
  {id: 'pe_pg', title: 'PostgreSQL Flexible Server', sub: 'private endpoint', from: 'aca',
    accent: C.good, x: 620, y: 0, w: 420, h: 84,
    callout: 'Postgres, Azure Files and the rest of the data plane all get publicNetworkAccess: Disabled plus a private endpoint. The database is simply not reachable from the internet, firewall or not.'},
  {id: 'pe_files', title: 'Azure Files (SMB)', sub: 'private endpoint · /app/data', from: 'aca',
    accent: C.good, x: 620, y: 140, w: 420, h: 84,
    callout: 'The SMB share with customer records, RAG documents and backups mounts over its private endpoint — same path, same contents, private wire.'},
  {id: 'pe_aoai', title: 'Azure OpenAI', sub: 'private endpoint · new prod resource', from: 'aca',
    accent: C.ai, x: 620, y: 280, w: 420, h: 84,
    callout: 'A new Azure OpenAI resource lives in the prod tenant behind its own private endpoint — every prompt and completion stays on the Microsoft backbone. Its quota approval takes days, so it is the first request to file.'},
];

export default makeScene2D(function* (view) {
  view.add(new Rect({width: 1920, height: 1080, fill: C.bg}));

  // ------------------------------------------------------------- act intro
  const intro = new Node({});
  intro.add(new Txt({
    text: 'SOC-Platform — Production Private Tenant', y: -60,
    fontFamily: FONT, fontSize: 62, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  intro.add(new Txt({
    text: 'Act 1 of 3 — Two tenants, one codebase', y: 30,
    fontFamily: FONT, fontSize: 34, fill: C.sub, opacity: 0,
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
    text: 'Act 1 — Two Tenants, One Codebase', x: -905, y: -510, offset: [-1, 0],
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

  const ALL = [...DEV_ITEMS, ...PROD_ITEMS];
  const pos: Record<string, [number, number]> = {};
  for (const it of ALL) pos[it.id] = [it.x, it.y];

  const cards: Record<string, Rect> = {};
  const arrows: Record<string, Line> = {};
  for (const it of ALL) {
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
      fontFamily: FONT, fontSize: it.id === 'aca' ? 28 : 23, fontWeight: 600,
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

  // tenant boundary labels
  const devLabel = new Txt({
    text: 'DEV / STAGING — current tenant, unchanged', x: -905, y: -462,
    offset: [-1, 0], fontFamily: FONT, fontSize: 22, fontWeight: 600,
    fill: C.sub, opacity: 0,
  });
  const prodBox = new Rect({
    x: -40, y: 30, width: 1810, height: 700, radius: 20,
    stroke: C.intel, lineWidth: 2, lineDash: [14, 10], opacity: 0,
  });
  prodBox.add(new Txt({
    text: 'PROD TENANT — new Entra tenant · ops-operated · private',
    x: -880, y: -318, offset: [-1, 0],
    fontFamily: FONT, fontSize: 22, fontWeight: 600, fill: C.intel,
  }));
  view.add(devLabel);
  view.add(prodBox);

  yield* all(title.opacity(1, 0.5), devLabel.opacity(1, 0.5));

  // ------------------------------------------------------------- dev strip
  for (const it of DEV_ITEMS) {
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
    yield* waitFor(Math.max(3.2, it.callout.length * 0.028));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- prod boundary
  pillTxt.text('Now the new part: a separate production tenant, operated by the ops team, where the app and its data are reachable only over private networking.');
  pill.stroke(C.intel);
  yield* all(prodBox.opacity(1, 0.6), callout.opacity(1, 0.3));
  yield* waitFor(4.4);
  yield* callout.opacity(0, 0.22);

  for (const it of PROD_ITEMS) {
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
    yield* waitFor(Math.max(3.2, it.callout.length * 0.028));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- promote arrow
  const promote = new Line({
    points: [[-20, -354], [620, -322]],
    stroke: C.intel, lineWidth: 5, endArrow: true, arrowSize: 16,
    lineCap: 'round', end: 0, lineDash: [16, 10],
  });
  links.add(promote);
  pillTxt.text('The two tenants touch at exactly ONE point: per release, ops imports the immutable image tag from the dev registry into prod ACR. No CLI, no VS Code, no Docker ever points at production.');
  pill.stroke(C.intel);
  yield* all(promote.end(1, 0.7, easeOutCubic), callout.opacity(1, 0.3));
  yield* waitFor(5.6);
  yield* callout.opacity(0, 0.22);

  // ------------------------------------------------------------- outro
  pillTxt.text('Dev is where iteration happens. Prod only ever receives promoted, tested artifacts. Act 2: how traffic gets in and out of the locked-down tenant.');
  pill.stroke(C.good);
  yield* callout.opacity(1, 0.4);
  yield* waitFor(4.6);
  yield* all(callout.opacity(0, 0.5), title.opacity(0, 0.5), devLabel.opacity(0, 0.5),
    prodBox.opacity(0, 0.5), links.opacity(0, 0.5), nodes.opacity(0, 0.5));
  yield* waitFor(0.4);
});
