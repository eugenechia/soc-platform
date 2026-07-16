import {makeScene2D, Rect, Txt, Line, Node} from '@motion-canvas/2d';
import {all, waitFor, easeInOutCubic, easeOutCubic, easeOutBack} from '@motion-canvas/core';
import {C, FONT} from '../lib/walkthrough';

/**
 * Deep Dive · Act 1 — Infrastructure.
 *
 * A hub-and-spoke map of everything the L1 Triage service runs on: the
 * Container App in the middle, Azure platform services on the left, AI
 * services on the right, external SaaS across the top. Each component pops in
 * with an arrow and a narration pill at the bottom.
 *
 * Facts verified against docs/INFRASTRUCTURE.md, Dockerfile, tools/llm_client.py
 * and tools/secrets.py. Production triage model: gpt-5.3-chat on lsg-soc-foundry.
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
}

const ITEMS: Item[] = [
  {id: 'hub', title: 'Azure Container Apps — soc-platform',
    sub: 'Flask + Gunicorn · 1 worker × 4 threads · 1 replica · Southeast Asia',
    accent: C.azure, x: 0, y: -30, w: 560, h: 150,
    callout: 'Everything runs in ONE container: a Flask + Gunicorn monolith, deliberately pinned to a single replica so the in-process scheduler and job registry stay consistent.'},
  {id: 'acr', title: 'Azure Container Registry', sub: 'socplatformreg · Managed Identity pull',
    accent: C.azure, x: -670, y: -270, w: 400, h: 96,
    callout: 'Images are built locally, pushed to ACR, and pulled by the app via Managed Identity (AcrPull) — no registry passwords. Every risky release also gets a dated rollback image tag.'},
  {id: 'kv', title: 'Azure Key Vault', sub: 'kv-socplatform · 26+ secrets',
    accent: C.intel, x: -670, y: -110, w: 400, h: 96,
    callout: 'Jira tokens, OpenAI keys, per-customer Sentinel secrets — all live in Key Vault and are read at runtime via Managed Identity. No secret ever ships in the image or the code.'},
  {id: 'pg', title: 'Azure PostgreSQL 16', sub: 'pg-soc-platform · reports & schedules',
    accent: C.good, x: -670, y: 50, w: 400, h: 96,
    callout: 'A PostgreSQL Flexible Server holds reports and schedules — TLS required, 7-day point-in-time restore, plus a nightly pg_dump backup written to Azure Files.'},
  {id: 'files', title: 'Azure Files (SMB)', sub: 'mounted at /app/data',
    accent: C.good, x: -670, y: 210, w: 400, h: 96,
    callout: 'An SMB share mounted into the container holds customer records, RAG source documents, backups, and the MITRE ATT&CK index.'},
  {id: 'chroma', title: 'Chroma vector store', sub: '/tmp/rag — ephemeral, auto-resync',
    accent: C.ai, x: 0, y: 190, w: 560, h: 96, dashed: true,
    callout: 'The RAG vector store deliberately lives on LOCAL ephemeral disk — Chroma uses SQLite, and SQLite locking hangs over SMB. Vectors are wiped on every restart and auto-resynced from Confluence at startup.'},
  {id: 'aoai', title: 'Azure OpenAI — lsg-soc-foundry',
    sub: 'gpt-5.3-chat (triage) · cheap tier · text-embedding-3-small',
    accent: C.ai, x: 670, y: -110, w: 440, h: 120,
    callout: 'All LLM calls go to Azure OpenAI. Production triage runs the gpt-5.3-chat deployment; a cheap tier for mechanical tasks (MITRE mapping, code decode) is wired in but dark until volume justifies it.'},
  {id: 'entra', title: 'Entra ID SSO', sub: 'admin UI sign-in',
    accent: C.intel, x: 670, y: 90, w: 440, h: 96,
    callout: 'Humans sign in to the admin UI through Entra ID single sign-on. Webhooks and the SIEM gateway authenticate with shared secrets instead.'},
  {id: 'jira', title: 'Jira Cloud', accent: C.jira, x: -720, y: -430, w: 300, h: 76,
    callout: 'Jira Cloud is the ticket system — issue webhooks come in; priorities, labels, assignees and enrichment comments go back out through the REST API.'},
  {id: 'sentinel', title: 'Sentinel / Defender', accent: C.azure, x: -390, y: -430, w: 300, h: 76,
    callout: 'Per-customer Sentinel and Defender credentials (from Key Vault) let the platform query each customer’s OWN SIEM workspace via KQL — for command-line evidence and log correlation.'},
  {id: 'ti', title: 'VirusTotal · AbuseIPDB · SOCRadar', accent: C.intel, x: -20, y: -430, w: 400, h: 76,
    callout: 'Three threat-intelligence sources provide indicator reputation — the hard evidence the deterministic verdict is built on.'},
  {id: 'tavily', title: 'Tavily Web Search', accent: C.intel, x: 350, y: -430, w: 300, h: 76,
    callout: 'Tavily gives the LLM open-web research on malicious indicators — but only after a privacy sanitizer strips anything that could identify the client (more in Act 3).'},
  {id: 'confluence', title: 'Confluence KB', accent: C.ai, x: 680, y: -430, w: 300, h: 76,
    callout: 'Customer Confluence pages — whitelists, known-activity registers, environment notes — are the knowledge base behind RAG, indexed and scoped strictly per customer.'},
];

export default makeScene2D(function* (view) {
  view.add(new Rect({width: 1920, height: 1080, fill: C.bg}));

  // ------------------------------------------------------------- act intro
  const intro = new Node({});
  intro.add(new Txt({
    text: 'SOC-Platform · L1 Triage — Deep Dive', y: -60,
    fontFamily: FONT, fontSize: 64, fontWeight: 700, fill: C.text, opacity: 0,
  }));
  intro.add(new Txt({
    text: 'Act 1 of 3 — The Infrastructure', y: 30,
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
    text: 'Act 1 — Infrastructure', x: -905, y: -510, offset: [-1, 0],
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

  // build cards + arrows (hidden)
  const hub = ITEMS[0];
  const cards: Record<string, Rect> = {};
  const arrows: Record<string, Line> = {};
  for (const it of ITEMS) {
    if (it.id !== 'hub') {
      const line = new Line({
        points: [[hub.x, hub.y], [it.x, it.y]],
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
      text: it.title, y: it.sub ? -18 : 0,
      fontFamily: FONT, fontSize: it.id === 'hub' ? 29 : 24, fontWeight: 600,
      fill: C.text, width: it.w - 28, textWrap: true, textAlign: 'center',
      lineHeight: 30,
    }));
    if (it.sub) {
      card.add(new Txt({
        text: it.sub, y: it.h / 2 - 34,
        fontFamily: FONT, fontSize: 19, fill: C.sub,
        width: it.w - 28, textWrap: true, textAlign: 'center', lineHeight: 24,
      }));
    }
    nodes.add(card);
    cards[it.id] = card;
  }

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
    yield* waitFor(Math.max(3.2, it.callout.length * 0.028));
    yield* callout.opacity(0, 0.22);
  }

  // ------------------------------------------------------------- outro
  pillTxt.text('One container · managed identities everywhere · secrets in a vault · a rollback tag on every release. That is the ground the AI stands on.');
  pill.stroke(C.good);
  yield* callout.opacity(1, 0.4);
  yield* waitFor(4.2);
  yield* all(callout.opacity(0, 0.5), title.opacity(0, 0.5),
    links.opacity(0, 0.5), nodes.opacity(0, 0.5));
  yield* waitFor(0.4);
});
